"""Render an XAAB results bundle as a Markdown leaderboard + per-category tables."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def _fmt(v: Any, suffix: str = "%") -> str:
    return f"{v}{suffix}" if v is not None else "n/a"


def _catch_rate(detail: List[Dict], variant: bool, parent_ids: set) -> Any:
    # Apples-to-apples: the "original" bucket is only the base attacks that
    # actually have paraphrase variants (so hard-adversarial/velocity attacks,
    # which have no variants, don't dilute the rephrasing comparison).
    if variant:
        rows = [d for d in detail
                if d.get("expected") == "restrict" and d.get("variant_of") is not None]
    else:
        rows = [d for d in detail
                if d.get("expected") == "restrict" and d.get("id") in parent_ids]
    if not rows:
        return None, 0
    caught = sum(1 for d in rows if d.get("got") == "restrict")
    return round(caught / len(rows) * 100, 1), len(rows)


def _evasion_section(bundle: Dict[str, Dict]) -> List[str]:
    # Parent ids = base attacks that have at least one paraphrase variant.
    parent_ids = set()
    for b in bundle.values():
        for d in b.get("detail", []):
            if d.get("variant_of"):
                parent_ids.add(d["variant_of"])
    if not parent_ids:
        return []
    lines = ["## Evasion robustness\n"]
    lines.append("Each attack is also tested as **paraphrased / obfuscated variants** "
                 "that preserve the intent but dodge obvious keywords. Pattern layers "
                 "collapse on rewordings; intent-based enforcement should hold.\n")
    lines.append("| Target | Catch rate (original) | Catch rate (evasion variants) | Drop |")
    lines.append("| --- | ---: | ---: | ---: |")
    # rank by variant catch rate desc
    rows = []
    for b in bundle.values():
        s, detail = b["score"], b.get("detail", [])
        if s["target"].startswith("Baseline"):
            continue
        orig, n_o = _catch_rate(detail, False, parent_ids)
        var, n_v = _catch_rate(detail, True, parent_ids)
        if orig is None or var is None:
            continue
        drop = round(orig - var, 1)
        rows.append((var, s["target"], orig, var, drop, n_o, n_v))
    for _, target, orig, var, drop, n_o, n_v in sorted(rows, reverse=True):
        drop_str = f"{drop:.1f} pts" if drop >= 0 else f"+{abs(drop):.1f} pts"
        lines.append(f"| {target} | {orig}% ({n_o}) | {var}% ({n_v}) | {drop_str} |")
    lines.append("")
    return lines


def _stability_section(bundle: Dict[str, Dict]) -> List[str]:
    targets = [(name, b) for name, b in bundle.items() if b.get("stability")]
    if not targets:
        return []
    lines = ["## Stability across repeated runs\n"]
    lines.append("The Xybern layer uses an LLM intent judge, so we run it multiple "
                 "times and report variance. A reproducible benchmark has to hold up "
                 "run to run, not just once.\n")
    for name, b in targets:
        st = b["stability"]; m = st["metrics"]
        lines.append(f"**{name}** — {st['runs']} runs:\n")
        lines.append("| Metric | Mean | Std dev | Min | Max |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        label = {"catch_rate": "Catch rate", "false_positive_rate": "False-positive rate",
                 "youden_j": "Youden's J", "f1": "F1"}
        for key in ("catch_rate", "false_positive_rate", "youden_j", "f1"):
            a = m.get(key)
            if not a:
                continue
            lines.append(f"| {label[key]} | {a['mean']}% | ±{a['std']} | {a['min']}% | {a['max']}% |")
        if st["fully_stable"]:
            lines.append(f"\n*Every scenario decided identically across all {st['runs']} runs (zero variance).*\n")
        else:
            n = len(st["unstable_scenarios"])
            lines.append(f"\n*{n} scenario(s) varied between runs: "
                         f"{', '.join(st['unstable_scenarios'][:8])}"
                         f"{' ...' if n > 8 else ''}.*\n")
    return lines


def render_markdown(bundle: Dict[str, Dict], dataset_meta: Dict[str, Any]) -> str:
    scores = [b["score"] for b in bundle.values()]
    # Rank by Youden's J (catch rate − false-positive rate): one honest number.
    scores.sort(key=lambda s: (s.get("youden_j_pct") or -1e9), reverse=True)

    lines: List[str] = []
    lines.append("# Xybern Agent Authorization Benchmark (XAAB), Results\n")
    lines.append(f"*Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*  ")
    lines.append(
        f"*Dataset: {dataset_meta.get('total')} scenarios "
        f"({dataset_meta.get('attacks')} unsafe / {dataset_meta.get('benign')} legitimate) "
        f"across {dataset_meta.get('categories')} categories.*\n")

    lines.append("## Leaderboard\n")
    lines.append("Ranked by **Youden's J** (catch rate − false-positive rate). "
                 "A useful layer needs a high catch rate *and* a low false-positive "
                 "rate, the trivial baselines show why.\n")
    lines.append("| Rank | Target | Catch rate | False positives | Precision | F1 | "
                 "Youden's J | Latency p50 / p95 |")
    lines.append("| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for i, s in enumerate(scores, 1):
        lat = s.get("latency_ms", {})
        latency = f"{_fmt(lat.get('p50'), ' ms')} / {_fmt(lat.get('p95'), ' ms')}"
        lines.append(
            f"| {i} | {s['target']} | {_fmt(s.get('catch_rate_pct'))} | "
            f"{_fmt(s.get('false_positive_rate_pct'))} | {_fmt(s.get('precision_pct'))} | "
            f"{_fmt(s.get('f1_pct'))} | {_fmt(s.get('youden_j_pct'))} | {latency} |")
    lines.append("")

    # Stability across repeated runs (only if a target was multi-run)
    lines.extend(_stability_section(bundle))

    # Evasion robustness (only if the dataset includes paraphrased variants)
    lines.extend(_evasion_section(bundle))

    # Per-target category breakdown
    for s in scores:
        if s["target"].startswith("Baseline"):
            continue
        lines.append(f"## {s['target']}, by category\n")
        lines.append("| Category | Catch rate | False positives | Unsafe | Legit |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for cat, c in s.get("categories", {}).items():
            lines.append(
                f"| {cat} | {_fmt(c.get('catch_rate_pct'))} | "
                f"{_fmt(c.get('false_positive_rate_pct'))} | {c.get('attacks')} | "
                f"{c.get('benign')} |")
        conf = s.get("confusion", {})
        lines.append(
            f"\n*Confusion matrix: TP {conf.get('tp')}, FN {conf.get('fn')}, "
            f"FP {conf.get('fp')}, TN {conf.get('tn')}; errors {s.get('errors')}.*\n")

    lines.append("## How to reproduce\n")
    lines.append("```bash\npip install -r requirements.txt\n"
                 "export XAAB_BASE_URL=... XAAB_API_KEY=...\n"
                 "python -m xaab.cli run --target xybern\n```\n")
    lines.append("See [`METHODOLOGY.md`](METHODOLOGY.md) for the threat taxonomy, "
                 "labelling rules, and how to add a competitor adapter.\n")
    return "\n".join(lines)
