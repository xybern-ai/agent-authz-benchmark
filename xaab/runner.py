"""Run scenarios through one or more targets and collect scored results."""

from __future__ import annotations

import statistics
import sys
from typing import Dict, List, Tuple

from .adapters.base import AdapterResult, TargetAdapter
from .schema import Scenario
from .scorer import TargetScore, score


def run_target(adapter: TargetAdapter, scenarios: List[Scenario],
               verbose: bool = True) -> Tuple[TargetScore, List[Dict]]:
    adapter.setup()
    results: List[Tuple[Scenario, AdapterResult]] = []
    detail: List[Dict] = []
    try:
        for i, sc in enumerate(scenarios, 1):
            res = adapter.authorize(sc)
            results.append((sc, res))
            correct = (res.label == "restrict") == sc.is_attack
            detail.append({
                "id": sc.id, "category": sc.category, "expected": sc.expected,
                "got": res.label, "raw_decision": res.raw_decision,
                "correct": correct, "latency_ms": res.latency_ms,
                "error": res.error, "variant_of": sc.variant_of,
                # provenance: which signed Vault entry this decision was sealed to
                "decision_id": (res.raw or {}).get("decision_id"),
                "vault_entry_id": (res.raw or {}).get("vault_entry_id"),
            })
            if verbose:
                mark = "✓" if correct else "✗"
                err = f"  ERROR: {res.error}" if res.error else ""
                sys.stdout.write(
                    f"  [{i:>3}/{len(scenarios)}] {mark} {sc.id:<28} "
                    f"expected={sc.expected:<8} got={res.label:<8} "
                    f"({res.raw_decision}){err}\n")
                sys.stdout.flush()
    finally:
        adapter.teardown()
    return score(adapter.name, results), detail


def run_target_multi(adapter: TargetAdapter, scenarios: List[Scenario], runs: int,
                     verbose: bool = True) -> Tuple[TargetScore, List[Dict], Dict]:
    """Run a target ``runs`` times; return (first-run score, first-run detail,
    stability) where stability reports per-metric mean ± std across runs and any
    scenario that wasn't decided consistently every run. Use for non-deterministic
    targets (the LLM-judged layer); deterministic targets only need runs=1."""
    scores: List[TargetScore] = []
    details: List[List[Dict]] = []
    for r in range(1, runs + 1):
        if verbose:
            sys.stdout.write(f"\n--- {adapter.name}: run {r}/{runs} ---\n")
        ts, det = run_target(adapter, scenarios, verbose=verbose)
        scores.append(ts); details.append(det)

    def agg(metric):
        vals = [getattr(s, metric) for s in scores if getattr(s, metric) is not None]
        if not vals:
            return None
        return {"mean": round(statistics.mean(vals) * 100, 2),
                "std": round((statistics.pstdev(vals) if len(vals) > 1 else 0.0) * 100, 2),
                "min": round(min(vals) * 100, 2), "max": round(max(vals) * 100, 2)}

    # per-scenario consistency across runs (attacks only matter for catch stability,
    # but we track every scenario's correctness)
    by_id: Dict[str, List[bool]] = {}
    for det in details:
        for d in det:
            by_id.setdefault(d["id"], []).append(bool(d["correct"]))
    unstable = sorted(sid for sid, oks in by_id.items() if len(set(oks)) > 1)

    stability = {
        "runs": runs,
        "metrics": {m: agg(m) for m in ("catch_rate", "false_positive_rate", "youden_j", "f1")},
        "unstable_scenarios": unstable,
        "fully_stable": len(unstable) == 0,
    }
    return scores[0], details[0], stability


def run_all(adapters: List[TargetAdapter], scenarios: List[Scenario],
            verbose: bool = True, runs_by_name: Dict[str, int] | None = None) -> Dict[str, Dict]:
    """Run every adapter over every scenario; return a results bundle.

    ``runs_by_name`` optionally maps an adapter name to a run count (>1 enables
    multi-run stability for that target)."""
    runs_by_name = runs_by_name or {}
    out: Dict[str, Dict] = {}
    for adapter in adapters:
        n = runs_by_name.get(adapter.name, 1)
        if verbose:
            sys.stdout.write(f"\n=== {adapter.name} ({len(scenarios)} scenarios"
                             f"{f', x{n} runs' if n > 1 else ''}) ===\n")
        if n > 1:
            ts, detail, stability = run_target_multi(adapter, scenarios, n, verbose=verbose)
            out[adapter.name] = {"score": ts.to_dict(), "detail": detail, "stability": stability}
        else:
            ts, detail = run_target(adapter, scenarios, verbose=verbose)
            out[adapter.name] = {"score": ts.to_dict(), "detail": detail}
    return out
