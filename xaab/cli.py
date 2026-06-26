"""XAAB command line: run targets, score, and emit results + report.

    python -m xaab.cli run --target xybern --target allow-all --target block-all
    python -m xaab.cli validate          # just load + validate the dataset

Config (env or flags):
    XAAB_BASE_URL   control-plane base url (…/api/v1)   --base-url
    XAAB_API_KEY    benchmark workspace api key          --api-key
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from .adapters import (AllowAllAdapter, BlockAllAdapter, PatternGuardrailAdapter,
                       XybernAdapter)
from .adapters.base import TargetAdapter
from .report import render_markdown
from .runner import run_all
from .schema import load_scenarios

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
SCENARIOS_DIR = os.path.join(_ROOT, "scenarios")
RESULTS_DIR = os.path.join(_ROOT, "results")


def _build_adapters(names: List[str], base_url: str, api_key: str) -> List[TargetAdapter]:
    adapters: List[TargetAdapter] = []
    for n in names:
        if n in ("xybern", "sentinel"):
            if not base_url or not api_key:
                sys.exit("xybern target needs --base-url/XAAB_BASE_URL and --api-key/XAAB_API_KEY")
            adapters.append(XybernAdapter(base_url=base_url, api_key=api_key))
        elif n in ("allow-all", "allowall"):
            adapters.append(AllowAllAdapter())
        elif n in ("block-all", "blockall"):
            adapters.append(BlockAllAdapter())
        elif n in ("pattern", "pattern-guardrail", "regex"):
            adapters.append(PatternGuardrailAdapter())
        else:
            sys.exit(f"unknown target: {n}")
    return adapters


def _dataset_meta(scenarios) -> dict:
    attacks = sum(1 for s in scenarios if s.is_attack)
    cats = {s.category for s in scenarios}
    return {"total": len(scenarios), "attacks": attacks,
            "benign": len(scenarios) - attacks, "categories": len(cats)}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="xaab")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_run = sub.add_parser("run", help="run targets over the dataset")
    ap_run.add_argument("--target", action="append", default=[],
                        help="repeatable: xybern | allow-all | block-all")
    ap_run.add_argument("--base-url", default=os.environ.get("XAAB_BASE_URL", ""))
    ap_run.add_argument("--api-key", default=os.environ.get("XAAB_API_KEY", ""))
    ap_run.add_argument("--scenarios", default=SCENARIOS_DIR)
    ap_run.add_argument("--runs", type=int, default=1,
                        help="run the (non-deterministic) xybern target N times for stability/variance")
    ap_run.add_argument("--quiet", action="store_true")

    sub.add_parser("validate", help="load + validate the dataset, print summary")

    args = ap.parse_args(argv)
    scenarios = load_scenarios(args.scenarios if hasattr(args, "scenarios") else SCENARIOS_DIR)
    meta = _dataset_meta(scenarios)

    if args.cmd == "validate":
        print(json.dumps(meta, indent=2))
        by_cat = {}
        for s in scenarios:
            by_cat.setdefault(s.category, [0, 0])
            by_cat[s.category][0 if s.is_attack else 1] += 1
        for cat in sorted(by_cat):
            a, b = by_cat[cat]
            print(f"  {cat:<24} unsafe={a:<3} legit={b}")
        return

    targets = args.target or ["xybern", "pattern-guardrail", "allow-all", "block-all"]
    adapters = _build_adapters(targets, args.base_url, args.api_key)
    # Only the (non-deterministic) Xybern layer benefits from multi-run.
    runs_by_name = ({XybernAdapter.name: args.runs} if args.runs > 1 else None)
    fresh = run_all(adapters, scenarios, verbose=not args.quiet, runs_by_name=runs_by_name)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    results_path = os.path.join(RESULTS_DIR, "results.json")
    # Merge into any existing results so running a subset of targets never drops
    # the others (e.g. re-running an offline adapter keeps the live layer run).
    bundle = {}
    if os.path.exists(results_path):
        try:
            bundle = json.load(open(results_path)).get("results", {})
        except Exception:
            bundle = {}
    bundle.update(fresh)
    with open(results_path, "w") as f:
        json.dump({"meta": meta, "results": bundle}, f, indent=2)
    report = render_markdown(bundle, meta)
    with open(os.path.join(RESULTS_DIR, "RESULTS.md"), "w") as f:
        f.write(report)

    print("\n" + "=" * 64)
    print(report.split("## How to reproduce")[0].strip())
    print("=" * 64)
    print(f"\nWrote {RESULTS_DIR}/results.json and {RESULTS_DIR}/RESULTS.md")


if __name__ == "__main__":
    main()
