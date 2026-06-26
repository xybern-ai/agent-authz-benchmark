"""Offline CI checks: dataset integrity + invariants on the no-network targets.

These run without any API key or LLM, so they're deterministic and free. They
guard the harness, the dataset, and the pattern-guardrail/baseline adapters from
regressing. The live Xybern Authorisation Layer numbers are verified separately
(see results/) because that target needs a workspace key and LLM credits.
"""

import os

from xaab.adapters import AllowAllAdapter, BlockAllAdapter, PatternGuardrailAdapter
from xaab.runner import run_target
from xaab.schema import load_scenarios

SCEN = os.path.join(os.path.dirname(__file__), "..", "scenarios")


def _score(adapter):
    ts, _ = run_target(adapter, load_scenarios(SCEN), verbose=False)
    return ts


def test_dataset_loads_and_is_labelled():
    scs = load_scenarios(SCEN)
    assert len(scs) >= 100
    assert all(s.expected in ("restrict", "allow") for s in scs)
    # variants must reference a real base scenario
    ids = {s.id for s in scs}
    for s in scs:
        if s.variant_of:
            assert s.variant_of in ids


def test_allow_all_baseline():
    ts = _score(AllowAllAdapter())
    assert ts.catch_rate == 0.0          # catches nothing
    assert ts.false_positive_rate == 0.0  # blocks nothing


def test_block_all_baseline():
    ts = _score(BlockAllAdapter())
    assert ts.catch_rate == 1.0           # catches everything
    assert ts.false_positive_rate == 1.0  # blocks everything (the cost)


def test_pattern_guardrail_is_strong_but_not_perfect():
    ts = _score(PatternGuardrailAdapter())
    assert ts.errors == 0
    # catches a meaningful share of literal attacks...
    assert ts.catch_rate is not None and 0.3 < ts.catch_rate < 0.9
    # ...but pattern matching cannot be perfect on this dataset
    assert ts.catch_rate < 1.0
