# Xybern Agent Authorization Benchmark (XAAB), Results

*Generated 2026-06-26 16:41 UTC*  
*Dataset: 137 scenarios (107 unsafe / 30 legitimate) across 14 categories.*

## Leaderboard

Ranked by **Youden's J** (catch rate − false-positive rate). A useful layer needs a high catch rate *and* a low false-positive rate, the trivial baselines show why.

| Rank | Target | Catch rate | False positives | Precision | F1 | Youden's J | Latency p50 / p95 |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Xybern Authorisation Layer | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% | 9841.9 ms / 14482.4 ms |
| 2 | Pattern guardrail (regex/keyword) | 49.5% | 13.3% | 93.0% | 64.6% | 36.2% | 0.1 ms / 0.1 ms |
| 3 | Baseline: allow-all (no layer) | 0.0% | 0.0% | n/a | n/a | 0.0% | 0.0 ms / 0.0 ms |
| 4 | Baseline: block-all | 100.0% | 100.0% | 78.1% | 87.7% | 0.0% | 0.0 ms / 0.0 ms |

## Stability across repeated runs

The Xybern layer uses an LLM intent judge, so we run it multiple times and report variance. A reproducible benchmark has to hold up run to run, not just once.

**Xybern Authorisation Layer** — 3 runs:

| Metric | Mean | Std dev | Min | Max |
| --- | ---: | ---: | ---: | ---: |
| Catch rate | 100.0% | ±0.0 | 100.0% | 100.0% |
| False-positive rate | 0.0% | ±0.0 | 0.0% | 0.0% |
| Youden's J | 100.0% | ±0.0 | 100.0% | 100.0% |
| F1 | 100.0% | ±0.0 | 100.0% | 100.0% |

*Every scenario decided identically across all 3 runs (zero variance).*

## Evasion robustness

Each attack is also tested as **paraphrased / obfuscated variants** that preserve the intent but dodge obvious keywords. Pattern layers collapse on rewordings; intent-based enforcement should hold.

| Target | Catch rate (original) | Catch rate (evasion variants) | Drop |
| --- | ---: | ---: | ---: |
| Xybern Authorisation Layer | 100.0% (31) | 100.0% (62) | 0.0 pts |
| Pattern guardrail (regex/keyword) | 83.9% (31) | 43.5% (62) | 40.4 pts |

## Xybern Authorisation Layer, by category

| Category | Catch rate | False positives | Unsafe | Legit |
| --- | ---: | ---: | ---: | ---: |
| credential_access | 100.0% | 0.0% | 9 | 2 |
| data_exfiltration | 100.0% | 0.0% | 12 | 2 |
| destructive_ops | 100.0% | 0.0% | 12 | 2 |
| financial_risk | 100.0% | 0.0% | 12 | 2 |
| hard_benign | n/a | 0.0% | 0 | 10 |
| indirect_injection | 100.0% | n/a | 2 | 0 |
| multi_turn | 100.0% | n/a | 4 | 0 |
| obfuscation | 100.0% | n/a | 5 | 0 |
| pii_disclosure | 100.0% | 0.0% | 9 | 2 |
| privilege_escalation | 100.0% | 0.0% | 9 | 2 |
| prompt_injection | 100.0% | 0.0% | 12 | 2 |
| social_engineering | 100.0% | 0.0% | 9 | 2 |
| unsafe_code | 100.0% | 0.0% | 9 | 2 |
| velocity_abuse | 100.0% | 0.0% | 3 | 2 |

*Confusion matrix: TP 107, FN 0, FP 0, TN 30; errors 0.*

## Pattern guardrail (regex/keyword), by category

| Category | Catch rate | False positives | Unsafe | Legit |
| --- | ---: | ---: | ---: | ---: |
| credential_access | 100.0% | 0.0% | 9 | 2 |
| data_exfiltration | 41.7% | 0.0% | 12 | 2 |
| destructive_ops | 100.0% | 0.0% | 12 | 2 |
| financial_risk | 16.7% | 0.0% | 12 | 2 |
| hard_benign | n/a | 40.0% | 0 | 10 |
| indirect_injection | 0.0% | n/a | 2 | 0 |
| multi_turn | 0.0% | n/a | 4 | 0 |
| obfuscation | 0.0% | n/a | 5 | 0 |
| pii_disclosure | 88.9% | 0.0% | 9 | 2 |
| privilege_escalation | 100.0% | 0.0% | 9 | 2 |
| prompt_injection | 25.0% | 0.0% | 12 | 2 |
| social_engineering | 22.2% | 0.0% | 9 | 2 |
| unsafe_code | 33.3% | 0.0% | 9 | 2 |
| velocity_abuse | 0.0% | 0.0% | 3 | 2 |

*Confusion matrix: TP 53, FN 54, FP 4, TN 26; errors 0.*

## How to reproduce

```bash
pip install -r requirements.txt
export XAAB_BASE_URL=... XAAB_API_KEY=...
python -m xaab.cli run --target xybern
```

See [`METHODOLOGY.md`](METHODOLOGY.md) for the threat taxonomy, labelling rules, and how to add a competitor adapter.
