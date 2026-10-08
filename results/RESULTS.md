# Xybern Agent Authorization Benchmark (XAAB), Results

*Generated 2026-09-19 13:26 UTC*  
*Dataset: 164 scenarios (125 unsafe / 39 legitimate) across 17 categories.*

## Leaderboard

Ranked by **Youden's J** (catch rate − false-positive rate). A useful layer needs a high catch rate *and* a low false-positive rate, the trivial baselines show why.

| Rank | Target | Catch rate | False positives | Precision | F1 | Youden's J | Latency p50 / p95 |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Xybern Authorisation Layer | 99.2% | 0.0% | 100.0% | 99.6% | 99.2% | 5133.0 ms / 11125.0 ms |
| 2 | Pattern guardrail (regex/keyword) | 42.4% | 10.3% | 93.0% | 58.2% | 32.1% | 0.1 ms / 0.2 ms |
| 3 | Baseline: allow-all (no layer) | 0.0% | 0.0% | n/a | n/a | 0.0% | 0.0 ms / 0.0 ms |
| 4 | Baseline: block-all | 100.0% | 100.0% | 76.2% | 86.5% | 0.0% | 0.0 ms / 0.0 ms |

## Stability across repeated runs

The Xybern layer uses an LLM intent judge, so we run it multiple times and report variance. A reproducible benchmark has to hold up run to run, not just once.

**Xybern Authorisation Layer** — 3 runs:

| Metric | Mean | Std dev | Min | Max |
| --- | ---: | ---: | ---: | ---: |
| Catch rate | 99.73% | ±0.38 | 99.2% | 100.0% |
| False-positive rate | 0.0% | ±0.0 | 0.0% | 0.0% |
| Youden's J | 99.73% | ±0.38 | 99.2% | 100.0% |
| F1 | 99.87% | ±0.19 | 99.6% | 100.0% |

*1 scenario(s) varied between runs: inject-002.*

## Evasion robustness

Each attack is also tested as **paraphrased / obfuscated variants** that preserve the intent but dodge obvious keywords. Pattern layers collapse on rewordings; intent-based enforcement should hold.

| Target | Catch rate (original) | Catch rate (evasion variants) | Drop |
| --- | ---: | ---: | ---: |
| Xybern Authorisation Layer | 96.8% (31) | 100.0% (62) | +3.2 pts |
| Pattern guardrail (regex/keyword) | 83.9% (31) | 43.5% (62) | 40.4 pts |

## Xybern Authorisation Layer, by category

| Category | Catch rate | False positives | Unsafe | Legit |
| --- | ---: | ---: | ---: | ---: |
| agent_to_agent | 100.0% | 0.0% | 6 | 3 |
| authority_attacks | 100.0% | 0.0% | 8 | 3 |
| credential_access | 100.0% | 0.0% | 9 | 2 |
| data_exfiltration | 100.0% | 0.0% | 12 | 2 |
| destructive_ops | 100.0% | 0.0% | 12 | 2 |
| financial_risk | 100.0% | 0.0% | 12 | 2 |
| hard_benign | n/a | 0.0% | 0 | 10 |
| indirect_injection | 100.0% | n/a | 2 | 0 |
| information_flow | 100.0% | 0.0% | 4 | 3 |
| multi_turn | 100.0% | n/a | 4 | 0 |
| obfuscation | 100.0% | n/a | 5 | 0 |
| pii_disclosure | 100.0% | 0.0% | 9 | 2 |
| privilege_escalation | 100.0% | 0.0% | 9 | 2 |
| prompt_injection | 91.7% | 0.0% | 12 | 2 |
| social_engineering | 100.0% | 0.0% | 9 | 2 |
| unsafe_code | 100.0% | 0.0% | 9 | 2 |
| velocity_abuse | 100.0% | 0.0% | 3 | 2 |

*Confusion matrix: TP 124, FN 1, FP 0, TN 39; errors 1.*

## Pattern guardrail (regex/keyword), by category

| Category | Catch rate | False positives | Unsafe | Legit |
| --- | ---: | ---: | ---: | ---: |
| agent_to_agent | 0.0% | 0.0% | 6 | 3 |
| authority_attacks | 0.0% | 0.0% | 8 | 3 |
| credential_access | 100.0% | 0.0% | 9 | 2 |
| data_exfiltration | 41.7% | 0.0% | 12 | 2 |
| destructive_ops | 100.0% | 0.0% | 12 | 2 |
| financial_risk | 16.7% | 0.0% | 12 | 2 |
| hard_benign | n/a | 40.0% | 0 | 10 |
| indirect_injection | 0.0% | n/a | 2 | 0 |
| information_flow | 0.0% | 0.0% | 4 | 3 |
| multi_turn | 0.0% | n/a | 4 | 0 |
| obfuscation | 0.0% | n/a | 5 | 0 |
| pii_disclosure | 88.9% | 0.0% | 9 | 2 |
| privilege_escalation | 100.0% | 0.0% | 9 | 2 |
| prompt_injection | 25.0% | 0.0% | 12 | 2 |
| social_engineering | 22.2% | 0.0% | 9 | 2 |
| unsafe_code | 33.3% | 0.0% | 9 | 2 |
| velocity_abuse | 0.0% | 0.0% | 3 | 2 |

*Confusion matrix: TP 53, FN 72, FP 4, TN 35; errors 0.*

## How to reproduce

```bash
pip install -r requirements.txt
export XAAB_BASE_URL=... XAAB_API_KEY=...
python -m xaab.cli run --target xybern
```

See [`METHODOLOGY.md`](METHODOLOGY.md) for the threat taxonomy, labelling rules, and how to add a competitor adapter.
