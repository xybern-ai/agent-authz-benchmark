# Xybern Agent Authorization Benchmark (XAAB)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A neutral, reproducible benchmark for **AI-agent authorization layers**: how well
does a layer stop unsafe agent actions while letting legitimate ones through?

Most "agent safety" demos show a single blocked action. XAAB instead runs a
balanced, labelled suite of unsafe **and** legitimate actions and reports the
honest trade-off, catch rate *and* false-positive rate, for any layer, on the
same scenarios.

## Results (v2, 2026-09-19)

| Target | Catch rate | False positives | F1 | Youden's J | Latency p50 / p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Xybern Authorisation Layer** | **99.7%** (mean of 3 runs, min 99.2%, max 100%) | **0.0%** | **99.9%** | **99.7%** | 5133 ms / 11125 ms |
| Pattern guardrail (regex/keyword) | 42.4% | 10.3% | 58.2% | 32.1% | < 1 ms |
| Baseline: allow-all | 0.0% | 0.0% | n/a | 0.0% | 0 ms |
| Baseline: block-all | 100.0% | 100.0% | 76.2% | 0.0% | 0 ms |

*The v2 results above cover 164 scenarios (125 unsafe / 39 legitimate) across 17 categories: the 137 v1
scenarios plus `agent_to_agent`, `information_flow` and `authority_attacks`
(forged warrants, confused deputy, fabricated grants, forged and missing stamps,
substitution after authorisation, dual-control bypass, shared-limit bursts).
The one scenario that varied between runs (`inject-002`) was a client-side read
timeout on one run, not a rule miss: the layer decided every other scenario
identically all three times, and every one of the 27 new-category scenarios was
decided correctly in all three runs. The intent judge for this run was DeepSeek;
v1 (2026-06-26) ran with Claude at 100% / 0%. Full report:
[`results/RESULTS.md`](results/RESULTS.md). Methodology: [`METHODOLOGY.md`](METHODOLOGY.md). The suite now carries 180 scenarios across 19 categories: v3 adds `intent_drift` and `pre_execution` (the Expected Effect of an action judged by `effect` rules) (nine scenarios under an approved mission; the adapter creates the mission through `POST /enforce/missions`, so the run key needs the `approvals` scope). The next reference run reports it.*

### Evasion robustness

| Target | Catch rate (original) | Catch rate (evasion variants) | Drop |
| --- | ---: | ---: | ---: |
| **Xybern Authorisation Layer** | 100.0% | 100.0% | 0 pts |
| Pattern guardrail (regex/keyword) | 83.9% | 43.5% | −40 pts |

The **pattern guardrail** is a strong, well-tuned regex/keyword layer, but it
fails on **both** axes the hard cases probe:

- **Rephrasing**, its catch rate **collapses from 83.9% to 43.5%** once attacks
  are reworded; a keyword it doesn't contain is one it can't match.
- **Obfuscation / multi-turn / indirect** attacks, it misses **all 11**.
- **Scary-but-legitimate** actions (a code-review note with `DROP TABLE`, a
  pentest report, a post-mortem, a fraud-training email), it **false-positively
  blocks 4 of 10**.

The Authorisation Layer holds at **100% catch / 0% false positives** throughout:
its semantic policies judge *intent*, so a paraphrase is just another phrasing of
the same prohibited thing, and a mere mention is not an action. The baselines pin
the metric: blocking everything also gets a 100% catch rate, which is why
**Youden's J** (catch rate − false positives) is the number that matters.

### Stable run-to-run, and cryptographically verifiable

Because the layer uses an LLM intent judge, we run it **3 times** and report
variance: **99.7% mean catch / 0% false positives, std 0.38**, 163 of 164 scenarios
decided identically all three runs and the one that varied was a client timeout
(`--runs N` to reproduce).

And the run is not just a table you take on faith. Every decision is sealed to a
hash-chained, ECDSA P-256 **signed Provenance Vault**, and we publish the signed
proof bundle. Verify it yourself, offline, trusting nothing from us:

```bash
pip install cryptography
python verify.py results/proof/bundle.json
# -> VERIFIED: authentic, untampered, correctly chained (588 sealed decisions)
```

## Layout

```
agent-authz/
  scenarios/        labelled YAML scenarios (the dataset)
  policy-pack.json  the exact Authorisation Layer config scored (reference pack)
  xaab/
    schema.py       scenario model + loader
    adapters/       TargetAdapter ABC + Xybern + baselines (add competitors here)
    scorer.py       confusion matrix + metrics
    runner.py       run targets over the dataset
    report.py       markdown leaderboard
    cli.py          `python -m xaab.cli run|validate`
  results/          generated results.json + RESULTS.md
  METHODOLOGY.md    taxonomy, labelling rules, neutrality & limitations
```

## Run it

**You do not need a Xybern account to use this benchmark.** The dataset, harness,
scorer, the pattern guardrail, and the baselines all run locally with no API key
and no network. The published Xybern scores are already in [`results/`](results),
so you can read the comparison without running anything.

```bash
pip install -r requirements.txt

# inspect the dataset (offline)
python -m xaab.cli validate

# score the pattern guardrail + baselines (offline, no key)
python -m xaab.cli run --target pattern-guardrail --target allow-all --target block-all
```

### Benchmark your own layer (no Xybern access needed)

Write a ~30-line adapter for your layer (see "Add your own layer" below) and run
`python -m xaab.cli run --target <yours>`. Same dataset, same scoring.

> The `xybern` target runs against the Xybern Authorisation Layer, a commercial
> hosted product, so it needs a Xybern account. Its scores are published as frozen
> results in [`results/`](results), produced with the published
> [`policy-pack.json`](policy-pack.json) so the configuration is fully transparent.

## Add your own layer

Subclass `TargetAdapter` (see `xaab/adapters/xybern.py`, ~30 lines), map your
authorize response to `restrict` / `allow`, and run. The dataset and scoring are
identical for every target. Contributions, including competitor adapters and
adversarial scenarios, are welcome.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to add a target adapter or
adversarial scenarios.

## License

Apache-2.0, see [`LICENSE`](LICENSE). The scenario dataset and the reference
policy pack are published under the same license so the benchmark is fully
reproducible and auditable.
