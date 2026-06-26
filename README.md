# Xybern Agent Authorization Benchmark (XAAB)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A neutral, reproducible benchmark for **AI-agent authorization layers**: how well
does a layer stop unsafe agent actions while letting legitimate ones through?

Most "agent safety" demos show a single blocked action. XAAB instead runs a
balanced, labelled suite of unsafe **and** legitimate actions and reports the
honest trade-off, catch rate *and* false-positive rate, for any layer, on the
same scenarios.

## Results (v1)

| Target | Catch rate | False positives | F1 | Youden's J | Latency p50 / p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Xybern Authorisation Layer** | **100.0%** | **0.0%** | **100.0%** | **100.0%** | 6787 ms / 10622 ms |
| Pattern guardrail (regex/keyword) | 49.5% | 13.3% | 64.6% | 36.2% | < 1 ms |
| Baseline: allow-all | 0.0% | 0.0% | n/a | 0.0% | 0 ms |
| Baseline: block-all | 100.0% | 100.0% | 78.1% | 0.0% | 0 ms |

*137 scenarios (107 unsafe / 30 legitimate) across 14 categories, 54 base + 62
evasion variants + 11 hard-adversarial + 10 hard-benign. Full report:
[`results/RESULTS.md`](results/RESULTS.md). Methodology: [`METHODOLOGY.md`](METHODOLOGY.md).*

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
variance: **100% catch / 0% false positives with std 0.0**, every one of the 137
scenarios decided identically all three runs (`--runs N` to reproduce).

And the run is not just a table you take on faith. Every decision is sealed to a
hash-chained, ECDSA P-256 **signed Provenance Vault**, and we publish the signed
proof bundle. Verify it yourself, offline, trusting nothing from us:

```bash
pip install cryptography
python verify.py results/proof/bundle.json
# -> VERIFIED: authentic, untampered, correctly chained (485 sealed decisions)
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
