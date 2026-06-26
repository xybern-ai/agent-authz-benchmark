# Contributing to XAAB

This benchmark is only useful if it's adversarial and fair. Two kinds of
contributions are especially welcome:

## 1. Add a target adapter (benchmark another layer)

Implement a small adapter so any authorization layer can be scored on the same
scenarios. See `xaab/adapters/xybern.py` (~30 lines) or
`xaab/adapters/pattern_guardrail.py` for examples.

```python
from xaab.adapters.base import AdapterResult, TargetAdapter
from xaab.schema import Scenario

class MyLayerAdapter(TargetAdapter):
    name = "My Layer"
    def authorize(self, scenario: Scenario) -> AdapterResult:
        verdict = my_layer.check(scenario.action_type, scenario.action_content)
        label = "restrict" if verdict.blocked else "allow"
        return AdapterResult(label=label, raw_decision=str(verdict))
```

Then register it in `xaab/adapters/__init__.py` and `xaab/cli.py`. Configure your
layer to *its* best practice and **publish that config** in your PR, so the
comparison is reproducible and fair (this repo publishes the exact Xybern
reference pack in `policy-pack.json`).

## 2. Add adversarial scenarios

Especially want scenarios designed to make a layer **fail**, including the
Xybern Authorisation Layer. Add a YAML entry under `scenarios/`:

```yaml
- id: my-attack-001
  category: data_exfiltration
  title: Short description
  action_type: send_email
  action_content: "..."
  expected: restrict        # or "allow" for a hard-benign look-alike
  severity: high
  source: "OWASP LLM06 / your reference"
```

- Label honestly: `restrict` = genuinely unsafe; `allow` = genuinely legitimate.
- **Hard-benign** cases (legitimate but scary-looking) are very valuable, they
  catch over-blocking.
- For stateful cases, use `prior_actions` to set up the history.
- For an evasion variant of an existing attack, set `variant_of: <base-id>`.

Run `python -m xaab.cli validate` and `pytest -q` before opening a PR.

## Ground rules

- Keep scenarios **vendor-neutral**, derived from public threat taxonomies
  (OWASP LLM Top 10, MITRE ATLAS, CWE), not crafted to favour any one product.
- No real secrets or real personal data in scenario text (use obvious fakes).
