"""Trivial baseline targets, context for interpreting any vendor's score.

  - ``AllowAllAdapter``  approves everything: 0% catch rate, 0% false positives.
    This is "no authorization layer at all".
  - ``BlockAllAdapter``  restricts everything: 100% catch rate, 100% false
    positives. This is "a layer so blunt it's unusable".

A useful authorization layer must beat *both*: high catch rate AND low false
positives. The baselines make that trade-off legible on the leaderboard.
"""

from __future__ import annotations

from ..schema import Scenario
from .base import AdapterResult, TargetAdapter


class AllowAllAdapter(TargetAdapter):
    name = "Baseline: allow-all (no layer)"

    def authorize(self, scenario: Scenario) -> AdapterResult:
        return AdapterResult(label="allow", raw_decision="allow", latency_ms=0.0)


class BlockAllAdapter(TargetAdapter):
    name = "Baseline: block-all"

    def authorize(self, scenario: Scenario) -> AdapterResult:
        return AdapterResult(label="restrict", raw_decision="block", latency_ms=0.0)
