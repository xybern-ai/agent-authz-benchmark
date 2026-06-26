"""Scenario schema + loader for the Xybern Agent Authorization Benchmark (XAAB).

A *scenario* is a single, vendor-neutral test case: an agent action (optionally
preceded by a short sequence of prior actions) with a ground-truth label of
whether an authorization layer *should* restrict it.

Labels are binary:
  - ``restrict``  the action is unsafe/unauthorized, a good layer blocks or
                  escalates it (a "positive" for catch-rate).
  - ``allow``     the action is legitimate, a good layer lets it through (a
                  false positive if restricted).

Scenarios live as YAML files under ``scenarios/``. Keeping them declarative and
adapter-agnostic is what makes the benchmark reproducible across vendors.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

RESTRICT = "restrict"
ALLOW = "allow"
VALID_LABELS = {RESTRICT, ALLOW}


@dataclass
class PriorAction:
    """An action replayed (by the same agent) before the scenario's main action.

    Used to set up stateful/sequence cases (e.g. read a secret, then exfiltrate).
    """
    action_type: str
    action_content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Scenario:
    id: str
    category: str
    title: str
    action_type: str
    expected: str                      # "restrict" | "allow"
    action_content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    prior_actions: List[PriorAction] = field(default_factory=list)
    severity: Optional[str] = None     # for attacks: low|medium|high|critical
    source: Optional[str] = None       # threat-taxonomy citation
    notes: Optional[str] = None
    variant_of: Optional[str] = None   # set if this is an evasion paraphrase of another

    @property
    def is_attack(self) -> bool:
        return self.expected == RESTRICT

    @property
    def is_variant(self) -> bool:
        return self.variant_of is not None

    def validate(self) -> None:
        if self.expected not in VALID_LABELS:
            raise ValueError(f"{self.id}: expected must be one of {VALID_LABELS}")
        if not self.action_type:
            raise ValueError(f"{self.id}: action_type is required")
        if not self.category:
            raise ValueError(f"{self.id}: category is required")


def _scenario_from_dict(d: Dict[str, Any]) -> Scenario:
    priors = [PriorAction(**p) for p in d.get("prior_actions", [])]
    return Scenario(
        id=d["id"],
        category=d["category"],
        title=d.get("title", d["id"]),
        action_type=d["action_type"],
        expected=d["expected"],
        action_content=d.get("action_content"),
        metadata=d.get("metadata", {}) or {},
        prior_actions=priors,
        severity=d.get("severity"),
        source=d.get("source"),
        notes=d.get("notes"),
        variant_of=d.get("variant_of"),
    )


def load_scenarios(scenarios_dir: str) -> List[Scenario]:
    """Load + validate every scenario in a directory (one or many per YAML file)."""
    scenarios: List[Scenario] = []
    seen_ids = set()
    for path in sorted(glob.glob(os.path.join(scenarios_dir, "*.y*ml"))):
        with open(path) as f:
            docs = yaml.safe_load(f)
        items = docs if isinstance(docs, list) else docs.get("scenarios", [])
        for item in items:
            sc = _scenario_from_dict(item)
            sc.validate()
            if sc.id in seen_ids:
                raise ValueError(f"Duplicate scenario id: {sc.id}")
            seen_ids.add(sc.id)
            scenarios.append(sc)
    return scenarios
