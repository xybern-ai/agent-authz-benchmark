"""Target adapter interface.

A *target* is any authorization layer under test. To benchmark a new vendor,
implement a small adapter that maps a :class:`Scenario` to that vendor's
authorize call and maps its response back to a binary label (``restrict`` vs
``allow``). The benchmark itself never knows vendor specifics, that isolation
is what keeps the comparison neutral and reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..schema import Scenario


@dataclass
class AdapterResult:
    label: str                          # "restrict" | "allow", normalised verdict
    raw_decision: Optional[str] = None  # vendor's native decision string
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


class TargetAdapter:
    """Base class for an authorization-layer target."""

    #: Human-readable name shown in the leaderboard.
    name: str = "unnamed"

    def setup(self) -> None:
        """Optional one-time setup (e.g. register an agent, load policies)."""

    def authorize(self, scenario: Scenario) -> AdapterResult:  # pragma: no cover
        """Run one scenario through the target and return a normalised result."""
        raise NotImplementedError

    def teardown(self) -> None:
        """Optional cleanup after a run."""
