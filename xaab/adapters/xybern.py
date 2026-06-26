"""Adapter for the Xybern Authorisation Layer control plane.

Runs each scenario through the real ``POST /v1/enforce/intercept`` endpoint.
Stateful scenarios replay their ``prior_actions`` (as the same agent) first, so
sequence/velocity policies see the history they depend on.

Verdict mapping (intentionally conservative, never inflates the layer's score):
  block, escalate                → restrict   (the action was stopped/held)
  allow, allow_with_warning      → allow      (the action proceeds)
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

import requests

from ..schema import Scenario
from .base import AdapterResult, TargetAdapter

_RESTRICTING_DECISIONS = {"block", "escalate"}


class XybernAdapter(TargetAdapter):
    name = "Xybern Authorisation Layer"

    def __init__(self, base_url: str, api_key: str, timeout: float = 45.0,
                 agent_prefix: str = "xaab"):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.agent_prefix = agent_prefix
        self._session = requests.Session()
        self._session.headers.update({
            "X-API-Key": api_key,
            "User-Agent": "xaab-benchmark/1.0",
        })

    def _intercept(self, action_type: str, action_content: Optional[str],
                   metadata: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        r = self._session.post(
            f"{self.base_url}/enforce/intercept",
            json={
                "action_type": action_type,
                "action_content": action_content,
                "metadata": metadata or {},
                "agent_id": agent_id,
            },
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def _attempt(self, scenario: Scenario) -> AdapterResult:
        # Each attempt gets a fresh agent id so prior_actions replay cleanly and
        # only affect this case (no cross-contamination on retry).
        agent_id = f"{self.agent_prefix}_{scenario.id}_{uuid.uuid4().hex[:6]}"
        # Replay any prior actions to establish sequence/velocity state.
        for prior in scenario.prior_actions:
            self._intercept(prior.action_type, prior.action_content,
                            prior.metadata, agent_id)
        t0 = time.perf_counter()
        resp = self._intercept(scenario.action_type, scenario.action_content,
                               scenario.metadata, agent_id)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        decision = (resp.get("decision") or "").lower()
        label = "restrict" if decision in _RESTRICTING_DECISIONS else "allow"
        return AdapterResult(label=label, raw_decision=decision,
                             latency_ms=latency_ms, raw=resp)

    def authorize(self, scenario: Scenario) -> AdapterResult:
        # Retry once on a transient error (e.g. an LLM-judge read timeout) so
        # infrastructure blips don't masquerade as policy misses or variance.
        last = None
        for _ in range(2):
            try:
                return self._attempt(scenario)
            except Exception as exc:
                last = str(exc)
        return AdapterResult(label="allow", raw_decision=None, error=last)
