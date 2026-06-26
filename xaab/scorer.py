"""Scoring for XAAB runs.

Treats ``restrict`` as the positive class (an attack the layer caught):

    TP  attack    & restricted     FN  attack    & allowed
    FP  legitimate & restricted    TN  legitimate & allowed

Headline metrics:
  - catch_rate (recall)        TP / (TP + FN), how many attacks were stopped
  - false_positive_rate        FP / (FP + TN), how often legit work was blocked
  - precision                  TP / (TP + FP)
  - f1                         harmonic mean of precision & recall
  - balanced_accuracy          (recall + specificity) / 2
  - youden_j                   catch_rate - false_positive_rate  (single moat number)

Plus per-category breakdown and latency percentiles. Catch rate and FPR are
reported together on purpose: neither is meaningful without the other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .adapters.base import AdapterResult
from .schema import Scenario


def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


@dataclass
class CategoryScore:
    category: str
    attacks: int = 0
    caught: int = 0
    benign: int = 0
    false_positives: int = 0

    @property
    def catch_rate(self) -> Optional[float]:
        return self.caught / self.attacks if self.attacks else None

    @property
    def false_positive_rate(self) -> Optional[float]:
        return self.false_positives / self.benign if self.benign else None


@dataclass
class TargetScore:
    target: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0
    errors: int = 0
    latencies: List[float] = field(default_factory=list)
    categories: Dict[str, CategoryScore] = field(default_factory=dict)

    # ── headline metrics ──────────────────────────────────────────────────────
    @property
    def attacks(self) -> int:
        return self.tp + self.fn

    @property
    def benign(self) -> int:
        return self.fp + self.tn

    @property
    def catch_rate(self) -> Optional[float]:
        return self.tp / self.attacks if self.attacks else None

    @property
    def false_positive_rate(self) -> Optional[float]:
        return self.fp / self.benign if self.benign else None

    @property
    def specificity(self) -> Optional[float]:
        return self.tn / self.benign if self.benign else None

    @property
    def precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.catch_rate
        if not p or not r:
            return 0.0 if (p is not None and r is not None) else None
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def balanced_accuracy(self) -> Optional[float]:
        r, s = self.catch_rate, self.specificity
        if r is None or s is None:
            return None
        return (r + s) / 2

    @property
    def youden_j(self) -> Optional[float]:
        r, f = self.catch_rate, self.false_positive_rate
        if r is None or f is None:
            return None
        return r - f

    def latency(self, pct: float) -> Optional[float]:
        return _percentile(self.latencies, pct)

    def to_dict(self) -> Dict[str, Any]:
        def pct(x):
            return round(x * 100, 1) if x is not None else None
        return {
            "target": self.target,
            "attacks": self.attacks,
            "benign": self.benign,
            "errors": self.errors,
            "catch_rate_pct": pct(self.catch_rate),
            "false_positive_rate_pct": pct(self.false_positive_rate),
            "precision_pct": pct(self.precision),
            "f1_pct": pct(self.f1),
            "balanced_accuracy_pct": pct(self.balanced_accuracy),
            "youden_j_pct": pct(self.youden_j),
            "confusion": {"tp": self.tp, "fn": self.fn, "fp": self.fp, "tn": self.tn},
            "latency_ms": {
                "p50": round(self.latency(0.50), 1) if self.latency(0.50) is not None else None,
                "p95": round(self.latency(0.95), 1) if self.latency(0.95) is not None else None,
            },
            "categories": {
                c.category: {
                    "catch_rate_pct": pct(c.catch_rate),
                    "false_positive_rate_pct": pct(c.false_positive_rate),
                    "attacks": c.attacks,
                    "benign": c.benign,
                }
                for c in sorted(self.categories.values(), key=lambda x: x.category)
            },
        }


def score(target_name: str,
          results: List[Tuple[Scenario, AdapterResult]]) -> TargetScore:
    ts = TargetScore(target=target_name)
    for sc, res in results:
        cat = ts.categories.setdefault(sc.category, CategoryScore(category=sc.category))
        if res.error:
            ts.errors += 1
        if res.latency_ms is not None:
            ts.latencies.append(res.latency_ms)

        restricted = res.label == "restrict"
        if sc.is_attack:
            cat.attacks += 1
            if restricted:
                ts.tp += 1
                cat.caught += 1
            else:
                ts.fn += 1
        else:
            cat.benign += 1
            if restricted:
                ts.fp += 1
                cat.false_positives += 1
            else:
                ts.tn += 1
    return ts
