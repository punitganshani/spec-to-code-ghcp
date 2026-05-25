from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


Action = Literal["pass", "sanitize", "block"]
PolicyType = Literal["pii", "profanity", "off_topic"]
Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Violation:
    rule_id: str
    policy_type: PolicyType
    severity: Severity
    action: Action
    path: str
    details: dict[str, Any]


@dataclass(frozen=True)
class FilterDecision:
    action: Action
    payload: Any
    violations: list[Violation]
    flagged: bool
    config_version: str | None = None
