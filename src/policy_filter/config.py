from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


PolicyType = Literal["pii", "profanity", "off_topic"]
Action = Literal["sanitize", "block"]
Severity = Literal["low", "medium", "high", "critical"]


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class RuleConfig:
    id: str
    policy_type: PolicyType
    severity: Severity
    action: Action
    provider: str = "*"
    endpoints: tuple[str, ...] = ("*",)
    field_paths: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    banned_terms: tuple[str, ...] = ()
    allow_terms: tuple[str, ...] = ()
    allow_categories: tuple[str, ...] = ()
    deny_categories: tuple[str, ...] = ()
    pii_classes: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyConfig:
    version: str
    rules: tuple[RuleConfig, ...]


def _as_tuple(raw: Any, field_name: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ConfigError(f"Field '{field_name}' must be a list of strings.")
    return tuple(raw)


def _validate_policy_type(value: Any) -> PolicyType:
    if value not in {"pii", "profanity", "off_topic"}:
        raise ConfigError("rule.policy_type must be one of: pii, profanity, off_topic")
    return value


def _validate_action(value: Any) -> Action:
    if value not in {"sanitize", "block"}:
        raise ConfigError("rule.action must be one of: sanitize, block")
    return value


def _validate_severity(value: Any) -> Severity:
    if value not in {"low", "medium", "high", "critical"}:
        raise ConfigError("rule.severity must be one of: low, medium, high, critical")
    return value


def parse_policy_config(raw: dict[str, Any]) -> PolicyConfig:
    if not isinstance(raw, dict):
        raise ConfigError("Config root must be a JSON object.")
    version = raw.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ConfigError("Config 'version' must be a non-empty string.")

    raw_rules = raw.get("rules")
    if not isinstance(raw_rules, list):
        raise ConfigError("Config 'rules' must be a list.")

    rules: list[RuleConfig] = []
    seen_ids: set[str] = set()
    for idx, rule in enumerate(raw_rules):
        if not isinstance(rule, dict):
            raise ConfigError(f"Rule at index {idx} must be an object.")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ConfigError(f"Rule at index {idx} must include non-empty 'id'.")
        if rule_id in seen_ids:
            raise ConfigError(f"Duplicate rule id: {rule_id}")
        seen_ids.add(rule_id)

        policy_type = _validate_policy_type(rule.get("policy_type"))
        action = _validate_action(rule.get("action"))
        severity = _validate_severity(rule.get("severity"))
        provider = rule.get("provider", "*")
        if not isinstance(provider, str):
            raise ConfigError(f"Rule '{rule_id}' field 'provider' must be a string.")
        endpoints = _as_tuple(rule.get("endpoints", ["*"]), "endpoints")
        field_paths = _as_tuple(rule.get("field_paths", []), "field_paths")

        parsed = RuleConfig(
            id=rule_id,
            policy_type=policy_type,
            action=action,
            severity=severity,
            provider=provider,
            endpoints=endpoints or ("*",),
            field_paths=field_paths,
            patterns=_as_tuple(rule.get("patterns", []), "patterns"),
            banned_terms=_as_tuple(rule.get("banned_terms", []), "banned_terms"),
            allow_terms=_as_tuple(rule.get("allow_terms", []), "allow_terms"),
            allow_categories=_as_tuple(rule.get("allow_categories", []), "allow_categories"),
            deny_categories=_as_tuple(rule.get("deny_categories", []), "deny_categories"),
            pii_classes=_as_tuple(rule.get("pii_classes", []), "pii_classes"),
            metadata=rule.get("metadata", {}) if isinstance(rule.get("metadata", {}), dict) else {},
        )

        if parsed.policy_type == "pii" and not (parsed.patterns or parsed.field_paths):
            raise ConfigError(f"Rule '{rule_id}' pii rules require patterns and/or field_paths.")
        if parsed.policy_type == "profanity" and not parsed.banned_terms:
            raise ConfigError(f"Rule '{rule_id}' profanity rules require banned_terms.")
        if parsed.policy_type == "off_topic" and not (parsed.allow_categories or parsed.deny_categories):
            raise ConfigError(f"Rule '{rule_id}' off_topic rules require allow_categories and/or deny_categories.")

        rules.append(parsed)

    return PolicyConfig(version=version, rules=tuple(rules))


class PolicyConfigStore:
    def __init__(self, config_path: str | Path, *, auto_reload: bool = True) -> None:
        self._path = Path(config_path)
        self._auto_reload = auto_reload
        self._cached_mtime_ns: int | None = None
        self._cached: PolicyConfig | None = None

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> PolicyConfig:
        if not self._path.exists():
            raise ConfigError(f"Config file not found: {self._path}")
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        parsed = parse_policy_config(raw)
        self._cached = parsed
        self._cached_mtime_ns = self._path.stat().st_mtime_ns
        return parsed

    def get(self) -> PolicyConfig:
        if self._cached is None:
            return self.load()
        if not self._auto_reload:
            return self._cached
        current = self._path.stat().st_mtime_ns
        if self._cached_mtime_ns != current:
            return self.load()
        return self._cached
