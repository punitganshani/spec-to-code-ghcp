from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

from .config import PolicyConfig, PolicyConfigStore, RuleConfig
from .types import FilterDecision, Violation


def _path_to_str(path: tuple[str, ...]) -> str:
    return ".".join(path)


def _path_matches_spec(path: tuple[str, ...], spec: str) -> bool:
    parts = tuple(spec.split("."))
    if len(parts) != len(path):
        return False
    for p, s in zip(path, parts):
        if s != "*" and s != p:
            return False
    return True


def _normalize_category(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def _normalize_text(value: str) -> str:
    lowered = value.lower()
    return re.sub(r"[^\w\s]", " ", lowered)


def _iter_paths(value: Any, prefix: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    out: list[tuple[tuple[str, ...], Any]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                out.extend(_iter_paths(v, prefix + (k,)))
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            out.extend(_iter_paths(item, prefix + (str(idx),)))
    else:
        out.append((prefix, value))
    return out


def _set_path_value(payload: Any, path: tuple[str, ...], new_value: Any) -> None:
    if not path:
        return
    cursor = payload
    for seg in path[:-1]:
        if isinstance(cursor, list):
            cursor = cursor[int(seg)]
        else:
            cursor = cursor[seg]
    leaf = path[-1]
    if isinstance(cursor, list):
        cursor[int(leaf)] = new_value
    else:
        cursor[leaf] = new_value


@dataclass(frozen=True)
class _CompiledRule:
    rule: RuleConfig
    pattern_regexes: tuple[re.Pattern[str], ...]
    profanity_regexes: tuple[re.Pattern[str], ...]
    allow_terms: set[str]
    allow_categories: set[str]
    deny_categories: set[str]


class PolicyEvaluator:
    def __init__(self, config_store: PolicyConfigStore) -> None:
        self._config_store = config_store
        self._compiled_by_version: dict[str, list[_CompiledRule]] = {}

    async def evaluate(
        self,
        payload: Any,
        *,
        provider: str,
        endpoint: str,
        config_version: str | None = None,
    ) -> FilterDecision:
        config = self._config_store.get()
        if config_version and config.version != config_version:
            raise ValueError(f"Expected config version '{config_version}', got '{config.version}'.")

        compiled = self._compiled_rules(config)
        paths = _iter_paths(payload)
        violations: list[Violation] = []
        blocked = False
        sanitized_payload: Any | None = None
        sanitized_any = False

        for path, value in paths:
            if not isinstance(value, str):
                continue

            current_value = value
            for c in compiled:
                rule = c.rule
                if not self._rule_applies(rule, provider=provider, endpoint=endpoint, path=path):
                    continue

                match, details, replacement = self._evaluate_single(c, current_value)
                if not match:
                    continue

                violation = Violation(
                    rule_id=rule.id,
                    policy_type=rule.policy_type,
                    severity=rule.severity,
                    action=rule.action,
                    path=_path_to_str(path),
                    details=details,
                )
                violations.append(violation)

                if rule.action == "block":
                    blocked = True
                    continue

                if sanitized_payload is None:
                    sanitized_payload = copy.deepcopy(payload)
                _set_path_value(sanitized_payload, path, replacement)
                current_value = replacement
                sanitized_any = True

        if blocked:
            return FilterDecision(
                action="block",
                payload=None,
                violations=violations,
                flagged=True,
                config_version=config.version,
            )
        if sanitized_any and sanitized_payload is not None:
            return FilterDecision(
                action="sanitize",
                payload=sanitized_payload,
                violations=violations,
                flagged=True,
                config_version=config.version,
            )
        return FilterDecision(
            action="pass",
            payload=payload,
            violations=violations,
            flagged=False,
            config_version=config.version,
        )

    def _compiled_rules(self, config: PolicyConfig) -> list[_CompiledRule]:
        if config.version in self._compiled_by_version:
            return self._compiled_by_version[config.version]

        compiled: list[_CompiledRule] = []
        for rule in config.rules:
            profanity_regexes = tuple(
                re.compile(rf"\b{re.escape(term.lower())}\b", re.IGNORECASE)
                for term in rule.banned_terms
            )
            pattern_regexes = tuple(re.compile(pat) for pat in rule.patterns)
            compiled.append(
                _CompiledRule(
                    rule=rule,
                    pattern_regexes=pattern_regexes,
                    profanity_regexes=profanity_regexes,
                    allow_terms={x.lower() for x in rule.allow_terms},
                    allow_categories={_normalize_category(x) for x in rule.allow_categories},
                    deny_categories={_normalize_category(x) for x in rule.deny_categories},
                )
            )
        self._compiled_by_version[config.version] = compiled
        return compiled

    @staticmethod
    def _rule_applies(
        rule: RuleConfig,
        *,
        provider: str,
        endpoint: str,
        path: tuple[str, ...],
    ) -> bool:
        provider_ok = rule.provider == "*" or rule.provider == provider
        endpoint_ok = "*" in rule.endpoints or endpoint in rule.endpoints
        if not (provider_ok and endpoint_ok):
            return False
        if not rule.field_paths:
            return True
        return any(_path_matches_spec(path, spec) for spec in rule.field_paths)

    @staticmethod
    def _evaluate_single(compiled: _CompiledRule, value: str) -> tuple[bool, dict[str, Any], str]:
        rule = compiled.rule
        if rule.policy_type == "pii":
            for rx in compiled.pattern_regexes:
                if rx.search(value):
                    pii_class = rule.pii_classes[0] if rule.pii_classes else "pii"
                    return True, {"pii_class": pii_class, "pattern": rx.pattern}, f"[REDACTED:{pii_class.upper()}]"
            return False, {}, value

        if rule.policy_type == "profanity":
            normalized = _normalize_text(value)
            if any(term in normalized.split() for term in compiled.allow_terms):
                return False, {}, value
            replaced = value
            matched_terms: list[str] = []
            for rx in compiled.profanity_regexes:
                if rx.search(replaced):
                    matched_terms.append(rx.pattern)
                    replaced = rx.sub("***", replaced)
            if matched_terms:
                return True, {"matched_terms": matched_terms}, replaced
            return False, {}, value

        if rule.policy_type == "off_topic":
            normalized_category = _normalize_category(value)
            if compiled.deny_categories and normalized_category in compiled.deny_categories:
                return (
                    True,
                    {"category": normalized_category, "reason": "denylisted_category"},
                    "[FILTERED:OFF_TOPIC]",
                )
            if compiled.allow_categories and normalized_category not in compiled.allow_categories:
                return (
                    True,
                    {"category": normalized_category, "reason": "not_allowlisted"},
                    "[FILTERED:OFF_TOPIC]",
                )
            return False, {}, value

        return False, {}, value
