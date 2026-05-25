from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from policy_filter.config import ConfigError, PolicyConfigStore
from policy_filter.evaluator import PolicyEvaluator


def _write_config(path: Path, *, block_pii: bool = False) -> None:
    data = {
        "version": "v1",
        "rules": [
            {
                "id": "pii-email",
                "policy_type": "pii",
                "severity": "critical" if block_pii else "medium",
                "action": "block" if block_pii else "sanitize",
                "provider": "providerA",
                "endpoints": ["/search"],
                "field_paths": ["customer.email"],
                "patterns": [r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"],
                "pii_classes": ["email"],
            },
            {
                "id": "profanity-1",
                "policy_type": "profanity",
                "severity": "medium",
                "action": "sanitize",
                "provider": "*",
                "endpoints": ["*"],
                "field_paths": ["summary"],
                "banned_terms": ["damn"],
                "allow_terms": ["damnation"],
            },
            {
                "id": "off-topic-1",
                "policy_type": "off_topic",
                "severity": "medium",
                "action": "sanitize",
                "provider": "*",
                "endpoints": ["*"],
                "field_paths": ["items.*.category"],
                "deny_categories": ["adult"],
                "allow_categories": ["finance", "news"],
            },
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


class TestPolicyEvaluator(unittest.IsolatedAsyncioTestCase):
    async def test_pass_through_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg)
            evaluator = PolicyEvaluator(PolicyConfigStore(cfg))
            payload = {"customer": {"email": "clean@example.org"}, "summary": "safe", "items": [{"category": "news"}]}
            decision = await evaluator.evaluate(payload, provider="providerB", endpoint="/other")
            self.assertEqual(decision.action, "pass")
            self.assertFalse(decision.flagged)
            self.assertEqual(decision.payload, payload)

    async def test_pii_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg)
            evaluator = PolicyEvaluator(PolicyConfigStore(cfg))
            payload = {"customer": {"email": "alice@example.com"}}
            decision = await evaluator.evaluate(payload, provider="providerA", endpoint="/search")
            self.assertEqual(decision.action, "sanitize")
            self.assertTrue(decision.flagged)
            self.assertEqual(decision.payload["customer"]["email"], "[REDACTED:EMAIL]")
            self.assertEqual(decision.violations[0].policy_type, "pii")

    async def test_profanity_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg)
            evaluator = PolicyEvaluator(PolicyConfigStore(cfg))
            payload = {"summary": "This is damn bad"}
            decision = await evaluator.evaluate(payload, provider="any", endpoint="/any")
            self.assertEqual(decision.action, "sanitize")
            self.assertEqual(decision.payload["summary"], "This is *** bad")

    async def test_off_topic_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg)
            evaluator = PolicyEvaluator(PolicyConfigStore(cfg))
            payload = {"items": [{"category": "adult"}, {"category": "finance"}]}
            decision = await evaluator.evaluate(payload, provider="any", endpoint="/any")
            self.assertEqual(decision.action, "sanitize")
            self.assertEqual(decision.payload["items"][0]["category"], "[FILTERED:OFF_TOPIC]")
            self.assertEqual(decision.payload["items"][1]["category"], "finance")

    async def test_block_on_high_severity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg, block_pii=True)
            evaluator = PolicyEvaluator(PolicyConfigStore(cfg))
            payload = {"customer": {"email": "alice@example.com"}}
            decision = await evaluator.evaluate(payload, provider="providerA", endpoint="/search")
            self.assertEqual(decision.action, "block")
            self.assertIsNone(decision.payload)

    async def test_mixed_violations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg)
            evaluator = PolicyEvaluator(PolicyConfigStore(cfg))
            payload = {
                "customer": {"email": "alice@example.com"},
                "summary": "damn this",
                "items": [{"category": "adult"}],
            }
            decision = await evaluator.evaluate(payload, provider="providerA", endpoint="/search")
            self.assertEqual(decision.action, "sanitize")
            self.assertEqual(len(decision.violations), 3)


class TestConfigValidation(unittest.TestCase):
    def test_invalid_config_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "bad.json"
            cfg.write_text(json.dumps({"version": "v1", "rules": [{"id": "x"}]}), encoding="utf-8")
            with self.assertRaises(ConfigError):
                PolicyConfigStore(cfg).load()

    def test_config_store_auto_reload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg)
            store = PolicyConfigStore(cfg, auto_reload=True)
            first = store.get()
            updated = {
                "version": "v2",
                "rules": [
                    {
                        "id": "profanity-2",
                        "policy_type": "profanity",
                        "severity": "medium",
                        "action": "sanitize",
                        "provider": "*",
                        "endpoints": ["*"],
                        "field_paths": ["summary"],
                        "banned_terms": ["oops"],
                    }
                ],
            }
            cfg.write_text(json.dumps(updated), encoding="utf-8")
            second = store.get()
            self.assertEqual(first.version, "v1")
            self.assertEqual(second.version, "v2")
