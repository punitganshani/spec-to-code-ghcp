from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from policy_filter.config import PolicyConfigStore
from policy_filter.evaluator import PolicyEvaluator


def _write_perf_config(path: Path) -> None:
    data = {
        "version": "v1",
        "rules": [
            {
                "id": "pii-email",
                "policy_type": "pii",
                "severity": "medium",
                "action": "sanitize",
                "provider": "*",
                "endpoints": ["*"],
                "field_paths": ["items.*.email"],
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
                "field_paths": ["items.*.summary"],
                "banned_terms": ["damn"],
            },
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


class TestPerformanceBudget(unittest.IsolatedAsyncioTestCase):
    async def test_representative_payload_under_50ms(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_perf_config(cfg)
            evaluator = PolicyEvaluator(PolicyConfigStore(cfg))
            payload = {
                "items": [
                    {"email": f"user{i}@example.com", "summary": "damn content", "category": "news"}
                    for i in range(200)
                ]
            }
            start = time.perf_counter()
            decision = await evaluator.evaluate(payload, provider="providerA", endpoint="/search")
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self.assertIn(decision.action, {"sanitize", "pass"})
            self.assertLessEqual(elapsed_ms, 50.0)
