from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from policy_filter.config import PolicyConfigStore
from policy_filter.evaluator import PolicyEvaluator
from policy_filter.middleware import AsyncPolicyMiddleware, PolicyBlockedError


def _write_config(path: Path, *, block: bool = False) -> None:
    data = {
        "version": "v1",
        "rules": [
            {
                "id": "pii-email",
                "policy_type": "pii",
                "severity": "critical" if block else "medium",
                "action": "block" if block else "sanitize",
                "provider": "providerA",
                "endpoints": ["/search"],
                "field_paths": ["customer.email"],
                "patterns": [r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"],
                "pii_classes": ["email"],
            }
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


class TestMiddleware(unittest.IsolatedAsyncioTestCase):
    async def test_invoke_returns_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg)
            middleware = AsyncPolicyMiddleware(
                evaluator=PolicyEvaluator(PolicyConfigStore(cfg)),
                provider="providerA",
                endpoint="/search",
            )

            async def _request() -> dict[str, object]:
                return {"customer": {"email": "a@example.com"}}

            result = await middleware.invoke(_request)
            self.assertEqual(result["customer"]["email"], "[REDACTED:EMAIL]")

    async def test_invoke_can_return_decision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg)
            middleware = AsyncPolicyMiddleware(
                evaluator=PolicyEvaluator(PolicyConfigStore(cfg)),
                provider="providerA",
                endpoint="/search",
            )

            async def _request() -> dict[str, object]:
                return {"customer": {"email": "a@example.com"}}

            decision = await middleware.invoke(_request, return_decision=True)
            self.assertEqual(decision.action, "sanitize")
            self.assertTrue(decision.flagged)

    async def test_block_mode_raise(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg, block=True)
            middleware = AsyncPolicyMiddleware(
                evaluator=PolicyEvaluator(PolicyConfigStore(cfg)),
                provider="providerA",
                endpoint="/search",
                block_mode="raise",
            )

            async def _request() -> dict[str, object]:
                return {"customer": {"email": "a@example.com"}}

            with self.assertRaises(PolicyBlockedError):
                await middleware.invoke(_request)

    async def test_block_mode_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rules.json"
            _write_config(cfg, block=True)
            middleware = AsyncPolicyMiddleware(
                evaluator=PolicyEvaluator(PolicyConfigStore(cfg)),
                provider="providerA",
                endpoint="/search",
                block_mode="none",
            )

            async def _request() -> dict[str, object]:
                return {"customer": {"email": "a@example.com"}}

            result = await middleware.invoke(_request)
            self.assertIsNone(result)
