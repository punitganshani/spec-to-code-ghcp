from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal

from .evaluator import PolicyEvaluator
from .types import FilterDecision


class PolicyBlockedError(RuntimeError):
    def __init__(self, decision: FilterDecision) -> None:
        self.decision = decision
        super().__init__("Response blocked by policy filter.")


BlockMode = Literal["raise", "decision", "none"]


@dataclass
class AsyncPolicyMiddleware:
    evaluator: PolicyEvaluator
    provider: str
    endpoint: str
    block_mode: BlockMode = "raise"

    async def invoke(
        self,
        request_call: Callable[[], Awaitable[Any]],
        *,
        return_decision: bool = False,
    ) -> Any:
        payload = await request_call()
        decision = await self.evaluator.evaluate(
            payload,
            provider=self.provider,
            endpoint=self.endpoint,
        )
        if decision.action == "block":
            if self.block_mode == "raise":
                raise PolicyBlockedError(decision)
            if self.block_mode == "none":
                return None
            return decision
        if return_decision:
            return decision
        return decision.payload
