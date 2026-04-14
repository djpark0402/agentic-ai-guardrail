from dataclasses import dataclass
from typing import Any


@dataclass
class LayerResult:
    name: str
    allowed: bool
    reason: str | None = None


class BaseLayer:
    name: str = "BASE"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        raise NotImplementedError


class L1InputLayer(BaseLayer):
    name = "L1"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        prompt = str(context.get("prompt", ""))
        forbidden = ["<script", "</script", "javascript:", "onerror="]
        lowered = prompt.lower()
        for token in forbidden:
            if token in lowered:
                return LayerResult(name=self.name, allowed=False, reason=f"forbidden token: {token}")
        return LayerResult(name=self.name, allowed=True)


class L2PolicyLayer(BaseLayer):
    name = "L2"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        prompt = str(context.get("prompt", ""))
        if "BLOCKED_POLICY_TOKEN" in prompt:
            return LayerResult(name=self.name, allowed=False, reason="policy violation")
        return LayerResult(name=self.name, allowed=True)
