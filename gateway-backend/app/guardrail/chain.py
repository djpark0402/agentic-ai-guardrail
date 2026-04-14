from dataclasses import dataclass, field
from typing import Any

from app.guardrail.layers import BaseLayer, LayerResult


@dataclass
class ChainResult:
    allowed: bool
    trace: list[LayerResult] = field(default_factory=list)
    blocked_by: str | None = None
    reason: str | None = None


class GuardrailChain:
    def __init__(self, layers: list[BaseLayer]):
        self.layers = layers

    async def run(self, context: dict[str, Any]) -> ChainResult:
        trace: list[LayerResult] = []
        for layer in self.layers:
            result = await layer.check(context)
            trace.append(result)
            if not result.allowed:
                return ChainResult(
                    allowed=False,
                    trace=trace,
                    blocked_by=result.name,
                    reason=result.reason,
                )
        return ChainResult(allowed=True, trace=trace)
