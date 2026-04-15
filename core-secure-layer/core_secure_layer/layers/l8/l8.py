"""L8 guardrail layer skeleton."""

from typing import Any

from core_secure_layer.layers.base import BaseLayer, LayerResult


class L8Layer(BaseLayer):
    """Skeleton for guardrail layer L8."""

    name = "L8"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        """Run the L8 check (not yet implemented).

        Args:
            context: Request context shared across layers.

        Returns:
            The layer's decision as a :class:`LayerResult`.

        Raises:
            NotImplementedError: Implementation is deferred.
        """
        raise NotImplementedError
