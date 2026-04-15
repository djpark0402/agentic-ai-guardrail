"""L2 guardrail layer skeleton."""

from typing import Any

from core_secure_layer.layers.base import BaseLayer, LayerResult


class L2Layer(BaseLayer):
    """Skeleton for guardrail layer L2."""

    name = "L2"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        """Run the L2 check (not yet implemented).

        Args:
            context: Request context shared across layers.

        Returns:
            The layer's decision as a :class:`LayerResult`.

        Raises:
            NotImplementedError: Implementation is deferred.
        """
        raise NotImplementedError
