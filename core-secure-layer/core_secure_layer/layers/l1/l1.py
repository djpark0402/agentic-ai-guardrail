"""L1 guardrail layer skeleton."""

from typing import Any

from core_secure_layer.layers.base import BaseLayer, LayerResult


class L1Layer(BaseLayer):
    """Skeleton for guardrail layer L1."""

    name = "L1"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        """Run the L1 check (not yet implemented).

        Args:
            context: Request context shared across layers.

        Returns:
            The layer's decision as a :class:`LayerResult`.

        Raises:
            NotImplementedError: Implementation is deferred.
        """
        raise NotImplementedError
