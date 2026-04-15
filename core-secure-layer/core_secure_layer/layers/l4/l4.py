"""L4 guardrail layer skeleton."""

from typing import Any

from core_secure_layer.layers.base import BaseLayer, LayerResult


class L4Layer(BaseLayer):
    """Skeleton for guardrail layer L4."""

    name = "L4"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        """Run the L4 check (not yet implemented).

        Args:
            context: Request context shared across layers.

        Returns:
            The layer's decision as a :class:`LayerResult`.

        Raises:
            NotImplementedError: Implementation is deferred.
        """
        raise NotImplementedError
