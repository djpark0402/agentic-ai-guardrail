"""L6 guardrail layer skeleton."""

from typing import Any

from core_secure_layer.layers.base import BaseLayer, LayerResult


class L6Layer(BaseLayer):
    """Skeleton for guardrail layer L6."""

    name = "L6"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        """Run the L6 check (not yet implemented).

        Args:
            context: Request context shared across layers.

        Returns:
            The layer's decision as a :class:`LayerResult`.

        Raises:
            NotImplementedError: Implementation is deferred.
        """
        raise NotImplementedError
