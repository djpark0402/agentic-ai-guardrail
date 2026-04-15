"""L7 guardrail layer skeleton."""

from typing import Any

from core_secure_layer.layers.base import BaseLayer, LayerResult


class L7Layer(BaseLayer):
    """Skeleton for guardrail layer L7."""

    name = "L7"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        """Run the L7 check (not yet implemented).

        Args:
            context: Request context shared across layers.

        Returns:
            The layer's decision as a :class:`LayerResult`.

        Raises:
            NotImplementedError: Implementation is deferred.
        """
        raise NotImplementedError
