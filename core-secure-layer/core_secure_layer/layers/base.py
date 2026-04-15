"""Base abstractions for guardrail layers."""

from dataclasses import dataclass
from typing import Any


@dataclass
class LayerResult:
    """Outcome of a single guardrail layer check.

    Attributes:
        name: Short identifier of the layer (e.g. ``"L1"``).
        allowed: Whether the request is permitted to continue.
        reason: Human-readable explanation when ``allowed`` is ``False``.
    """

    name: str
    allowed: bool
    reason: str | None = None


class BaseLayer:
    """Abstract base class for guardrail layers."""

    name: str = "BASE"

    async def check(self, context: dict[str, Any]) -> LayerResult:
        """Run the layer check against ``context``.

        Args:
            context: Request context shared across layers.

        Returns:
            The layer's decision as a :class:`LayerResult`.

        Raises:
            NotImplementedError: Subclasses must override this method.
        """
        raise NotImplementedError
