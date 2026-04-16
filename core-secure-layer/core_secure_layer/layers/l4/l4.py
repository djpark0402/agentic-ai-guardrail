"""L4 가드레일 레이어 스켈레톤."""

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
)


class L4Layer(BaseLayer):
    """가드레일 레이어 L4 스켈레톤."""

    name = "L4"

    async def _check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """L4 검사 실행 (미구현).

        Args:
            request: 가드레일 요청 객체.

        Returns:
            레이어의 검사 결과.

        Raises:
            NotImplementedError: 구현 대기 중.
        """
        raise NotImplementedError
