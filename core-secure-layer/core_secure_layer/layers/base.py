"""가드레일 레이어 베이스 추상 클래스."""

import time

from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
)


class BaseLayer:
    """가드레일 레이어의 추상 베이스 클래스.

    서브클래스는 :meth:`_check` 를 오버라이드하여 검사 로직을
    구현한다.  외부 호출은 :meth:`check` 를 사용하며
    ``execution_time_ms`` 가 항상 자동으로 측정된다.
    """

    name: str = "BASE"

    async def check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """검사 실행 및 실행 시간 자동 측정.

        ``_check()`` 를 호출하고 ``execution_time_ms`` 를
        결과에 채운다.  외부에서는 항상 이 메서드를 호출한다.

        Args:
            request: 가드레일 요청 객체.

        Returns:
            ``execution_time_ms`` 가 채워진 검사 결과.
        """
        start = time.perf_counter()
        result = await self._check(request)
        elapsed = (time.perf_counter() - start) * 1000
        result.execution_time_ms = elapsed
        return result

    async def _check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """검사 로직 (서브클래스에서 구현).

        Args:
            request: 가드레일 요청 객체.

        Returns:
            레이어의 검사 결과.

        Raises:
            NotImplementedError: 서브클래스가 구현해야 함.
        """
        raise NotImplementedError
