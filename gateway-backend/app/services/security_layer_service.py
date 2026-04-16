"""security-layer 보안 검사 서비스."""

import logging

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy
from app.services.guardrail_converter import (
    content_to_request,
    layer_result_to_guardrail_result,
    messages_to_request,
)
from app.services.layer_registry import get_layer

logger = logging.getLogger(__name__)


class SecurityLayerService:
    """core-secure-layer 를 통한 L1~L6 보안 검사 서비스.

    policy 에서 활성화된 레이어(`lN == True`)만 순차적으로
    실행한다. 미구현 레이어(``NotImplementedError``)는 PASS 로
    처리하여 구현 완료된 레이어만 실제 검사를 수행한다.
    """

    async def check_input(
        self,
        messages: list[Message],
        policy: GuardrailPolicy,
    ) -> GuardrailResult:
        """활성 레이어에 한해 입력 메시지 보안 검사를 수행한다.

        Args:
            messages: 사용자 입력 메시지 목록.
            policy: 적용할 보안 정책.

        Returns:
            모든 활성 레이어 통과 시 PASS, 하나라도 차단 시 BLOCK.
        """
        enabled = policy.enabled_layers()
        logger.info(
            "입력 보안 검사 시작: 메시지 수=%d enabled_layers=%s",
            len(messages),
            enabled,
        )
        for layer_idx in enabled:
            result = await self._run_layer_input(layer_idx, messages)
            if result.status is CheckStatus.BLOCK:
                return result
        return GuardrailResult(status=CheckStatus.PASS)

    async def check_output(
        self,
        content: str,
        policy: GuardrailPolicy,
    ) -> GuardrailResult:
        """활성 레이어에 한해 출력 콘텐츠 보안 검사를 수행한다.

        Args:
            content: LLM 응답 텍스트.
            policy: 적용할 보안 정책.

        Returns:
            모든 활성 레이어 통과 시 PASS, 하나라도 차단 시 BLOCK.
        """
        enabled = policy.enabled_layers()
        logger.info(
            "출력 보안 검사 시작: content_len=%d enabled_layers=%s",
            len(content),
            enabled,
        )
        for layer_idx in enabled:
            result = await self._run_layer_output(layer_idx, content)
            if result.status is CheckStatus.BLOCK:
                return result
        return GuardrailResult(status=CheckStatus.PASS)

    async def _run_layer_input(
        self,
        layer_idx: int,
        messages: list[Message],
    ) -> GuardrailResult:
        """core-secure-layer 를 통해 입력 레이어를 실행한다.

        Args:
            layer_idx: 실행할 레이어 인덱스 (1~6).
            messages: 검사 대상 메시지 목록.

        Returns:
            레이어 실행 결과. 미구현·미매핑 레이어는 PASS.
        """
        layer = get_layer(layer_idx)
        if layer is None:
            logger.debug("레이어 L%d: 매핑 없음, PASS", layer_idx)
            return GuardrailResult(status=CheckStatus.PASS)

        request = messages_to_request(messages)
        try:
            result = await layer.check(request)
        except NotImplementedError:
            logger.debug("레이어 %s: 미구현, PASS", layer.name)
            return GuardrailResult(status=CheckStatus.PASS)

        return layer_result_to_guardrail_result(result)

    async def _run_layer_output(
        self,
        layer_idx: int,
        content: str,
    ) -> GuardrailResult:
        """core-secure-layer 를 통해 출력 레이어를 실행한다.

        Args:
            layer_idx: 실행할 레이어 인덱스 (1~6).
            content: 검사 대상 응답 텍스트.

        Returns:
            레이어 실행 결과. 미구현·미매핑 레이어는 PASS.
        """
        layer = get_layer(layer_idx)
        if layer is None:
            logger.debug("레이어 L%d: 매핑 없음, PASS", layer_idx)
            return GuardrailResult(status=CheckStatus.PASS)

        request = content_to_request(content)
        try:
            result = await layer.check(request)
        except NotImplementedError:
            logger.debug("레이어 %s: 미구현, PASS", layer.name)
            return GuardrailResult(status=CheckStatus.PASS)

        return layer_result_to_guardrail_result(result)
