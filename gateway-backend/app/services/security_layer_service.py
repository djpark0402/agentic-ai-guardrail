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


def _with_layer_name(
    result: GuardrailResult,
    layer_idx: int,
) -> GuardrailResult:
    """결과에 `layer` 가 비어 있으면 `L{idx}` 로 보강한 사본을 돌려준다.

    관찰 모드 응답에서 레이어별 판정을 순서대로 식별하기 위해 필요하다.
    PASS/미구현/미매핑 레이어는 `layer` 가 비어 있을 수 있으므로 여기서 메운다.
    """
    if result.layer:
        return result
    return result.model_copy(update={"layer": f"L{layer_idx}"})


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

    async def check_input_all(
        self,
        messages: list[Message],
        policy: GuardrailPolicy,
    ) -> list[GuardrailResult]:
        """활성 레이어 전부를 순차 실행하고 각 결과를 수집한다.

        관찰(데모) 모드 전용 경로로, BLOCK 판정이 나와도 후속 레이어 실행을
        중단하지 않는다. 각 결과에는 `layer` 필드가 `"L{idx}"` 형식으로
        보강되어, 정책 순서에 따른 레이어별 판정 내역을 클라이언트에 그대로
        노출할 수 있다.

        Args:
            messages: 사용자 입력 메시지 목록.
            policy: 적용할 보안 정책.

        Returns:
            활성 레이어 개수만큼의 `GuardrailResult` 리스트. 순서는
            `policy.enabled_layers()` 와 일치한다.
        """
        enabled = policy.enabled_layers()
        logger.info(
            "입력 보안 검사(관찰 모드) 시작: 메시지 수=%d enabled_layers=%s",
            len(messages),
            enabled,
        )
        results: list[GuardrailResult] = []
        for layer_idx in enabled:
            result = await self._run_layer_input(layer_idx, messages)
            results.append(_with_layer_name(result, layer_idx))
        return results

    async def check_output_all(
        self,
        content: str,
        policy: GuardrailPolicy,
    ) -> list[GuardrailResult]:
        """활성 레이어 전부를 순차 실행하고 각 출력 결과를 수집한다.

        관찰(데모) 모드 전용 경로. `check_input_all` 과 대칭.

        Args:
            content: LLM 응답 텍스트.
            policy: 적용할 보안 정책.

        Returns:
            활성 레이어 개수만큼의 `GuardrailResult` 리스트.
        """
        enabled = policy.enabled_layers()
        logger.info(
            "출력 보안 검사(관찰 모드) 시작: content_len=%d enabled_layers=%s",
            len(content),
            enabled,
        )
        results: list[GuardrailResult] = []
        for layer_idx in enabled:
            result = await self._run_layer_output(layer_idx, content)
            results.append(_with_layer_name(result, layer_idx))
        return results

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
