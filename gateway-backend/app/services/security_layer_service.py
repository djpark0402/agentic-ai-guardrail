"""security-layer 보안 검사 서비스."""

import logging

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy

logger = logging.getLogger(__name__)


class SecurityLayerService:
    """core-secure-layer 를 통한 L1~L6 보안 검사 서비스.

    policy 에서 활성화된 레이어(`lN == True`)만 순차적으로 실행한다.
    현재는 core_secure_layer 실연동 이전이므로 각 레이어 훅이 PASS 를
    반환하며, 실제 라이브러리가 붙으면 훅 지점만 교체한다.
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
        """개별 입력 레이어 실행 훅 (core_secure_layer 연동 지점).

        Args:
            layer_idx: 실행할 레이어 인덱스 (1~6).
            messages: 검사 대상 메시지 목록.

        Returns:
            레이어 실행 결과. 현재 더미는 항상 PASS 를 반환한다.
        """
        logger.debug(
            "입력 레이어 실행: L%d (메시지 수=%d)", layer_idx, len(messages)
        )
        return GuardrailResult(status=CheckStatus.PASS)

    async def _run_layer_output(
        self,
        layer_idx: int,
        content: str,
    ) -> GuardrailResult:
        """개별 출력 레이어 실행 훅 (core_secure_layer 연동 지점).

        Args:
            layer_idx: 실행할 레이어 인덱스 (1~6).
            content: 검사 대상 응답 텍스트.

        Returns:
            레이어 실행 결과. 현재 더미는 항상 PASS 를 반환한다.
        """
        logger.debug(
            "출력 레이어 실행: L%d (content_len=%d)", layer_idx, len(content)
        )
        return GuardrailResult(status=CheckStatus.PASS)
