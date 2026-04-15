"""security-layer 보안 검사 서비스 (더미 구현)."""

import logging

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy

logger = logging.getLogger(__name__)


class SecurityLayerService:
    """core-secure-layer 라이브러리를 통해 보안 검사를 수행하는 서비스.

    실제 구현에서는 core_secure_layer Python 패키지를 직접 호출한다.
    현재는 더미로 구현되어 있으며 항상 PASS를 반환한다.
    """

    async def check_input(
        self,
        messages: list[Message],
        policy: GuardrailPolicy,
    ) -> GuardrailResult:
        """입력 메시지에 대해 보안 레이어 검사를 수행한다 (더미 구현).

        Args:
            messages: 사용자 입력 메시지 목록.
            policy: 적용할 보안 정책.

        Returns:
            항상 PASS를 반환하는 더미 결과.
        """
        # 실제 구현: core_secure_layer.check_input(messages, policy)
        logger.info("입력 보안 검사 시작: 메시지 수=%d", len(messages))
        return GuardrailResult(status=CheckStatus.PASS)

    async def check_output(
        self,
        content: str,
        policy: GuardrailPolicy,
    ) -> GuardrailResult:
        """출력 콘텐츠에 대해 보안 레이어 검사를 수행한다 (더미 구현).

        Args:
            content: LLM 응답 텍스트.
            policy: 적용할 보안 정책.

        Returns:
            항상 PASS를 반환하는 더미 결과.
        """
        # 실제 구현: core_secure_layer.check_output(content, policy)
        logger.info("출력 보안 검사 시작: content_len=%d", len(content))
        return GuardrailResult(status=CheckStatus.PASS)
