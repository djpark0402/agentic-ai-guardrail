"""admin-backend 정책 조회 서비스 (더미 구현)."""

import logging

from app.models.policy import GuardrailPolicy, LayerConfig

logger = logging.getLogger(__name__)


class PolicyService:
    """admin-backend에서 보안 정책을 조회하는 서비스.

    실제 구현에서는 httpx를 통해 admin-backend REST API를 호출한다.
    현재는 더미로 구현되어 있으며 모든 레이어가 활성화된 정책을 반환한다.
    """

    async def fetch_policy(self, session_id: str) -> GuardrailPolicy:
        """admin-backend에서 보안 정책을 가져온다 (더미 구현).

        Args:
            session_id: 세션 식별자 (로깅 목적).

        Returns:
            6개 레이어가 모두 활성화된 하드코딩된 정책.
        """
        # 실제 구현: httpx로 admin-backend REST API 호출
        logger.info("정책 조회 요청: session_id=%s", session_id)

        return GuardrailPolicy(
            layer_1_prompt_injection=LayerConfig(enabled=True),
            layer_2_sensitive_data=LayerConfig(enabled=True),
            layer_3_toxicity=LayerConfig(enabled=True),
            layer_4_hallucination=LayerConfig(enabled=True),
            layer_5_pii=LayerConfig(enabled=True),
            layer_6_compliance=LayerConfig(enabled=True),
        )
