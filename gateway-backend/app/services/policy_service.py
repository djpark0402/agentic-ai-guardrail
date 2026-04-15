"""admin-backend 정책 조회 서비스."""

import logging

import httpx

from app.models.policy import GuardrailPolicy

logger = logging.getLogger(__name__)

_POLICY_PATH = "/api/v1/policies/active"
_REQUEST_TIMEOUT_SEC = 5.0


class PolicyService:
    """admin-backend `/api/v1/policies/active` 활성 정책 조회 서비스."""

    def __init__(
        self,
        admin_backend_url: str,
        http_client: httpx.AsyncClient,
    ) -> None:
        """PolicyService 를 초기화한다.

        Args:
            admin_backend_url: admin-backend 베이스 URL.
            http_client: 재사용할 httpx AsyncClient 인스턴스.
        """
        self._base_url = admin_backend_url.rstrip("/")
        self._client = http_client

    async def fetch_policy(self, session_id: str) -> GuardrailPolicy:
        """admin-backend에서 현재 활성 보안 정책을 가져온다.

        Args:
            session_id: 세션 식별자 (로깅 목적).

        Returns:
            L0~L5 활성화 플래그를 담은 `GuardrailPolicy`.

        Raises:
            httpx.HTTPError: admin-backend 호출 실패(네트워크/4xx/5xx) 시.
        """
        url = f"{self._base_url}{_POLICY_PATH}"
        logger.info("정책 조회 요청: session_id=%s url=%s", session_id, url)

        try:
            response = await self._client.get(
                url,
                headers={"accept": "*/*"},
                timeout=_REQUEST_TIMEOUT_SEC,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error(
                "정책 조회 실패: session_id=%s error=%s", session_id, exc
            )
            raise

        policy = GuardrailPolicy.model_validate(response.json())
        logger.info(
            "정책 조회 성공: session_id=%s enabled_layers=%s",
            session_id,
            policy.enabled_layers(),
        )
        return policy
