"""admin-backend 정책 조회 서비스.

사용자 요청 헤더 검증을 ADMIN 에 위임하기 위해 `POST /api/v1/gateway/verify`
로 전환되었다. 게이트웨이는 사용자의 4개 헤더값과 `bodyHash` 를 JSON body 로
싣고, `.env` 의 `ADMIN_API_KEY` 를 `X-API-Key` 헤더로 함께 보낸다. 응답은
정책 스키마(`l1Enabled..l6Enabled`) 그대로 유지된다.
"""

from __future__ import annotations

import logging

import httpx

from app.models.policy import GuardrailPolicy
from app.services.request_verifier import VerifiedHeaders

logger = logging.getLogger(__name__)

_VERIFY_PATH = "/api/v1/gateway/verify"
_REQUEST_TIMEOUT_SEC = 5.0


class PolicyService:
    """admin-backend `/api/v1/gateway/verify` 검증 + 정책 조회 서비스."""

    def __init__(
        self,
        admin_backend_url: str,
        http_client: httpx.AsyncClient,
        admin_api_key: str | None = None,
    ) -> None:
        """PolicyService 를 초기화한다.

        Args:
            admin_backend_url: admin-backend 베이스 URL.
            http_client: 재사용할 httpx AsyncClient 인스턴스.
            admin_api_key: admin-backend 요청 시 `X-API-Key` 헤더로 전송할
                게이트웨이 전용 키. None 이면 헤더를 싣지 않는다.
        """
        self._base_url = admin_backend_url.rstrip("/")
        self._client = http_client
        self._admin_api_key = admin_api_key

    async def verify_and_fetch_policy(
        self,
        *,
        session_id: str,
        headers: VerifiedHeaders,
        body_hash: str,
    ) -> GuardrailPolicy:
        """사용자 헤더값을 ADMIN 에 제출하여 검증 후 활성 정책을 받아온다.

        Args:
            session_id: 세션 식별자 (로깅 목적).
            headers: 사용자 요청에서 추출한 4개 검증 헤더.
            body_hash: 사용자 요청 body 의 SHA-256 hex 다이제스트.

        Returns:
            ADMIN 이 승인한 현재 활성 `GuardrailPolicy`.

        Raises:
            httpx.HTTPError: admin-backend 호출 실패(네트워크/4xx/5xx) 시.
        """
        url = f"{self._base_url}{_VERIFY_PATH}"
        payload = {
            "apiKey": headers.api_key,
            "timestamp": headers.timestamp,
            "nonce": headers.nonce,
            "bodyHash": body_hash,
            "signature": headers.signature,
        }
        req_headers: dict[str, str] = {
            "accept": "*/*",
            "Content-Type": "application/json",
        }
        if self._admin_api_key:
            req_headers["X-API-Key"] = self._admin_api_key

        logger.info(
            "정책 검증 요청: session_id=%s url=%s nonce=%s",
            session_id,
            url,
            headers.nonce,
        )
        # 디버깅 목적: ADMIN 으로 실제 전송되는 X-API-Key 헤더와 body 원문을
        # 그대로 콘솔에 남긴다. 운영 환경에서는 제거하거나 DEBUG 레벨로 낮출 것.
        logger.info(
            "[DEBUG] ADMIN 요청 헤더 X-API-Key=%s body=%s",
            req_headers.get("X-API-Key", "(미설정)"),
            payload,
        )
        try:
            response = await self._client.post(
                url,
                json=payload,
                headers=req_headers,
                timeout=_REQUEST_TIMEOUT_SEC,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error(
                "정책 검증 실패: session_id=%s error=%s", session_id, exc
            )
            raise

        policy = GuardrailPolicy.model_validate(response.json())
        logger.info(
            "정책 검증 성공: session_id=%s enabled_layers=%s",
            session_id,
            policy.enabled_layers(),
        )
        return policy
