"""upstream 에러를 구조화된 JSON 응답으로 매핑하는 모듈.

LLM(openai 호환 예외) 및 admin-backend(httpx) 예외를 원인별로 분류하여
HTTP 상태 코드와 구조화된 에러 상세를 반환한다.
"""

import logging
from typing import Any

import httpx
import openai
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class UpstreamErrorDetail(BaseModel):
    """구조화된 upstream 에러 응답 본문.

    Attributes:
        detail: 사람이 읽을 수 있는 요약 메시지.
        provider: 오류가 발생한 upstream 이름.
        upstream_status: 원래 upstream HTTP 상태 코드.
        upstream_code: provider 가 제공한 에러 코드.
        retryable: 재시도 가치가 있는지 여부.
    """

    detail: str
    provider: str
    upstream_status: int | None = None
    upstream_code: str | None = None
    retryable: bool


# ── LLM 예외 매핑 ────────────────────────────────────────────

# (HTTP 상태, retryable) 쌍. isinstance 순서가 중요하므로
# 리스트로 관리한다 — APITimeoutError 는 APIConnectionError 의
# 서브클래스이므로 반드시 먼저 매칭해야 한다.
_SOLAR_MAP: list[tuple[type[openai.APIError], int, bool]] = [
    (openai.AuthenticationError, 401, False),
    (openai.BadRequestError, 400, False),
    (openai.PermissionDeniedError, 403, False),
    (openai.NotFoundError, 404, False),
    (openai.ConflictError, 409, False),
    (openai.UnprocessableEntityError, 422, False),
    (openai.RateLimitError, 429, True),
    # APITimeoutError 는 APIConnectionError 의 서브클래스
    (openai.APITimeoutError, 504, True),
    (openai.APIConnectionError, 502, True),
]


def _extract_upstream_code(
    exc: openai.APIError,
) -> str | None:
    """예외 body 에서 upstream 에러 코드를 추출한다."""
    body: Any = getattr(exc, "body", None)
    if isinstance(body, dict):
        error_obj = body.get("error")
        if isinstance(error_obj, dict):
            code = error_obj.get("code")
            if isinstance(code, str):
                return code
    return None


def map_solar_error(
    exc: openai.APIError,
) -> tuple[int, UpstreamErrorDetail]:
    """LLM(openai 호환) 예외를 HTTP 상태와 구조화된 상세로 매핑한다.

    Args:
        exc: openai 호환 예외 인스턴스.

    Returns:
        (HTTP 상태 코드, UpstreamErrorDetail) 튜플.
    """
    # 매핑 테이블에서 가장 구체적인 타입 먼저 매칭
    for exc_type, status, retryable in _SOLAR_MAP:
        if isinstance(exc, exc_type):
            return status, UpstreamErrorDetail(
                detail=f"LLM API 오류: {exc.message}",
                provider="solar",
                upstream_status=getattr(exc, "status_code", None),
                upstream_code=_extract_upstream_code(exc),
                retryable=retryable,
            )

    # InternalServerError — 503 이면 503, 그 외 502
    if isinstance(exc, openai.InternalServerError):
        raw_status = getattr(exc, "status_code", 500)
        mapped = 503 if raw_status == 503 else 502
        return mapped, UpstreamErrorDetail(
            detail=f"LLM API 오류: {exc.message}",
            provider="solar",
            upstream_status=raw_status,
            upstream_code=_extract_upstream_code(exc),
            retryable=True,
        )

    # 기타 APIError — upstream status 보존 또는 502 fallback
    raw_status = getattr(exc, "status_code", None)
    mapped = raw_status if raw_status else 502
    retryable = mapped >= 500 if raw_status else True
    return mapped, UpstreamErrorDetail(
        detail=f"LLM API 오류: {exc.message}",
        provider="solar",
        upstream_status=raw_status,
        upstream_code=_extract_upstream_code(exc),
        retryable=retryable,
    )


# ── Admin-backend 예외 매핑 ──────────────────────────────────


def map_admin_backend_error(
    exc: httpx.HTTPError,
) -> tuple[int, UpstreamErrorDetail]:
    """admin-backend(httpx) 예외를 HTTP 상태와 구조화된 상세로 매핑.

    Args:
        exc: httpx 예외 인스턴스.

    Returns:
        (HTTP 상태 코드, UpstreamErrorDetail) 튜플.
    """
    message = str(exc)

    # 타임아웃 — TimeoutException 이 ConnectError 보다 먼저
    if isinstance(exc, httpx.TimeoutException):
        return 504, UpstreamErrorDetail(
            detail=f"admin-backend 타임아웃: {message}",
            provider="admin_backend",
            upstream_status=None,
            retryable=True,
        )

    # 연결 실패
    if isinstance(exc, httpx.ConnectError):
        return 503, UpstreamErrorDetail(
            detail=f"admin-backend 연결 실패: {message}",
            provider="admin_backend",
            upstream_status=None,
            retryable=True,
        )

    # HTTP 상태 에러 — upstream 상태 보존
    if isinstance(exc, httpx.HTTPStatusError):
        raw = exc.response.status_code
        return raw, UpstreamErrorDetail(
            detail=(f"admin-backend HTTP {raw}: {message}"),
            provider="admin_backend",
            upstream_status=raw,
            retryable=raw >= 500,
        )

    # 기타 httpx 에러 — 503 fallback
    return 503, UpstreamErrorDetail(
        detail=f"admin-backend 오류: {message}",
        provider="admin_backend",
        upstream_status=None,
        retryable=True,
    )

