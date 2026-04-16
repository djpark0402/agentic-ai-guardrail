"""upstream 에러 매핑 함수 단위 테스트."""

import logging

import httpx
import openai
import pytest

from app.errors import (
    UpstreamErrorDetail,
    map_admin_backend_error,
    map_solar_error,
)

# ── 테스트 헬퍼 ──────────────────────────────────────────────


def _solar_status_error(
    exc_cls: type[openai.APIStatusError],
    status: int,
    message: str = "test error",
    code: str | None = None,
) -> openai.APIStatusError:
    """APIStatusError 계열 예외를 생성한다."""
    body: dict[str, object] | None = None
    if code is not None:
        body = {"error": {"code": code}}
    request = httpx.Request("POST", "https://api.test/v1")
    response = httpx.Response(status, request=request)
    return exc_cls(
        message=message,
        response=response,
        body=body,
    )


def _solar_connection_error(
    message: str = "Connection error.",
) -> openai.APIConnectionError:
    """APIConnectionError 를 생성한다."""
    request = httpx.Request("POST", "https://api.test/v1")
    return openai.APIConnectionError(
        message=message,
        request=request,
    )


def _solar_timeout_error() -> openai.APITimeoutError:
    """APITimeoutError 를 생성한다."""
    request = httpx.Request("POST", "https://api.test/v1")
    return openai.APITimeoutError(request=request)


# ── Solar 예외 매핑 테스트 ───────────────────────────────────


class TestMapSolarErrorStatusCodes:
    """map_solar_error 가 예외 타입별 올바른 HTTP 상태를 반환."""

    def test_authentication_error_returns_401(self) -> None:
        exc = _solar_status_error(
            openai.AuthenticationError,
            401,
            code="api_key_is_not_allowed",
        )
        status, detail = map_solar_error(exc)

        assert status == 401
        assert detail.provider == "solar"
        assert detail.upstream_status == 401
        assert detail.upstream_code == "api_key_is_not_allowed"
        assert detail.retryable is False

    def test_bad_request_error_returns_400(self) -> None:
        exc = _solar_status_error(openai.BadRequestError, 400)
        status, detail = map_solar_error(exc)

        assert status == 400
        assert detail.retryable is False

    def test_permission_denied_error_returns_403(self) -> None:
        exc = _solar_status_error(openai.PermissionDeniedError, 403)
        status, detail = map_solar_error(exc)

        assert status == 403
        assert detail.retryable is False

    def test_not_found_error_returns_404(self) -> None:
        exc = _solar_status_error(openai.NotFoundError, 404)
        status, detail = map_solar_error(exc)

        assert status == 404
        assert detail.retryable is False

    def test_conflict_error_returns_409(self) -> None:
        exc = _solar_status_error(openai.ConflictError, 409)
        status, detail = map_solar_error(exc)

        assert status == 409
        assert detail.retryable is False

    def test_unprocessable_entity_error_returns_422(
        self,
    ) -> None:
        exc = _solar_status_error(openai.UnprocessableEntityError, 422)
        status, detail = map_solar_error(exc)

        assert status == 422
        assert detail.retryable is False

    def test_rate_limit_error_returns_429_retryable(
        self,
    ) -> None:
        exc = _solar_status_error(openai.RateLimitError, 429)
        status, detail = map_solar_error(exc)

        assert status == 429
        assert detail.retryable is True

    def test_timeout_error_returns_504_retryable(
        self,
    ) -> None:
        exc = _solar_timeout_error()
        status, detail = map_solar_error(exc)

        assert status == 504
        assert detail.retryable is True

    def test_connection_error_returns_502_retryable(
        self,
    ) -> None:
        exc = _solar_connection_error()
        status, detail = map_solar_error(exc)

        assert status == 502
        assert detail.retryable is True

    def test_internal_server_error_returns_502(self) -> None:
        exc = _solar_status_error(openai.InternalServerError, 500)
        status, detail = map_solar_error(exc)

        assert status == 502
        assert detail.retryable is True

    def test_internal_server_error_503_returns_503(
        self,
    ) -> None:
        exc = _solar_status_error(openai.InternalServerError, 503)
        status, detail = map_solar_error(exc)

        assert status == 503
        assert detail.retryable is True


class TestMapSolarErrorResponseFields:
    """map_solar_error 가 구조화된 응답 필드를 올바르게 채움."""

    def test_provider_is_solar(self) -> None:
        exc = _solar_status_error(openai.AuthenticationError, 401)
        _, detail = map_solar_error(exc)

        assert detail.provider == "solar"

    def test_upstream_code_extracted_from_body(self) -> None:
        exc = _solar_status_error(
            openai.AuthenticationError,
            401,
            code="api_key_suspended",
        )
        _, detail = map_solar_error(exc)

        assert detail.upstream_code == "api_key_suspended"

    def test_upstream_code_none_when_no_body(self) -> None:
        exc = _solar_status_error(openai.BadRequestError, 400)
        _, detail = map_solar_error(exc)

        assert detail.upstream_code is None

    def test_detail_message_contains_exc_message(
        self,
    ) -> None:
        exc = _solar_status_error(
            openai.AuthenticationError,
            401,
            message="API key suspended",
        )
        _, detail = map_solar_error(exc)

        assert "API key suspended" in detail.detail

    def test_upstream_error_detail_model_fields(
        self,
    ) -> None:
        """UpstreamErrorDetail 모델이 필수 필드를 모두 포함."""
        detail = UpstreamErrorDetail(
            detail="test",
            provider="solar",
            upstream_status=401,
            upstream_code="test_code",
            retryable=False,
        )
        assert detail.detail == "test"
        assert detail.provider == "solar"
        assert detail.upstream_status == 401
        assert detail.upstream_code == "test_code"
        assert detail.retryable is False


# ── Admin-backend 예외 매핑 테스트 ───────────────────────────


class TestMapAdminBackendError:
    """map_admin_backend_error 가 httpx 예외별 올바른 매핑."""

    def test_connect_error_returns_503(self) -> None:
        request = httpx.Request("GET", "https://admin/api")
        exc = httpx.ConnectError(
            message="Connection refused",
            request=request,
        )
        status, detail = map_admin_backend_error(exc)

        assert status == 503
        assert detail.provider == "admin_backend"
        assert detail.retryable is True

    def test_timeout_returns_504(self) -> None:
        request = httpx.Request("GET", "https://admin/api")
        exc = httpx.ReadTimeout(
            message="Read timed out",
            request=request,
        )
        status, detail = map_admin_backend_error(exc)

        assert status == 504
        assert detail.retryable is True

    def test_http_status_error_preserves_status(
        self,
    ) -> None:
        request = httpx.Request("GET", "https://admin/api")
        response = httpx.Response(
            503,
            request=request,
        )
        exc = httpx.HTTPStatusError(
            message="Service Unavailable",
            request=request,
            response=response,
        )
        status, detail = map_admin_backend_error(exc)

        assert status == 503
        assert detail.upstream_status == 503
        assert detail.retryable is True

    def test_http_status_error_4xx_not_retryable(
        self,
    ) -> None:
        request = httpx.Request("GET", "https://admin/api")
        response = httpx.Response(
            404,
            request=request,
        )
        exc = httpx.HTTPStatusError(
            message="Not Found",
            request=request,
            response=response,
        )
        status, detail = map_admin_backend_error(exc)

        assert status == 404
        assert detail.retryable is False

    def test_generic_http_error_returns_503(self) -> None:
        request = httpx.Request("GET", "https://admin/api")
        exc = httpx.DecodingError(
            message="Decoding error",
            request=request,
        )
        status, detail = map_admin_backend_error(exc)

        assert status == 503
        assert detail.retryable is True
        assert detail.provider == "admin_backend"


# ── 핸들러 로깅 통합 테스트 ──────────────────────────────────


class TestSolarErrorHandlerLogging:
    """solar_error_handler 가 구조화된 로그를 남기는지 검증."""

    async def test_logs_contain_provider_and_exception_type(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Solar 에러 핸들러 호출 시 로그에 핵심 필드 포함."""
        from unittest.mock import MagicMock

        from app.main import solar_error_handler

        exc = _solar_status_error(
            openai.AuthenticationError,
            401,
            code="api_key_suspended",
        )
        mock_request = MagicMock()
        mock_request.state = MagicMock()
        mock_request.state.session_id = "test-session"

        with caplog.at_level(logging.ERROR, "app.main"):
            await solar_error_handler(mock_request, exc)

        assert any(
            "solar" in r.message and "AuthenticationError" in r.message
            for r in caplog.records
        )


class TestAdminBackendErrorHandlerLogging:
    """admin_backend_error_handler 가 구조화된 로그를 남기는지."""

    async def test_logs_contain_provider_and_exception_type(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Admin-backend 에러 핸들러 호출 시 로그에 핵심 필드."""
        from unittest.mock import MagicMock

        from app.main import admin_backend_error_handler

        request = httpx.Request("GET", "https://admin/api")
        exc = httpx.ConnectError(
            message="Connection refused",
            request=request,
        )
        mock_request = MagicMock()
        mock_request.state = MagicMock()
        mock_request.state.session_id = "test-session"

        with caplog.at_level(logging.ERROR, "app.main"):
            await admin_backend_error_handler(mock_request, exc)

        assert any(
            "admin_backend" in r.message and "ConnectError" in r.message
            for r in caplog.records
        )


# ── LangChain 예외 매핑 ──────────────────────────────────────


class TestMapLangChainError:
    """map_langchain_error 테스트."""

    def test_returns_502_with_retryable(self):
        """LangChainException 을 502 retryable 로 매핑한다."""
        from langchain_core.exceptions import LangChainException

        from app.errors import map_langchain_error

        exc = LangChainException("Something failed")
        status, detail = map_langchain_error(exc)

        assert status == 502
        assert detail.provider == "solar"
        assert detail.retryable is True
        assert "LLM 호출 오류" in detail.detail

    def test_preserves_error_message(self):
        """예외 메시지가 detail 에 포함된다."""
        from langchain_core.exceptions import LangChainException

        from app.errors import map_langchain_error

        exc = LangChainException("specific error message")
        _, detail = map_langchain_error(exc)

        assert "specific error message" in detail.detail
