"""Chat 라우터 테스트."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.dependencies import (
    get_policy_service,
    get_security_service,
    get_solar_service,
)
from app.main import app
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy, LayerConfig


def _all_enabled_policy() -> GuardrailPolicy:
    """테스트용 전체 활성화 정책을 반환한다."""
    return GuardrailPolicy(
        layer_1_prompt_injection=LayerConfig(enabled=True),
        layer_2_sensitive_data=LayerConfig(enabled=True),
        layer_3_toxicity=LayerConfig(enabled=True),
        layer_4_hallucination=LayerConfig(enabled=True),
        layer_5_pii=LayerConfig(enabled=True),
        layer_6_compliance=LayerConfig(enabled=True),
    )


@pytest.fixture
def mock_policy_service():
    """항상 전체 활성화 정책을 반환하는 더미 PolicyService."""
    svc = MagicMock()
    svc.fetch_policy = AsyncMock(return_value=_all_enabled_policy())
    return svc


@pytest.fixture
def mock_security_service():
    """항상 PASS를 반환하는 더미 SecurityLayerService."""
    svc = MagicMock()
    svc.check_input = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )
    svc.check_output = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )
    return svc


@pytest.fixture
def mock_solar_service():
    """더미 응답을 반환하는 SolarService."""
    svc = MagicMock()
    svc.chat = AsyncMock(return_value="안녕하세요! 무엇을 도와드릴까요?")

    async def fake_stream(**_kwargs):
        for chunk in ["안녕", "하세요", "!"]:
            yield chunk

    svc.stream_chat = fake_stream
    return svc


@pytest.fixture
def client(mock_policy_service, mock_security_service, mock_solar_service):
    """모든 서비스가 mock된 TestClient."""
    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: (
        mock_security_service
    )
    app.dependency_overrides[get_solar_service] = lambda: mock_solar_service
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_chat_completions_non_streaming_returns_200(client):
    """비스트리밍 요청이 200과 응답 내용을 반환한다."""
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "안녕"}],
            "stream": False,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["choices"][0]["message"]["content"] == (
        "안녕하세요! 무엇을 도와드릴까요?"
    )


def test_chat_completions_input_blocked_returns_400(
    mock_policy_service, mock_solar_service
):
    """입력 검사가 BLOCK이면 HTTP 400을 반환한다."""
    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="프롬프트 인젝션 감지",
        )
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_solar_service] = lambda: mock_solar_service

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "악의적 프롬프트"}],
            },
        )
        assert response.status_code == 400
        assert "입력" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_chat_completions_output_blocked_returns_400(
    mock_policy_service, mock_solar_service
):
    """출력 검사가 BLOCK이면 HTTP 400을 반환한다."""
    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="유해 콘텐츠 감지",
        )
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_solar_service] = lambda: mock_solar_service

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "질문"}],
            },
        )
        assert response.status_code == 400
        assert "출력" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_chat_completions_streaming_returns_sse(client):
    """stream=True 요청이 text/event-stream 응답을 반환한다."""
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "안녕"}],
            "stream": True,
        },
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    body = response.text
    assert "data:" in body
    assert "[DONE]" in body


def test_policy_fetch_called_once(client, mock_policy_service):
    """요청 처리 시 fetch_policy가 정확히 한 번 호출된다."""
    client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "테스트"}],
        },
    )
    mock_policy_service.fetch_policy.assert_called_once()


def test_input_check_called_with_messages(client, mock_security_service):
    """입력 검사 시 메시지가 check_input에 전달된다."""
    client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "테스트 메시지"}],
        },
    )
    mock_security_service.check_input.assert_called_once()


def test_output_check_called_after_solar(client, mock_security_service):
    """Solar API 응답 후 check_output이 호출된다."""
    client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "테스트"}],
        },
    )
    mock_security_service.check_output.assert_called_once()
