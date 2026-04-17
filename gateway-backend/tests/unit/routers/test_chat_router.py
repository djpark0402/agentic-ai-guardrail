"""Chat 라우터 테스트."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.dependencies import (
    get_policy_service,
    get_provider_router,
    get_security_service,
)
from app.main import app
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy


def _make_completion(
    content,
    *,
    model="solar-pro",
    created=1_700_000_000,
    finish_reason="stop",
    usage=None,
    tool_calls=None,
):
    """ChatCompletion 형태의 더미 응답 객체를 만든다."""
    usage_ns = (
        SimpleNamespace(model_dump=lambda: dict(usage)) if usage else None
    )
    return SimpleNamespace(
        id="chatcmpl-upstream",
        object="chat.completion",
        created=created,
        model=model,
        choices=[
            SimpleNamespace(
                index=0,
                message=SimpleNamespace(
                    role="assistant",
                    content=content,
                    tool_calls=tool_calls,
                ),
                finish_reason=finish_reason,
            )
        ],
        usage=usage_ns,
    )


def _all_enabled_policy():
    """테스트용 전체 활성화 정책을 반환한다."""
    return GuardrailPolicy(l1=True, l2=True, l3=True, l4=True, l5=True, l6=True)


def _make_mock_llm_service(completion=None):
    """더미 LLMService mock을 생성한다."""
    svc = MagicMock(spec=["chat", "provider_name"])
    svc.provider_name = "solar"
    svc.chat = AsyncMock(
        return_value=completion
        or _make_completion("안녕하세요! 무엇을 도와드릴까요?")
    )
    return svc


def _make_mock_provider_router(llm_service=None):
    """더미 ProviderRouter mock을 생성한다."""
    svc = llm_service or _make_mock_llm_service()
    router = MagicMock()
    router.resolve = MagicMock(return_value=(svc, "solar-pro"))
    return router, svc


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
def mock_provider_router():
    """더미 ProviderRouter."""
    router, _svc = _make_mock_provider_router()
    return router


@pytest.fixture
def mock_llm_service(mock_provider_router):
    """mock_provider_router 에서 resolve 가 반환하는 LLMService."""
    return mock_provider_router.resolve.return_value[0]


@pytest.fixture
def client(
    mock_policy_service,
    mock_security_service,
    mock_provider_router,
):
    """모든 서비스가 mock된 TestClient.

    로컬 `.env` 값(특히 `SKIP_POLICY_FETCH`)의 영향을 배제하기 위해
    `get_settings` 도 `skip_policy_fetch=False` 로 고정 오버라이드한다.
    """

    def _default_settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=False,
        )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: (
        mock_security_service
    )
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings
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
    mock_policy_service, mock_provider_router
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
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [
                    {
                        "role": "user",
                        "content": "악의적 프롬프트",
                    }
                ],
            },
        )
        assert response.status_code == 400
        assert "입력" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_chat_completions_output_blocked_returns_400(
    mock_policy_service, mock_provider_router
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
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router

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


def test_streaming_uses_non_streaming_llm_call(client, mock_llm_service):
    """스트리밍 응답이어도 LLM은 비스트리밍 chat()으로만 호출된다."""
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "안녕"}],
            "stream": True,
        },
    )
    assert response.status_code == 200
    mock_llm_service.chat.assert_awaited_once()


def _parse_sse_chunks(body):
    """SSE 본문에서 JSON chunk 프레임만 뽑아 파싱한다."""
    parsed = []
    for line in body.splitlines():
        if not line.startswith("data: "):
            continue
        payload = line.removeprefix("data: ")
        if payload == "[DONE]":
            continue
        parsed.append(json.loads(payload))
    return parsed


def test_streaming_chunks_are_openai_compliant_json(client):
    """각 SSE 프레임이 chat.completion.chunk JSON 스키마를 따른다."""
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "안녕"}],
            "stream": True,
        },
    )
    assert response.status_code == 200
    assert response.text.rstrip().endswith("data: [DONE]")

    chunks = _parse_sse_chunks(response.text)
    assert len(chunks) >= 3
    for chunk in chunks:
        assert chunk["object"] == "chat.completion.chunk"
        assert "id" in chunk
        assert "created" in chunk
        assert "model" in chunk
        assert chunk["choices"][0]["index"] == 0
        assert "delta" in chunk["choices"][0]

    assert chunks[0]["choices"][0]["delta"].get("role") == "assistant"
    assert chunks[0]["choices"][0]["finish_reason"] is None
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
    assert chunks[-1]["choices"][0]["delta"] == {}


def test_streaming_chunks_concatenate_to_full_content(client):
    """delta.content 를 이어붙이면 원본 LLM 응답과 동일하다."""
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "안녕"}],
            "stream": True,
        },
    )
    assert response.status_code == 200

    chunks = _parse_sse_chunks(response.text)
    rebuilt = "".join(
        c["choices"][0]["delta"].get("content", "") for c in chunks
    )
    assert rebuilt == "안녕하세요! 무엇을 도와드릴까요?"


def test_streaming_uses_completion_metadata(client, mock_llm_service):
    """스트리밍 청크의 model/created 가 원본 completion 값을 사용한다."""
    mock_llm_service.chat = AsyncMock(
        return_value=_make_completion(
            "hi",
            model="solar-pro2",
            created=1_717_000_000,
        )
    )
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "안녕"}],
            "stream": True,
        },
    )
    chunks = _parse_sse_chunks(response.text)
    assert chunks[0]["model"] == "solar-pro2"
    assert chunks[0]["created"] == 1_717_000_000


def test_streaming_output_blocked_does_not_leak_content(
    mock_policy_service, mock_provider_router
):
    """출력 BLOCK 시 SSE 본문에 원본 LLM 응답이 누출되지 않는다."""
    leaked = "비밀번호는 hunter2입니다"
    llm_svc = mock_provider_router.resolve.return_value[0]
    llm_svc.chat = AsyncMock(return_value=_make_completion(leaked))

    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="민감 정보 감지",
        )
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "질문"}],
                "stream": True,
            },
        )
        assert response.status_code == 200
        body = response.text
        assert leaked not in body
        assert "민감 정보 감지" in body or "출력" in body

        chunks = _parse_sse_chunks(body)
        assert len(chunks) == 1
        chunk = chunks[0]
        assert chunk["choices"][0]["finish_reason"] == "content_filter"
        assert chunk["choices"][0]["delta"] == {}
        assert chunk.get("error", {}).get("type") == "guardrail_block"
    finally:
        app.dependency_overrides.clear()


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


def test_output_check_called_after_llm(client, mock_security_service):
    """LLM API 응답 후 check_output이 호출된다."""
    client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "테스트"}],
        },
    )
    mock_security_service.check_output.assert_called_once()


# ── 에러 전파 통합 테스트 ────────────────────────────────────


def test_solar_auth_error_returns_structured_401(client, mock_llm_service):
    """AuthenticationError 가 구조화된 401 응답으로 반환."""
    import httpx as _httpx
    import openai as _openai

    request = _httpx.Request("POST", "https://api.test/v1")
    response = _httpx.Response(401, request=request)
    mock_llm_service.chat = AsyncMock(
        side_effect=_openai.AuthenticationError(
            message="API key suspended",
            response=response,
            body={"error": {"code": "api_key_suspended"}},
        )
    )
    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "hi"}],
        },
    )

    assert resp.status_code == 401
    data = resp.json()
    assert data["provider"] == "solar"
    assert data["retryable"] is False
    assert data["upstream_code"] == "api_key_suspended"


def test_policy_fetch_error_returns_structured_503(client, mock_policy_service):
    """admin-backend 연결 실패가 구조화된 503 응답으로 반환."""
    import httpx as _httpx

    request = _httpx.Request("GET", "https://admin/api")
    mock_policy_service.fetch_policy = AsyncMock(
        side_effect=_httpx.ConnectError(
            message="Connection refused",
            request=request,
        )
    )
    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "hi"}],
        },
    )

    assert resp.status_code == 503
    data = resp.json()
    assert data["provider"] == "admin_backend"
    assert data["retryable"] is True


# ── 정책 조회 생략 (SKIP_POLICY_FETCH) 테스트 ──────────────────


def test_all_disabled_policy_has_no_enabled_layers():
    """GuardrailPolicy.all_disabled()는 모든 레이어가 비활성이다."""
    policy = GuardrailPolicy.all_disabled()
    assert policy.enabled_layers() == []
    assert policy.l1 is False
    assert policy.l6 is False


def test_all_enabled_policy_has_all_layers():
    """GuardrailPolicy.all_enabled()는 L1~L6 전체가 활성이다."""
    policy = GuardrailPolicy.all_enabled()
    assert policy.enabled_layers() == [1, 2, 3, 4, 5, 6]
    assert policy.l1 is True
    assert policy.l6 is True


def test_skip_policy_fetch_forces_all_layers_enabled(
    mock_security_service, mock_provider_router
):
    """SKIP_POLICY_FETCH=true 이면 fetch_policy 를 호출하지 않고 L1~L6 전부를 강제 활성화한다."""  # noqa: E501
    mock_ps = MagicMock()
    mock_ps.fetch_policy = AsyncMock()

    def _skip_settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=True,
        )

    app.dependency_overrides[get_policy_service] = lambda: mock_ps
    app.dependency_overrides[get_security_service] = lambda: (
        mock_security_service
    )
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _skip_settings

    try:
        c = TestClient(app)
        resp = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
        assert resp.status_code == 200
        mock_ps.fetch_policy.assert_not_called()

        # SKIP 시 check_input/check_output 이 L1~L6 전체 정책을 받아야 한다
        input_policy = mock_security_service.check_input.call_args.kwargs[
            "policy"
        ]
        output_policy = mock_security_service.check_output.call_args.kwargs[
            "policy"
        ]
        assert input_policy.enabled_layers() == [1, 2, 3, 4, 5, 6]
        assert output_policy.enabled_layers() == [1, 2, 3, 4, 5, 6]
    finally:
        app.dependency_overrides.clear()
