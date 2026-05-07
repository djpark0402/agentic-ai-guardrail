"""Chat 라우터 테스트."""

import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.config import SkipPolicyFetchSettings, get_settings
from app.dependencies import (
    get_nonce_store,
    get_policy_service,
    get_provider_router,
    get_security_service,
)
from app.main import app
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy
from app.routers.chat import _log_request_summary
from app.services.request_verifier import (
    NonceStore,
)


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
    return GuardrailPolicy(
        l1=True,
        l2=True,
        l3=True,
        l4=True,
        l5=True,
        l6=True,
        outbound=True,
    )


def _outbound_disabled_policy():
    """L1~L6 은 전부 활성화되어 있지만 `outbound=False` 인 정책 —
    출력 파이프라인만 스킵되는 시나리오 재현용."""
    return GuardrailPolicy(
        l1=True,
        l2=True,
        l3=True,
        l4=True,
        l5=True,
        l6=True,
        outbound=False,
    )


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
    svc.verify_and_fetch_policy = AsyncMock(return_value=_all_enabled_policy())
    return svc


@pytest.fixture
def nonce_store():
    """각 테스트마다 새 NonceStore 를 주입해 재연 방지 상태를 격리한다."""
    return NonceStore(ttl_sec=600)


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


def _default_settings_override():
    """로컬 `.env` 값이 새 관찰 모드 플래그 등을 통해 테스트로 누출되는 것을
    차단하기 위한 Settings 오버라이드. 차단 경로를 쓰는 모든 테스트에서 공용.

    사용자 헤더 검증은 기본 off (`skip_header_verification=True`) — 헤더
    검증을 직접 검사하는 테스트만 별도로 False 로 오버라이드한다.
    """

    def _settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=False,
            skip_header_verification=True,
            continue_on_layer_failure=False,
        )

    return _settings


@pytest.fixture
def mock_llm_service(mock_provider_router):
    """mock_provider_router 에서 resolve 가 반환하는 LLMService."""
    return mock_provider_router.resolve.return_value[0]


@pytest.fixture
def client(
    mock_policy_service,
    mock_security_service,
    mock_provider_router,
    nonce_store,
):
    """모든 서비스가 mock된 TestClient.

    로컬 `.env` 값(특히 `SKIP_POLICY_FETCH`)의 영향을 배제하기 위해
    `get_settings` 를 고정 오버라이드하고, 헤더 검증은 기본 off 로
    둔다(`skip_header_verification=True`).
    """

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: (
        mock_security_service
    )
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_nonce_store] = lambda: nonce_store
    app.dependency_overrides[get_settings] = _default_settings_override()
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


def test_chat_completions_logs_request_summary(client, caplog):
    """정상 완료 시 단계별 시간 요약 로그를 남긴다."""
    with caplog.at_level(logging.INFO):
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "안녕"}],
                "stream": False,
            },
        )

    assert response.status_code == 200
    assert "요청 완료 요약" in caplog.text
    assert "final_status=success" in caplog.text
    assert "policy_fetch_ms=" in caplog.text
    assert "input_guardrail_ms=" in caplog.text
    assert "llm_call_ms=" in caplog.text
    assert "output_guardrail_ms=" in caplog.text
    assert "response_emit_ms=" in caplog.text
    assert "total_ms=" in caplog.text


def test_request_summary_logs_input_guardrail_layer_timings(caplog):
    """입력 가드레일 총합 바로 아래에 레이어별 소요 시간을 남긴다."""
    timings = {
        "policy_fetch": 1.0,
        "input_guardrail": 10.0,
        "input_guardrail_L1": 3.0,
        "input_guardrail_L3": 7.0,
        "llm_call": 5.0,
        "total": 16.0,
    }

    with caplog.at_level(logging.INFO):
        _log_request_summary(
            "session-id",
            final_status="success",
            stream=False,
            timings=timings,
        )

    assert "input_guardrail_ms=10.0" in caplog.text
    assert "input_guardrail_L1(인코딩 검사)_ms=3.0" in caplog.text
    assert "input_guardrail_L3(공격 패턴 유사도)_ms=7.0" in caplog.text
    assert caplog.text.index("input_guardrail_ms=10.0") < caplog.text.index(
        "input_guardrail_L1(인코딩 검사)_ms=3.0"
    )


def test_chat_completions_input_blocked_returns_stop_with_guide_content(
    mock_policy_service, mock_provider_router
):
    """입력 BLOCK 은 정상 LLM 응답 shape (finish_reason=stop) 로 반환되고,
    message.content 에 레이어·스테이지·사유가 담긴 한글 안내문이 실린다."""
    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="프롬프트 인젝션 감지",
            layer="L1",
            severity="CRITICAL",
            confidence=1.0,
            tags=["prompt_injection"],
        )
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings_override()

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [
                    {"role": "user", "content": "악의적 프롬프트"},
                ],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["choices"][0]["finish_reason"] == "stop"
        content = data["choices"][0]["message"]["content"]
        assert "L1" in content
        assert "입력 보안" in content
        assert "프롬프트 인젝션 감지" in content
        # 비표준 error 블록은 더 이상 노출되지 않는다.
        assert data.get("error") is None
    finally:
        app.dependency_overrides.clear()


def test_chat_completions_input_block_logs_request_summary(
    mock_policy_service, mock_provider_router, caplog
):
    """입력 BLOCK 종료도 요약 로그에 최종 상태를 남긴다."""
    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="프롬프트 인젝션 감지",
            layer="L1",
        )
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings_override()

    try:
        c = TestClient(app)
        with caplog.at_level(logging.INFO):
            response = c.post(
                "/v1/chat/completions",
                json={
                    "model": "solar-pro",
                    "messages": [
                        {"role": "user", "content": "악의적 프롬프트"},
                    ],
                },
            )

        assert response.status_code == 200
        assert "요청 완료 요약" in caplog.text
        assert "final_status=blocked_input" in caplog.text
        assert "input_guardrail_ms=" in caplog.text
        assert "total_ms=" in caplog.text
    finally:
        app.dependency_overrides.clear()


def test_chat_completions_input_blocked_streaming_returns_sse(
    mock_policy_service, mock_provider_router
):
    """입력 BLOCK + stream=True 는 정상 LLM 스트림과 동일한 3-part SSE 로
    방출되고, delta.content 를 이어붙이면 차단 안내문이 된다."""
    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="프롬프트 인젝션 감지",
            layer="L1",
            severity="CRITICAL",
        )
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings_override()

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "악의적 프롬프트"}],
                "stream": True,
            },
        )
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]

        chunks = _parse_sse_chunks(response.text)
        # role 프레임 + content delta N개 + finish 프레임
        assert len(chunks) >= 3
        assert chunks[0]["choices"][0]["delta"].get("role") == "assistant"
        assert chunks[0]["choices"][0]["finish_reason"] is None
        assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
        assert chunks[-1]["choices"][0]["delta"] == {}

        rebuilt = "".join(
            c["choices"][0]["delta"].get("content", "") for c in chunks
        )
        assert "L1" in rebuilt
        assert "입력 보안" in rebuilt
        assert "프롬프트 인젝션 감지" in rebuilt
        # 비표준 error 블록은 어떤 프레임에도 실리지 않는다.
        assert all("error" not in chunk for chunk in chunks)
        # 입력 차단은 LLM 호출 전에 발생 → chat() 이 호출되지 않아야 함
        llm_svc = mock_provider_router.resolve.return_value[0]
        llm_svc.chat.assert_not_awaited()
    finally:
        app.dependency_overrides.clear()


def test_chat_completions_output_blocked_returns_stop_with_guide_content(
    mock_policy_service, mock_provider_router
):
    """출력 BLOCK 도 정상 LLM 응답 shape 으로 반환되며, message.content 에
    출력 스테이지 안내문이 실린다."""
    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="유해 콘텐츠 감지",
            layer="L3",
            severity="HIGH",
            confidence=0.92,
            tags=["harmful_content"],
        )
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings_override()

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "질문"}],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["object"] == "chat.completion"
        assert data["choices"][0]["finish_reason"] == "stop"
        content = data["choices"][0]["message"]["content"]
        assert "L3" in content
        assert "출력 보안" in content
        assert "유해 콘텐츠 감지" in content
        assert data.get("error") is None
    finally:
        app.dependency_overrides.clear()


def test_chat_completions_output_block_logs_request_summary(
    mock_policy_service, mock_provider_router, caplog
):
    """출력 BLOCK 종료도 요약 로그에 최종 상태를 남긴다."""
    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="유해 콘텐츠 감지",
            layer="L3",
        )
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings_override()

    try:
        c = TestClient(app)
        with caplog.at_level(logging.INFO):
            response = c.post(
                "/v1/chat/completions",
                json={
                    "model": "solar-pro",
                    "messages": [{"role": "user", "content": "질문"}],
                },
            )

        assert response.status_code == 200
        assert "요청 완료 요약" in caplog.text
        assert "final_status=blocked_output" in caplog.text
        assert "output_guardrail_ms=" in caplog.text
        assert "total_ms=" in caplog.text
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
    """출력 BLOCK 시 SSE 본문에 원본 LLM 응답이 누출되지 않고, 재조립된
    content 에 레이어·스테이지·사유 안내문만 실린다.
    """
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
            layer="L4",
            severity="HIGH",
            confidence=0.88,
            tags=["pii", "secret_leak"],
        )
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings_override()

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
        # 핵심 불변: 원본 LLM 응답이 SSE 어디에도 노출돼서는 안 된다.
        assert leaked not in body

        chunks = _parse_sse_chunks(body)
        # role + content delta N개 + finish 프레임
        assert len(chunks) >= 3
        assert chunks[0]["choices"][0]["delta"].get("role") == "assistant"
        assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
        assert chunks[-1]["choices"][0]["delta"] == {}

        rebuilt = "".join(
            c["choices"][0]["delta"].get("content", "") for c in chunks
        )
        assert "L4" in rebuilt
        assert "출력 보안" in rebuilt
        assert "민감 정보 감지" in rebuilt
        # 비표준 error 블록은 어느 프레임에도 실리지 않는다.
        assert all("error" not in chunk for chunk in chunks)
    finally:
        app.dependency_overrides.clear()


def test_block_streaming_applies_inter_chunk_delay(
    mock_policy_service, mock_provider_router, monkeypatch
):
    """차단 스트림의 각 content delta 프레임 사이에 설정된 지연이 삽입된다.

    실제 wall-clock 을 소비하지 않도록 `asyncio.sleep` 을 즉시 반환하는
    fake 로 치환하고 호출 인자/횟수만 검증한다.
    """
    import app.routers.chat as chat_router

    sleeps: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(chat_router.asyncio, "sleep", _fake_sleep)
    # 의도적으로 기본값과 다른 값을 주입하여 상수가 실제로 사용됐는지 확인.
    monkeypatch.setattr(
        chat_router, "GUARDRAIL_BLOCK_STREAM_DELAY_SECONDS", 0.02
    )

    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="프롬프트 인젝션 감지",
            layer="L1",
        )
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings_override()

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "악의적 프롬프트"}],
                "stream": True,
            },
        )
        assert response.status_code == 200
        chunks = _parse_sse_chunks(response.text)
        # content delta 프레임 개수 = 전체 chunks - role 프레임 - finish 프레임
        content_frames = [
            ch for ch in chunks if "content" in ch["choices"][0]["delta"]
        ]
        assert len(content_frames) >= 2
        # 각 content delta 프레임 사이에 최소 한 번씩 20ms sleep 이 호출된다.
        block_sleeps = [s for s in sleeps if s == pytest.approx(0.02)]
        assert len(block_sleeps) >= len(content_frames) - 1
    finally:
        app.dependency_overrides.clear()


def test_block_streaming_chunks_rebuild_to_block_content(
    mock_policy_service, mock_provider_router
):
    """SSE content delta 를 이어붙이면 _build_block_content 출력과 동일하다."""
    from app.routers.chat import _build_block_content

    blocked_svc = MagicMock()
    blocked_svc.check_input = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="민감 정보 감지",
            layer="L4",
        )
    )
    blocked_svc.check_output = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: blocked_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings_override()

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "테스트"}],
                "stream": True,
            },
        )
        assert response.status_code == 200
        chunks = _parse_sse_chunks(response.text)
        rebuilt = "".join(
            ch["choices"][0]["delta"].get("content", "") for ch in chunks
        )
        expected = _build_block_content("input", "L4", "민감 정보 감지")
        assert rebuilt == expected
    finally:
        app.dependency_overrides.clear()


def test_policy_fetch_called_once(client, mock_policy_service):
    """요청 처리 시 verify_and_fetch_policy 가 정확히 한 번 호출된다."""
    client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [{"role": "user", "content": "테스트"}],
        },
    )
    mock_policy_service.verify_and_fetch_policy.assert_called_once()


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


def test_input_guardrail_checks_only_latest_user_message(
    client, mock_security_service
):
    """히스토리에 과거 user 턴이 남아 있어도, 이번 턴에 새로 보낸 user
    입력만 가드레일이 본다.

    회귀 방지: `messages_to_request` 가 `messages` 전체를 연결하던 시절에는
    과거 턴이 계속 검사 대상에 포함되어 '한 번 차단되면 이후 요청도 계속
    차단' 되는 버그가 있었다. 이 테스트는 라우터가 messages 를 있는 그대로
    넘기고, 가드레일 직렬화 단계에서 마지막 user 메시지만 추출되는지를
    잠근다.
    """
    from app.services.guardrail_converter import messages_to_request

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "solar-pro",
            "messages": [
                {"role": "user", "content": "주민번호 123456-1234567"},
                {"role": "assistant", "content": "차단 안내"},
                {"role": "user", "content": "안녕하세요"},
            ],
        },
    )
    assert response.status_code == 200

    mock_security_service.check_input.assert_awaited_once()
    call = mock_security_service.check_input.await_args
    passed_messages = call.kwargs["messages"]
    # 라우터는 messages 를 손대지 않고 그대로 서비스에 전달한다.
    assert len(passed_messages) == 3

    # 가드레일 직렬화는 가장 최근 user 턴만 검사 대상으로 삼는다.
    guardrail_req = messages_to_request(passed_messages)
    assert guardrail_req.user_input == "안녕하세요"
    assert "주민번호" not in guardrail_req.user_input


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
    mock_policy_service.verify_and_fetch_policy = AsyncMock(
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


# ── outboundEnabled 정책 플래그 테스트 ──────────────────────────


def test_outbound_disabled_skips_output_guardrail(mock_provider_router):
    """`policy.outbound=False` 이면 check_output 은 호출되지 않고, LLM 원본
    응답이 그대로 전달된다. 출력 레이어가 BLOCK 을 내도록 세팅해도 스킵 경로가
    먼저 타기 때문에 BLOCK 안내문이 섞이지 않는다."""
    outbound_off_ps = MagicMock()
    outbound_off_ps.verify_and_fetch_policy = AsyncMock(
        return_value=_outbound_disabled_policy()
    )
    security_svc = MagicMock()
    security_svc.check_input = AsyncMock(
        return_value=GuardrailResult(status=CheckStatus.PASS)
    )
    # 스킵 경로가 먼저 타지 않으면 아래 BLOCK 이 응답에 반영된다 — 실수로
    # 가드레일을 돌린 경우를 확실히 잡아내기 위한 함정.
    security_svc.check_output = AsyncMock(
        return_value=GuardrailResult(
            status=CheckStatus.BLOCK,
            reason="호출되면 안 됨",
            layer="L3",
        )
    )

    app.dependency_overrides[get_policy_service] = lambda: outbound_off_ps
    app.dependency_overrides[get_security_service] = lambda: security_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _default_settings_override()

    try:
        c = TestClient(app)
        response = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "안녕"}],
            },
        )
        assert response.status_code == 200
        data = response.json()
        # LLM 원본 응답이 그대로 전달되어야 한다.
        assert data["choices"][0]["message"]["content"] == (
            "안녕하세요! 무엇을 도와드릴까요?"
        )
        # check_output 은 호출조차 되지 않아야 한다.
        security_svc.check_output.assert_not_awaited()
        # 입력 검사는 정상적으로 호출된다 — 스킵은 출력에만 국한.
        security_svc.check_input.assert_awaited_once()
    finally:
        app.dependency_overrides.clear()


def test_outbound_disabled_observe_mode_skips_output_checks(
    mock_provider_router,
):
    """관찰 모드에서도 `policy.outbound=False` 이면 check_output_all 이
    호출되지 않고, 응답의 `guardrail_reports.output` 이 빈 배열로 첨부된다."""
    outbound_off_ps = MagicMock()
    outbound_off_ps.verify_and_fetch_policy = AsyncMock(
        return_value=_outbound_disabled_policy()
    )
    observe_svc = MagicMock()
    observe_svc.check_input_all = AsyncMock(
        return_value=[GuardrailResult(status=CheckStatus.PASS, layer="L1")]
    )
    observe_svc.check_output_all = AsyncMock(return_value=[])

    app.dependency_overrides[get_policy_service] = lambda: outbound_off_ps
    app.dependency_overrides[get_security_service] = lambda: observe_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _observe_settings_override()

    try:
        c = TestClient(app)
        resp = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "데모"}],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # 관찰 모드에서도 출력 검사는 완전히 건너뛰어야 한다.
        observe_svc.check_output_all.assert_not_awaited()
        # input reports 는 유지, output 은 빈 배열.
        reports = data["guardrail_reports"]
        assert reports["mode"] == "observe"
        assert [r["layer"] for r in reports["input"]] == ["L1"]
        assert reports["output"] == []
    finally:
        app.dependency_overrides.clear()


def _observe_settings_override():
    """CONTINUE_ON_LAYER_FAILURE=true 를 주입하는 Settings 오버라이드."""

    def _settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=False,
            skip_header_verification=True,
            app_env="dev",
            continue_on_layer_failure=True,
        )

    return _settings


def test_observe_mode_input_block_allows_llm_call(
    mock_policy_service, mock_provider_router
):
    """관찰 모드에서는 입력 레이어가 BLOCK 을 내도 LLM 을 호출하고
    정상 200 응답에 guardrail_reports 가 첨부된다."""
    observe_svc = MagicMock()
    observe_svc.check_input_all = AsyncMock(
        return_value=[
            GuardrailResult(
                status=CheckStatus.BLOCK,
                reason="injection",
                layer="L1",
                severity="HIGH",
                confidence=0.9,
                tags=["prompt_injection"],
            ),
            GuardrailResult(status=CheckStatus.PASS, layer="L3"),
        ]
    )
    observe_svc.check_output_all = AsyncMock(
        return_value=[GuardrailResult(status=CheckStatus.PASS, layer="L2")]
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: observe_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _observe_settings_override()

    try:
        c = TestClient(app)
        resp = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "데모 프롬프트"}],
            },
        )
        assert resp.status_code == 200
        data = resp.json()

        # BLOCK 이어도 차단 응답 대신 정상 LLM 응답이 돌아와야 한다.
        assert data["choices"][0]["finish_reason"] != "content_filter"
        assert data["choices"][0]["message"]["content"] == (
            "안녕하세요! 무엇을 도와드릴까요?"
        )
        assert data.get("error") is None

        # guardrail_reports 가 모든 레이어 판정을 담고 있어야 한다.
        reports = data["guardrail_reports"]
        assert reports["mode"] == "observe"
        assert [r["layer"] for r in reports["input"]] == ["L1", "L3"]
        assert [r["status"] for r in reports["input"]] == ["block", "pass"]
        assert reports["input"][0]["reason"] == "injection"
        assert reports["input"][0]["severity"] == "HIGH"
        assert reports["input"][0]["tags"] == ["prompt_injection"]

        # LLM 은 호출되었어야 한다.
        llm_svc = mock_provider_router.resolve.return_value[0]
        llm_svc.chat.assert_awaited_once()

        # 관찰 모드에서는 *_all 메서드만 호출되고, 기존 짧은회로 메서드는
        # 사용되지 않는다.
        assert not observe_svc.check_input.called
        assert not observe_svc.check_output.called
    finally:
        app.dependency_overrides.clear()


def test_observe_mode_output_block_keeps_original_content(
    mock_policy_service, mock_provider_router
):
    """관찰 모드에서는 출력 레이어가 BLOCK 을 내도 원본 LLM 응답이
    그대로 사용자에게 전송된다."""
    original_reply = "안녕하세요! 무엇을 도와드릴까요?"
    observe_svc = MagicMock()
    observe_svc.check_input_all = AsyncMock(
        return_value=[GuardrailResult(status=CheckStatus.PASS, layer="L1")]
    )
    observe_svc.check_output_all = AsyncMock(
        return_value=[
            GuardrailResult(status=CheckStatus.PASS, layer="L1"),
            GuardrailResult(
                status=CheckStatus.BLOCK,
                reason="pii leak",
                layer="L4",
                severity="CRITICAL",
                confidence=0.95,
                tags=["pii"],
            ),
        ]
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: observe_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _observe_settings_override()

    try:
        c = TestClient(app)
        resp = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "질문"}],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["choices"][0]["message"]["content"] == original_reply
        assert data["choices"][0]["finish_reason"] != "content_filter"

        reports = data["guardrail_reports"]
        assert reports["mode"] == "observe"
        assert [r["status"] for r in reports["output"]] == ["pass", "block"]
        assert reports["output"][1]["reason"] == "pii leak"
    finally:
        app.dependency_overrides.clear()


def test_observe_mode_streaming_attaches_guardrail_reports(
    mock_policy_service, mock_provider_router
):
    """관찰 모드의 스트리밍 응답은 마지막 finish 프레임에
    guardrail_reports 를 싣고 원본 content 를 그대로 전달한다."""
    observe_svc = MagicMock()
    observe_svc.check_input_all = AsyncMock(
        return_value=[
            GuardrailResult(
                status=CheckStatus.BLOCK,
                reason="injection",
                layer="L1",
                severity="HIGH",
            )
        ]
    )
    observe_svc.check_output_all = AsyncMock(
        return_value=[GuardrailResult(status=CheckStatus.PASS, layer="L2")]
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: observe_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _observe_settings_override()

    try:
        c = TestClient(app)
        resp = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "데모"}],
                "stream": True,
            },
        )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        chunks = _parse_sse_chunks(resp.text)

        # content_filter 가 아니라 정상 종료 프레임이어야 한다.
        assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
        rebuilt = "".join(
            c["choices"][0]["delta"].get("content", "") for c in chunks
        )
        assert rebuilt == "안녕하세요! 무엇을 도와드릴까요?"

        # 마지막 finish 프레임에 guardrail_reports 가 실린다.
        last = chunks[-1]
        reports = last["guardrail_reports"]
        assert reports["mode"] == "observe"
        assert reports["input"][0]["layer"] == "L1"
        assert reports["input"][0]["status"] == "block"
        assert reports["output"][0]["status"] == "pass"
    finally:
        app.dependency_overrides.clear()


def test_observe_mode_logs_request_summary(
    mock_policy_service, mock_provider_router, caplog
):
    """관찰 모드도 종료 시 같은 구조의 시간 요약 로그를 남긴다."""
    observe_svc = MagicMock()
    observe_svc.check_input_all = AsyncMock(
        return_value=[GuardrailResult(status=CheckStatus.PASS, layer="L1")]
    )
    observe_svc.check_output_all = AsyncMock(
        return_value=[GuardrailResult(status=CheckStatus.PASS, layer="L2")]
    )

    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: observe_svc
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_settings] = _observe_settings_override()

    try:
        c = TestClient(app)
        with caplog.at_level(logging.INFO):
            response = c.post(
                "/v1/chat/completions",
                json={
                    "model": "solar-pro",
                    "messages": [{"role": "user", "content": "데모"}],
                },
            )

        assert response.status_code == 200
        assert "요청 완료 요약" in caplog.text
        assert "final_status=observe_success" in caplog.text
        assert "input_guardrail_ms=" in caplog.text
        assert "output_guardrail_ms=" in caplog.text
        assert "response_emit_ms=" in caplog.text
    finally:
        app.dependency_overrides.clear()


def test_skip_policy_fetch_forces_all_layers_enabled(
    mock_security_service, mock_provider_router
):
    """SKIP_POLICY_FETCH=true 이면 verify_and_fetch_policy 를 호출하지 않고 L1~L6 전부를 강제 활성화한다."""  # noqa: E501
    mock_ps = MagicMock()
    mock_ps.verify_and_fetch_policy = AsyncMock()

    def _skip_settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=True,
            skip_header_verification=True,
            continue_on_layer_failure=False,
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
        mock_ps.verify_and_fetch_policy.assert_not_called()

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


def test_skip_policy_fetch_input_layers_subset(
    mock_security_service, mock_provider_router
):
    """SKIP_POLICY_FETCH_INPUT_LAYERS 로 입력 레이어 부분 활성화."""
    mock_ps = MagicMock()
    mock_ps.verify_and_fetch_policy = AsyncMock()

    def _skip_settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=True,
            skip_header_verification=True,
            continue_on_layer_failure=False,
            app_env="dev",
            skip_policy_fetch_config=SkipPolicyFetchSettings(
                input_layers="L4,L5",
                output_layers="L1,L2,L3,L4,L5,L6",
            ),
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
        input_policy = mock_security_service.check_input.call_args.kwargs[
            "policy"
        ]
        output_policy = mock_security_service.check_output.call_args.kwargs[
            "policy"
        ]
        assert input_policy.enabled_layers() == [4, 5]
        assert output_policy.enabled_layers() == [1, 2, 3, 4, 5, 6]
    finally:
        app.dependency_overrides.clear()


def test_skip_policy_fetch_l5_setting_applied_to_input_and_output_policy(
    mock_security_service, mock_provider_router
):
    """SKIP_POLICY_FETCH=true 에서 L5 설정 환경변수가 정책에 주입된다."""
    mock_ps = MagicMock()
    mock_ps.verify_and_fetch_policy = AsyncMock()

    def _skip_settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=True,
            skip_header_verification=True,
            continue_on_layer_failure=False,
            app_env="dev",
            skip_policy_fetch_config=SkipPolicyFetchSettings(
                l5_model="pii_model_v11",
                l5_threshold=0.82,
            ),
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
        input_policy = mock_security_service.check_input.call_args.kwargs[
            "policy"
        ]
        output_policy = mock_security_service.check_output.call_args.kwargs[
            "policy"
        ]
        assert input_policy.l5_setting is not None
        assert input_policy.l5_setting.model == "pii_model_v11"
        assert input_policy.l5_setting.threshold == 0.82
        assert output_policy.l5_setting is not None
        assert output_policy.l5_setting.model == "pii_model_v11"
        assert output_policy.l5_setting.threshold == 0.82
    finally:
        app.dependency_overrides.clear()


def test_skip_policy_fetch_output_layers_empty_skips_output_check(
    mock_security_service, mock_provider_router
):
    """OUTPUT_LAYERS='' 면 check_output 호출 없이 LLM 응답을 통과시킨다."""
    mock_ps = MagicMock()
    mock_ps.verify_and_fetch_policy = AsyncMock()
    mock_security_service.check_output.reset_mock()

    def _skip_settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=True,
            skip_header_verification=True,
            continue_on_layer_failure=False,
            app_env="dev",
            skip_policy_fetch_config=SkipPolicyFetchSettings(
                input_layers="L4",
                output_layers="",
            ),
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
        # 출력 가드레일은 outbound=False 로 통째로 생략되어야 한다.
        mock_security_service.check_output.assert_not_called()
        input_policy = mock_security_service.check_input.call_args.kwargs[
            "policy"
        ]
        assert input_policy.enabled_layers() == [4]
    finally:
        app.dependency_overrides.clear()


def test_skip_policy_fetch_input_layers_empty_runs_no_input_layers(
    mock_security_service, mock_provider_router
):
    """SKIP_POLICY_FETCH_INPUT_LAYERS='' 면 입력 정책에 활성 레이어가 없다."""
    mock_ps = MagicMock()
    mock_ps.verify_and_fetch_policy = AsyncMock()

    def _skip_settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=True,
            skip_header_verification=True,
            continue_on_layer_failure=False,
            app_env="dev",
            skip_policy_fetch_config=SkipPolicyFetchSettings(
                input_layers="",
                output_layers="L1,L2,L3,L4,L5,L6",
            ),
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
        input_policy = mock_security_service.check_input.call_args.kwargs[
            "policy"
        ]
        output_policy = mock_security_service.check_output.call_args.kwargs[
            "policy"
        ]
        assert input_policy.enabled_layers() == []
        assert output_policy.enabled_layers() == [1, 2, 3, 4, 5, 6]
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 사용자 요청 헤더 검증 (SKIP_HEADER_VERIFICATION=false)
# ---------------------------------------------------------------------------


def _verify_enabled_settings():
    """헤더 검증을 강제 (skip_header_verification=False) 하는 Settings 오버라이드."""  # noqa: E501

    def _settings():
        s = get_settings()
        from app.config import Settings

        return Settings(
            llm_model=s.llm_model,
            upstage_api_key=s.upstage_api_key.get_secret_value(),
            skip_policy_fetch=False,
            skip_header_verification=False,
            continue_on_layer_failure=False,
            request_timestamp_skew_sec=300,
        )

    return _settings


def _valid_user_headers() -> dict[str, str]:
    """timestamp/nonce 이 서버 시간 기준으로 유효한 4개 헤더."""
    import time as _time

    return {
        "X-API-Key": "uak_user",
        "X-Timestamp": str(int(_time.time())),
        "X-Nonce": "nonce-unique-xyz",
        "X-Signature": "a" * 64,
    }


def _setup_header_verify_overrides(
    mock_policy_service,
    mock_security_service,
    mock_provider_router,
    nonce_store,
):
    """헤더 검증 테스트용 DI 오버라이드를 일괄 등록한다."""
    app.dependency_overrides[get_policy_service] = lambda: mock_policy_service
    app.dependency_overrides[get_security_service] = lambda: (
        mock_security_service
    )
    app.dependency_overrides[get_provider_router] = lambda: mock_provider_router
    app.dependency_overrides[get_nonce_store] = lambda: nonce_store
    app.dependency_overrides[get_settings] = _verify_enabled_settings()


def test_header_verification_missing_returns_401(
    mock_policy_service,
    mock_security_service,
    mock_provider_router,
    nonce_store,
):
    """헤더가 하나라도 누락되면 401 + header_verification_failed 를 반환한다."""
    _setup_header_verify_overrides(
        mock_policy_service,
        mock_security_service,
        mock_provider_router,
        nonce_store,
    )
    try:
        c = TestClient(app)
        resp = c.post(
            "/v1/chat/completions",
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "안녕"}],
            },
        )
        assert resp.status_code == 401
        body = resp.json()
        assert body["error"]["type"] == "header_verification_failed"
        assert "X-API-Key" in body["error"]["reason"]
        # 검증 실패 시 ADMIN 정책 조회가 호출되지 않아야 한다.
        mock_policy_service.verify_and_fetch_policy.assert_not_called()
    finally:
        app.dependency_overrides.clear()


def test_header_verification_timestamp_skew_returns_401(
    mock_policy_service,
    mock_security_service,
    mock_provider_router,
    nonce_store,
):
    """timestamp 시간차가 허용 범위를 넘으면 401."""
    _setup_header_verify_overrides(
        mock_policy_service,
        mock_security_service,
        mock_provider_router,
        nonce_store,
    )
    headers = _valid_user_headers()
    headers["X-Timestamp"] = "1000000000"  # 2001년 — 현재와 수년 차이
    try:
        c = TestClient(app)
        resp = c.post(
            "/v1/chat/completions",
            headers=headers,
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "안녕"}],
            },
        )
        assert resp.status_code == 401
        assert resp.json()["error"]["type"] == "header_verification_failed"
    finally:
        app.dependency_overrides.clear()


def test_header_verification_replayed_nonce_returns_401(
    mock_policy_service,
    mock_security_service,
    mock_provider_router,
    nonce_store,
):
    """동일 nonce 를 연속 두 번 보내면 두 번째 요청이 401."""
    _setup_header_verify_overrides(
        mock_policy_service,
        mock_security_service,
        mock_provider_router,
        nonce_store,
    )
    headers = _valid_user_headers()
    body = {
        "model": "solar-pro",
        "messages": [{"role": "user", "content": "안녕"}],
    }
    try:
        c = TestClient(app)
        first = c.post("/v1/chat/completions", headers=headers, json=body)
        assert first.status_code == 200
        second = c.post("/v1/chat/completions", headers=headers, json=body)
        assert second.status_code == 401
        assert second.json()["error"]["type"] == "header_verification_failed"
    finally:
        app.dependency_overrides.clear()


def test_header_verification_success_passes_headers_to_policy_service(
    mock_policy_service,
    mock_security_service,
    mock_provider_router,
    nonce_store,
):
    """정상 헤더는 그대로 verify_and_fetch_policy 에 전달된다."""
    _setup_header_verify_overrides(
        mock_policy_service,
        mock_security_service,
        mock_provider_router,
        nonce_store,
    )
    headers = _valid_user_headers()
    try:
        c = TestClient(app)
        resp = c.post(
            "/v1/chat/completions",
            headers=headers,
            json={
                "model": "solar-pro",
                "messages": [{"role": "user", "content": "안녕"}],
            },
        )
        assert resp.status_code == 200
        call_kwargs = (
            mock_policy_service.verify_and_fetch_policy.call_args.kwargs
        )
        assert call_kwargs["headers"].api_key == headers["X-API-Key"]
        assert call_kwargs["headers"].timestamp == headers["X-Timestamp"]
        assert call_kwargs["headers"].nonce == headers["X-Nonce"]
        assert call_kwargs["headers"].signature == headers["X-Signature"]
        # bodyHash 는 sha256 hex 64자여야 한다.
        assert len(call_kwargs["body_hash"]) == 64
    finally:
        app.dependency_overrides.clear()
