"""SolarService 테스트 (openai 클라이언트 mock)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.solar_service import SolarService


@pytest.fixture
def mock_settings():
    """테스트용 더미 Settings."""
    settings = MagicMock()
    settings.upstage_api_key.get_secret_value.return_value = "test-key"
    settings.llm_base_url = "https://api.upstage.ai/v1"
    settings.llm_model = "solar-pro"
    return settings


@pytest.fixture
def service(mock_settings, mocker):
    """AsyncOpenAI 클라이언트가 mock된 SolarService."""
    mock_client = MagicMock()
    mocker.patch(
        "app.services.solar_service.AsyncOpenAI",
        return_value=mock_client,
    )
    return SolarService(settings=mock_settings), mock_client


async def test_chat_calls_completions_create(service):
    """chat()이 기본 파라미터로 completions.create를 호출한다."""
    svc, mock_client = service

    mock_client.chat.completions.create = AsyncMock(return_value=MagicMock())

    messages = [{"role": "user", "content": "안녕"}]
    await svc.chat(messages=messages)

    mock_client.chat.completions.create.assert_called_once_with(
        model="solar-pro",
        messages=messages,
        stream=False,
    )


async def test_chat_returns_completion_object(service):
    """chat()이 ChatCompletion 객체 전체를 반환한다.

    라우터가 id/created/model/usage/finish_reason/tool_calls 를
    복사해야 하므로 content 문자열이 아닌 응답 객체를 그대로 반환한다.
    """
    svc, mock_client = service

    mock_response = MagicMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    result = await svc.chat(messages=[{"role": "user", "content": "질문"}])
    assert result is mock_response


async def test_chat_passes_through_openai_parameters(service):
    """temperature/top_p/max_tokens/tools 등이 Solar 호출에 전달된다."""
    svc, mock_client = service
    mock_client.chat.completions.create = AsyncMock(return_value=MagicMock())

    messages = [{"role": "user", "content": "질문"}]
    tools = [{"type": "function", "function": {"name": "f"}}]

    await svc.chat(
        messages=messages,
        temperature=0.2,
        top_p=0.9,
        max_tokens=128,
        tools=tools,
        tool_choice="auto",
        response_format={"type": "json_object"},
        stop=["\n\n"],
        seed=42,
    )

    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["temperature"] == 0.2
    assert call_kwargs["top_p"] == 0.9
    assert call_kwargs["max_tokens"] == 128
    assert call_kwargs["tools"] == tools
    assert call_kwargs["tool_choice"] == "auto"
    assert call_kwargs["response_format"] == {"type": "json_object"}
    assert call_kwargs["stop"] == ["\n\n"]
    assert call_kwargs["seed"] == 42


async def test_chat_drops_none_parameters(service):
    """None 값은 Solar 호출에서 제거되어 unknown kwarg 오류를 방지한다."""
    svc, mock_client = service
    mock_client.chat.completions.create = AsyncMock(return_value=MagicMock())

    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        temperature=None,
        max_tokens=None,
        tools=None,
    )

    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert "temperature" not in call_kwargs
    assert "max_tokens" not in call_kwargs
    assert "tools" not in call_kwargs


async def test_chat_forces_stream_false_even_if_overridden(service):
    """호출자가 stream=True 를 넘기더라도 항상 비스트리밍으로 호출된다."""
    svc, mock_client = service
    mock_client.chat.completions.create = AsyncMock(return_value=MagicMock())

    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        stream=True,
    )

    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["stream"] is False


async def test_chat_request_model_overrides_default(service):
    """요청에 model 이 지정되면 env 기본값 대신 사용한다."""
    svc, mock_client = service
    mock_client.chat.completions.create = AsyncMock(return_value=MagicMock())

    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        model="solar-pro2",
    )

    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "solar-pro2"


async def test_chat_wraps_solar_specific_fields_in_extra_body(service):
    """Solar 전용 필드(reasoning_effort)는 extra_body 로 전달된다."""
    svc, mock_client = service
    mock_client.chat.completions.create = AsyncMock(return_value=MagicMock())

    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        reasoning_effort="high",
    )

    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs.get("extra_body", {}).get("reasoning_effort") == "high"
    assert "reasoning_effort" not in call_kwargs


async def test_solar_service_exposes_only_chat(service):
    """SolarService는 더 이상 stream_chat을 노출하지 않는다.

    LLM 호출은 항상 비스트리밍이며, 사용자에게의 스트리밍은
    라우터 계층에서 재방출한다.
    """
    svc, _ = service
    assert not hasattr(svc, "stream_chat")
