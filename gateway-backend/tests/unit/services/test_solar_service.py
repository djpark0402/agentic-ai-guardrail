"""SolarService 테스트 (LangChain ChatOpenAI mock)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from langchain_core.messages import AIMessage

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
    """ChatOpenAI 가 mock 된 SolarService."""
    mock_llm = MagicMock()
    mock_llm.bind = MagicMock(return_value=mock_llm)
    mock_llm.ainvoke = AsyncMock(
        return_value=AIMessage(
            content="응답",
            response_metadata={
                "model_name": "solar-pro",
                "finish_reason": "stop",
            },
            id="chatcmpl-test",
        )
    )
    mocker.patch(
        "app.services.solar_service.ChatOpenAI",
        return_value=mock_llm,
    )
    return SolarService(settings=mock_settings), mock_llm


async def test_chat_calls_ainvoke(service):
    """chat()이 LangChain ainvoke 를 호출한다."""
    svc, mock_llm = service

    await svc.chat(messages=[{"role": "user", "content": "안녕"}])

    mock_llm.ainvoke.assert_called_once()


async def test_chat_returns_completion_compatible_object(service):
    """chat()이 ChatCompletion 호환 객체를 반환한다."""
    svc, _ = service

    result = await svc.chat(messages=[{"role": "user", "content": "질문"}])

    assert result.choices[0].message.content == "응답"
    assert result.choices[0].message.role == "assistant"
    assert result.choices[0].finish_reason == "stop"
    assert result.model == "solar-pro"
    assert hasattr(result, "id")
    assert hasattr(result, "created")


async def test_chat_passes_through_parameters(service):
    """temperature/tools 등이 bind()를 통해 전달된다."""
    svc, mock_llm = service

    tools = [{"type": "function", "function": {"name": "f"}}]

    await svc.chat(
        messages=[{"role": "user", "content": "질문"}],
        temperature=0.2,
        top_p=0.9,
        max_tokens=128,
        tools=tools,
        tool_choice="auto",
    )

    bind_calls = mock_llm.bind.call_args_list
    bound_kwargs = {}
    for call in bind_calls:
        bound_kwargs.update(call.kwargs)

    assert bound_kwargs["temperature"] == 0.2
    assert bound_kwargs["top_p"] == 0.9
    assert bound_kwargs["max_tokens"] == 128
    assert bound_kwargs["tools"] == tools
    assert bound_kwargs["tool_choice"] == "auto"


async def test_chat_drops_none_parameters(service):
    """None 값은 bind()에 전달되지 않는다."""
    svc, mock_llm = service

    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        temperature=None,
        max_tokens=None,
        tools=None,
    )

    for call in mock_llm.bind.call_args_list:
        assert "temperature" not in call.kwargs
        assert "max_tokens" not in call.kwargs
        assert "tools" not in call.kwargs


async def test_chat_ignores_stream_parameter(service):
    """stream=True 를 넘기더라도 무시된다."""
    svc, mock_llm = service

    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        stream=True,
    )

    for call in mock_llm.bind.call_args_list:
        assert "stream" not in call.kwargs


async def test_chat_model_override(service):
    """요청에 model 이 지정되면 bind(model=...)로 전달된다."""
    svc, mock_llm = service

    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        model="solar-pro2",
    )

    bind_calls = mock_llm.bind.call_args_list
    bound_kwargs = {}
    for call in bind_calls:
        bound_kwargs.update(call.kwargs)

    assert bound_kwargs["model"] == "solar-pro2"


async def test_chat_wraps_solar_specific_fields(service):
    """Solar 전용 필드는 model_kwargs 로 전달된다."""
    svc, mock_llm = service

    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        reasoning_effort="high",
    )

    bind_calls = mock_llm.bind.call_args_list
    bound_kwargs = {}
    for call in bind_calls:
        bound_kwargs.update(call.kwargs)

    assert (
        bound_kwargs.get("model_kwargs", {}).get("reasoning_effort") == "high"
    )


async def test_solar_service_exposes_only_chat(service):
    """SolarService는 stream_chat을 노출하지 않는다."""
    svc, _ = service
    assert not hasattr(svc, "stream_chat")


async def test_chat_converts_messages_to_langchain(service, mocker):
    """OpenAI 포맷 메시지가 LangChain 메시지로 변환된다."""
    svc, mock_llm = service

    messages = [
        {"role": "system", "content": "시스템 메시지"},
        {"role": "user", "content": "사용자 메시지"},
        {
            "role": "assistant",
            "content": "어시스턴트 메시지",
        },
    ]

    await svc.chat(messages=messages)

    call_args = mock_llm.ainvoke.call_args
    lc_messages = call_args.args[0]

    assert len(lc_messages) == 3
    assert lc_messages[0].__class__.__name__ == "SystemMessage"
    assert lc_messages[1].__class__.__name__ == "HumanMessage"
    assert lc_messages[2].__class__.__name__ == "AIMessage"


async def test_chat_handles_tool_calls_response(mock_settings, mocker):
    """tool_calls 가 포함된 응답을 OpenAI 형식으로 변환한다."""
    mock_llm = MagicMock()
    mock_llm.bind = MagicMock(return_value=mock_llm)
    mock_llm.ainvoke = AsyncMock(
        return_value=AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "get_weather",
                    "args": {"location": "서울"},
                    "id": "call_123",
                }
            ],
            response_metadata={"finish_reason": "tool_calls"},
            id="chatcmpl-tc",
        )
    )
    mocker.patch(
        "app.services.solar_service.ChatOpenAI",
        return_value=mock_llm,
    )

    svc = SolarService(settings=mock_settings)
    result = await svc.chat(messages=[{"role": "user", "content": "서울 날씨"}])

    tc = result.choices[0].message.tool_calls
    assert tc is not None
    assert len(tc) == 1
    assert tc[0].model_dump()["function"]["name"] == "get_weather"
    assert tc[0].id == "call_123"
    assert tc[0].type == "function"


async def test_chat_handles_usage_metadata(mock_settings, mocker):
    """usage_metadata 가 ChatCompletion 호환 usage 로 변환된다."""
    mock_llm = MagicMock()
    mock_llm.bind = MagicMock(return_value=mock_llm)
    mock_llm.ainvoke = AsyncMock(
        return_value=AIMessage(
            content="응답",
            response_metadata={"finish_reason": "stop"},
            usage_metadata={
                "input_tokens": 10,
                "output_tokens": 20,
                "total_tokens": 30,
            },
            id="chatcmpl-usage",
        )
    )
    mocker.patch(
        "app.services.solar_service.ChatOpenAI",
        return_value=mock_llm,
    )

    svc = SolarService(settings=mock_settings)
    result = await svc.chat(messages=[{"role": "user", "content": "q"}])

    assert result.usage is not None
    usage = result.usage.model_dump()
    assert usage["prompt_tokens"] == 10
    assert usage["completion_tokens"] == 20
    assert usage["total_tokens"] == 30
