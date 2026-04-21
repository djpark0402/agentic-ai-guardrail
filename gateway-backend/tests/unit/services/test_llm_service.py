"""LLMService 테스트 (LangChain ChatOpenAI mock)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from langchain_core.messages import AIMessage

from app.services.llm_service import LLMService


@pytest.fixture
def service(mocker):
    """ChatOpenAI 가 mock 된 LLMService."""
    mock_llm = MagicMock()
    mock_llm.bind = MagicMock(return_value=mock_llm)
    mock_llm.ainvoke = AsyncMock(
        return_value=AIMessage(
            content="응답",
            response_metadata={
                "model_name": "test-model",
                "finish_reason": "stop",
            },
            id="chatcmpl-test",
        )
    )
    mocker.patch(
        "app.services.llm_service.ChatOpenAI",
        return_value=mock_llm,
    )
    svc = LLMService(
        api_key="test-key",
        base_url="https://api.test.ai/v1",
        model="test-model",
        provider_name="test",
    )
    return svc, mock_llm


async def test_chat_calls_ainvoke(service):
    svc, mock_llm = service
    await svc.chat(messages=[{"role": "user", "content": "안녕"}])
    mock_llm.ainvoke.assert_called_once()


async def test_chat_returns_completion_compatible_object(service):
    svc, _ = service
    result = await svc.chat(messages=[{"role": "user", "content": "질문"}])
    assert result.choices[0].message.content == "응답"
    assert result.choices[0].message.role == "assistant"
    assert result.choices[0].finish_reason == "stop"
    assert result.model == "test-model"
    assert hasattr(result, "id")
    assert hasattr(result, "created")


async def test_chat_passes_through_parameters(service):
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
    bound_kwargs = {}
    for call in mock_llm.bind.call_args_list:
        bound_kwargs.update(call.kwargs)
    assert bound_kwargs["temperature"] == 0.2
    assert bound_kwargs["top_p"] == 0.9
    assert bound_kwargs["max_tokens"] == 128
    assert bound_kwargs["tools"] == tools
    assert bound_kwargs["tool_choice"] == "auto"


async def test_chat_drops_none_parameters(service):
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
    svc, mock_llm = service
    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        stream=True,
    )
    for call in mock_llm.bind.call_args_list:
        assert "stream" not in call.kwargs


async def test_chat_model_override(service):
    svc, mock_llm = service
    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        model="other-model",
    )
    bound_kwargs = {}
    for call in mock_llm.bind.call_args_list:
        bound_kwargs.update(call.kwargs)
    assert bound_kwargs["model"] == "other-model"


async def test_chat_wraps_nonstandard_fields(service):
    svc, mock_llm = service
    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        reasoning_effort="high",
    )
    bound_kwargs = {}
    for call in mock_llm.bind.call_args_list:
        bound_kwargs.update(call.kwargs)
    assert (
        bound_kwargs.get("model_kwargs", {}).get("reasoning_effort") == "high"
    )


async def test_provider_name_property(service):
    svc, _ = service
    assert svc.provider_name == "test"


async def test_chat_converts_messages_to_langchain(service):
    svc, mock_llm = service
    messages = [
        {"role": "system", "content": "시스템"},
        {"role": "user", "content": "사용자"},
        {"role": "assistant", "content": "어시스턴트"},
    ]
    await svc.chat(messages=messages)
    lc_messages = mock_llm.ainvoke.call_args.args[0]
    assert len(lc_messages) == 3
    assert lc_messages[0].__class__.__name__ == "SystemMessage"
    assert lc_messages[1].__class__.__name__ == "HumanMessage"
    assert lc_messages[2].__class__.__name__ == "AIMessage"


async def test_chat_handles_tool_calls_response(mocker):
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
        "app.services.llm_service.ChatOpenAI",
        return_value=mock_llm,
    )
    svc = LLMService(
        api_key="k",
        base_url="https://api.test/v1",
        model="m",
    )
    result = await svc.chat(messages=[{"role": "user", "content": "서울 날씨"}])
    tc = result.choices[0].message.tool_calls
    assert tc is not None
    assert len(tc) == 1
    assert tc[0].model_dump()["function"]["name"] == "get_weather"
    assert tc[0].id == "call_123"


async def test_chat_handles_usage_metadata(mocker):
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
        "app.services.llm_service.ChatOpenAI",
        return_value=mock_llm,
    )
    svc = LLMService(
        api_key="k",
        base_url="https://api.test/v1",
        model="m",
    )
    result = await svc.chat(messages=[{"role": "user", "content": "q"}])
    assert result.usage is not None
    usage = result.usage.model_dump()
    assert usage["prompt_tokens"] == 10
    assert usage["completion_tokens"] == 20
    assert usage["total_tokens"] == 30
