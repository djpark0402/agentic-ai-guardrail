"""LLMService 테스트 (LiteLLM acompletion mock)."""

from unittest.mock import AsyncMock

import pytest
from litellm.types.utils import Choices, Message, ModelResponse, Usage

from app.services.llm_service import LLMService


def _model_response(
    *,
    content: str | None = "응답",
    finish_reason: str = "stop",
    model: str = "openai/test-model",
    tool_calls: list[dict[str, object]] | None = None,
    usage: Usage | None = None,
) -> ModelResponse:
    """테스트용 LiteLLM ModelResponse 를 만든다."""
    return ModelResponse(
        id="chatcmpl-test",
        created=123,
        model=model,
        object="chat.completion",
        choices=[
            Choices(
                index=0,
                finish_reason=finish_reason,
                message=Message(
                    role="assistant",
                    content=content,
                    tool_calls=tool_calls,
                ),
            )
        ],
        usage=usage,
    )


@pytest.fixture
def service(mocker):
    """LiteLLM acompletion 이 mock 된 LLMService."""
    mock_completion = AsyncMock(return_value=_model_response())
    mocker.patch(
        "app.services.llm_service.litellm.acompletion",
        mock_completion,
    )
    svc = LLMService(
        api_key="test-key",
        base_url="https://api.test.ai/v1",
        model="test-model",
        provider_name="test",
    )
    return svc, mock_completion


async def test_chat_calls_litellm_acompletion(service):
    """chat()은 LiteLLM acompletion 을 한 번 호출한다."""
    svc, mock_completion = service
    await svc.chat(messages=[{"role": "user", "content": "안녕"}])
    mock_completion.assert_awaited_once()


async def test_chat_returns_completion_compatible_object(service):
    """LiteLLM 응답 객체를 ChatCompletion 호환 형태로 그대로 반환한다."""
    svc, _ = service
    result = await svc.chat(messages=[{"role": "user", "content": "질문"}])
    assert result.choices[0].message.content == "응답"
    assert result.choices[0].message.role == "assistant"
    assert result.choices[0].finish_reason == "stop"
    assert result.model == "test-model"
    assert result.id == "chatcmpl-test"
    assert result.created == 123


async def test_chat_passes_through_parameters(service):
    """OpenAI 호환 파라미터를 LiteLLM 호출에 그대로 전달한다."""
    svc, mock_completion = service
    tools = [{"type": "function", "function": {"name": "f"}}]
    await svc.chat(
        messages=[{"role": "user", "content": "질문"}],
        temperature=0.2,
        top_p=0.9,
        max_tokens=128,
        tools=tools,
        tool_choice="auto",
    )
    kwargs = mock_completion.await_args.kwargs
    assert kwargs["temperature"] == 0.2
    assert kwargs["top_p"] == 0.9
    assert kwargs["max_tokens"] == 128
    assert kwargs["tools"] == tools
    assert kwargs["tool_choice"] == "auto"


async def test_chat_drops_none_parameters(service):
    """None 값인 파라미터는 upstream 호출에서 제거한다."""
    svc, mock_completion = service
    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        temperature=None,
        max_tokens=None,
        tools=None,
    )
    kwargs = mock_completion.await_args.kwargs
    assert "temperature" not in kwargs
    assert "max_tokens" not in kwargs
    assert "tools" not in kwargs


async def test_chat_forces_non_streaming_upstream_call(service):
    """사용자 stream 요청과 무관하게 upstream 호출은 non-stream 이다."""
    svc, mock_completion = service
    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        stream=True,
    )
    kwargs = mock_completion.await_args.kwargs
    assert kwargs["stream"] is False


async def test_chat_model_override(service):
    """요청 모델이 있으면 기본 모델보다 우선한다."""
    svc, mock_completion = service
    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        model="other-model",
    )
    kwargs = mock_completion.await_args.kwargs
    assert kwargs["model"] == "openai/other-model"


async def test_chat_passes_nonstandard_fields_directly(service):
    """provider 전용 파라미터도 LiteLLM 에 직접 전달한다."""
    svc, mock_completion = service
    await svc.chat(
        messages=[{"role": "user", "content": "q"}],
        reasoning_effort="high",
    )
    kwargs = mock_completion.await_args.kwargs
    assert kwargs["reasoning_effort"] == "high"


async def test_provider_name_property(service):
    """provider_name 속성을 반환한다."""
    svc, _ = service
    assert svc.provider_name == "test"


async def test_chat_passes_openai_messages_without_conversion(service):
    """OpenAI 포맷 메시지를 변환 없이 LiteLLM 에 전달한다."""
    svc, mock_completion = service
    messages = [
        {"role": "system", "content": "시스템"},
        {"role": "user", "content": "사용자"},
        {"role": "assistant", "content": "어시스턴트"},
    ]
    await svc.chat(messages=messages)
    assert mock_completion.await_args.kwargs["messages"] == messages


async def test_chat_handles_tool_calls_response(mocker):
    """LiteLLM tool_calls 응답을 그대로 보존한다."""
    tool_calls = [
        {
            "id": "call_123",
            "type": "function",
            "function": {"name": "get_weather", "arguments": "{}"},
        }
    ]
    mock_completion = AsyncMock(
        return_value=_model_response(
            content=None,
            finish_reason="tool_calls",
            tool_calls=tool_calls,
        )
    )
    mocker.patch(
        "app.services.llm_service.litellm.acompletion",
        mock_completion,
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
    """LiteLLM usage 객체를 그대로 보존한다."""
    mock_completion = AsyncMock(
        return_value=_model_response(
            usage=Usage(
                prompt_tokens=10,
                completion_tokens=20,
                total_tokens=30,
            )
        )
    )
    mocker.patch(
        "app.services.llm_service.litellm.acompletion",
        mock_completion,
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


async def test_chat_uses_configured_openai_compatible_endpoint(service):
    """OpenAI 호환 엔드포인트 설정을 LiteLLM 에 전달한다."""
    svc, mock_completion = service
    await svc.chat(messages=[{"role": "user", "content": "q"}])
    kwargs = mock_completion.await_args.kwargs
    assert kwargs["model"] == "openai/test-model"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["base_url"] == "https://api.test.ai/v1"
