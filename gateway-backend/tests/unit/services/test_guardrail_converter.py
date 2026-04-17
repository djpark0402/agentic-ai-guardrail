"""guardrail_converter 모듈 테스트."""

from core_secure_layer.layers.types import LayerResult, Severity

from app.models.chat import Message
from app.models.guardrail import CheckStatus
from app.services.guardrail_converter import (
    content_to_request,
    layer_result_to_guardrail_result,
    messages_to_request,
)


def test_messages_to_request_extracts_last_user_message():
    """마지막 user 메시지의 텍스트를 user_input으로 추출한다."""
    messages = [
        Message(role="user", content="첫 번째"),
        Message(role="assistant", content="응답"),
        Message(role="user", content="두 번째"),
    ]
    req = messages_to_request(messages)
    assert req.user_input == "두 번째"


def test_messages_to_request_handles_multimodal_content():
    """멀티모달(list[dict]) content에서 텍스트 부분을 결합한다."""
    messages = [
        Message(
            role="user",
            content=[
                {"type": "text", "text": "이미지 설명:"},
                {"type": "image_url", "image_url": {"url": "data:..."}},
                {"type": "text", "text": "이것은 무엇인가요?"},
            ],
        ),
    ]
    req = messages_to_request(messages)
    assert req.user_input == "이미지 설명: 이것은 무엇인가요?"


def test_messages_to_request_returns_empty_when_no_user_message():
    """user 메시지가 없으면 빈 문자열을 반환한다."""
    messages = [
        Message(role="system", content="시스템 프롬프트"),
        Message(role="assistant", content="응답"),
    ]
    req = messages_to_request(messages)
    assert req.user_input == ""


def test_content_to_request_wraps_string():
    """문자열을 GuardrailRequest.user_input으로 래핑한다."""
    req = content_to_request("LLM 응답 텍스트")
    assert req.user_input == "LLM 응답 텍스트"


def test_layer_result_to_guardrail_result_pass():
    """allowed=True인 LayerResult는 PASS로 변환된다."""
    lr = LayerResult(name="L1", allowed=True)
    result = layer_result_to_guardrail_result(lr)
    assert result.status == CheckStatus.PASS
    assert result.layer == "L1"
    assert result.reason is None


def test_layer_result_to_guardrail_result_block():
    """allowed=False인 LayerResult는 BLOCK으로 변환된다."""
    lr = LayerResult(
        name="L3",
        allowed=False,
        reason="prompt injection detected",
        severity=Severity.HIGH,
        tags=["prompt_injection"],
    )
    result = layer_result_to_guardrail_result(lr)
    assert result.status == CheckStatus.BLOCK
    assert result.reason == "prompt injection detected"
    assert result.layer == "L3"
