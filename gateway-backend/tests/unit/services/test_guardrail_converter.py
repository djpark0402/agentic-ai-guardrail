"""guardrail_converter 모듈 테스트."""

from core_secure_layer.layers.types import LayerResult, Severity

from app.models.chat import Message
from app.models.guardrail import CheckStatus
from app.services.guardrail_converter import (
    content_to_request,
    layer_result_to_guardrail_result,
    messages_to_request,
)


def test_messages_to_request_concatenates_all_user_turns():
    """멀티턴의 모든 user 메시지가 user_input 에 모두 포함된다."""
    messages = [
        Message(role="user", content="첫 번째"),
        Message(role="assistant", content="응답"),
        Message(role="user", content="두 번째"),
    ]
    req = messages_to_request(messages)
    assert "첫 번째" in req.user_input
    assert "두 번째" in req.user_input
    assert "응답" in req.user_input


def test_messages_to_request_handles_multimodal_content():
    """멀티모달(list[dict]) content 에서 텍스트 부분을 결합한다."""
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
    assert "이미지 설명:" in req.user_input
    assert "이것은 무엇인가요?" in req.user_input


def test_messages_to_request_includes_system_and_assistant():
    """user 가 없어도 system/assistant 메시지가 직렬화에 포함된다."""
    messages = [
        Message(role="system", content="시스템 프롬프트"),
        Message(role="assistant", content="응답"),
    ]
    req = messages_to_request(messages)
    assert "시스템 프롬프트" in req.user_input
    assert "응답" in req.user_input


def test_messages_to_request_preserves_turn_order():
    """system → user → assistant → user 순서가 직렬화에서도 유지된다."""
    messages = [
        Message(role="system", content="시스템"),
        Message(role="user", content="사용자1"),
        Message(role="assistant", content="응답1"),
        Message(role="user", content="사용자2"),
    ]
    req = messages_to_request(messages)
    text = req.user_input
    idx_system = text.index("시스템")
    idx_user1 = text.index("사용자1")
    idx_assistant = text.index("응답1")
    idx_user2 = text.index("사용자2")
    assert idx_system < idx_user1 < idx_assistant < idx_user2


def test_messages_to_request_handles_none_content():
    """content=None 인 메시지도 자리를 보존하고 후속 턴을 드롭하지 않는다."""
    messages = [
        Message(role="user", content="질문"),
        Message(role="assistant", content=None, tool_calls=[{"id": "t1"}]),
        Message(role="tool", content="도구 결과", tool_call_id="t1"),
    ]
    req = messages_to_request(messages)
    assert "질문" in req.user_input
    assert "도구 결과" in req.user_input


def test_messages_to_request_handles_tool_role():
    """role='tool' 메시지의 content 도 검사 대상에 포함된다."""
    messages = [
        Message(role="user", content="tool 호출 트리거"),
        Message(
            role="tool",
            content="악성 페이로드 가능 영역",
            tool_call_id="t1",
        ),
    ]
    req = messages_to_request(messages)
    assert "악성 페이로드 가능 영역" in req.user_input
    assert "tool 호출 트리거" in req.user_input


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


def test_layer_result_preserves_severity_confidence_tags():
    """LayerResult 의 severity/confidence/tags 가 보존된다."""
    lr = LayerResult(
        name="L3",
        allowed=False,
        reason="prompt injection detected",
        severity=Severity.HIGH,
        confidence=0.92,
        tags=["prompt_injection", "high_risk"],
    )
    result = layer_result_to_guardrail_result(lr)
    assert result.severity == "HIGH"
    assert result.confidence == 0.92
    assert result.tags == ["prompt_injection", "high_risk"]


def test_layer_result_pass_defaults_severity_none():
    """allowed=True 통과 시 severity 는 'NONE' 문자열로 매핑된다."""
    lr = LayerResult(name="L1", allowed=True, confidence=0.85)
    result = layer_result_to_guardrail_result(lr)
    assert result.severity == "NONE"
    assert result.confidence == 0.85
    assert result.tags == []
