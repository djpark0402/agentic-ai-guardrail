"""guardrail_converter 모듈 테스트."""

from core_secure_layer.layers.types import LayerResult, Severity

from app.models.chat import Message
from app.models.guardrail import CheckStatus
from app.services.guardrail_converter import (
    content_to_request,
    layer_result_to_guardrail_result,
    messages_to_request,
)


def test_messages_to_request_returns_last_user_message():
    """멀티턴 대화에서도 가장 최근 user 메시지 하나만 user_input 으로 전달된다.

    과거 user 턴은 이미 그 시점에 한 번 검사된 이력이므로, 히스토리 누적 때문에
    다시 검사되어 중복 차단이 발생하지 않도록 한다.
    """
    messages = [
        Message(role="user", content="첫 번째"),
        Message(role="assistant", content="응답"),
        Message(role="user", content="두 번째"),
    ]
    req = messages_to_request(messages)
    assert req.user_input == "두 번째"
    assert "첫 번째" not in req.user_input
    assert "응답" not in req.user_input


def test_messages_to_request_handles_multimodal_content():
    """user 메시지의 멀티모달 content 에서 텍스트 part 만 결합한다."""
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


def test_messages_to_request_excludes_system_and_assistant():
    """system/assistant 메시지 content 는 검사 대상에서 제외된다."""
    messages = [
        Message(role="system", content="시스템 프롬프트"),
        Message(role="assistant", content="응답"),
    ]
    req = messages_to_request(messages)
    assert "시스템 프롬프트" not in req.user_input
    assert "응답" not in req.user_input
    assert req.user_input == ""


def test_messages_to_request_ignores_previous_blocked_user_turn():
    """과거 user 턴에 차단 키워드가 남아 있어도, 가장 최근 user 메시지만 검사
    대상으로 전달되어 '한 번 차단되면 이후 요청이 계속 차단' 되는 회귀가
    재발하지 않도록 잠근다.
    """
    messages = [
        Message(role="system", content="시스템"),
        Message(role="user", content="주민번호 123456-1234567"),
        Message(role="assistant", content="차단 안내"),
        Message(role="user", content="안녕하세요"),
    ]
    req = messages_to_request(messages)
    assert req.user_input == "안녕하세요"
    assert "주민번호" not in req.user_input
    assert "시스템" not in req.user_input
    assert "차단 안내" not in req.user_input


def test_messages_to_request_drops_non_user_content():
    """content=None 인 assistant 와 tool 결과는 검사 문자열에서 빠진다."""
    messages = [
        Message(role="user", content="질문"),
        Message(role="assistant", content=None, tool_calls=[{"id": "t1"}]),
        Message(role="tool", content="도구 결과", tool_call_id="t1"),
    ]
    req = messages_to_request(messages)
    assert "질문" in req.user_input
    assert "도구 결과" not in req.user_input


def test_messages_to_request_excludes_tool_role():
    """role='tool' 메시지의 content 는 검사 대상에서 제외된다."""
    messages = [
        Message(role="user", content="tool 호출 트리거"),
        Message(
            role="tool",
            content="악성 페이로드 가능 영역",
            tool_call_id="t1",
        ),
    ]
    req = messages_to_request(messages)
    assert "tool 호출 트리거" in req.user_input
    assert "악성 페이로드 가능 영역" not in req.user_input


def test_messages_to_request_returns_empty_when_no_user_messages():
    """user 메시지가 하나도 없으면 user_input 은 빈 문자열이다."""
    messages = [
        Message(role="system", content="시스템 전용"),
        Message(role="assistant", content="응답만"),
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
