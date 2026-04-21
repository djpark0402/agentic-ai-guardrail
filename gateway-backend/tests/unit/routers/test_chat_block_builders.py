"""차단 응답 빌더 헬퍼 테스트."""

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult
from app.routers.chat import (
    _block_message,
    _build_block_error,
    _summarize_user_prompts,
)


def test_block_message_input_with_reason():
    """입력 스테이지는 한글 프리픽스 + 사유를 이어붙인다."""
    assert (
        _block_message("input", "프롬프트 인젝션 감지")
        == "입력 보안 검사 실패: 프롬프트 인젝션 감지"
    )


def test_block_message_output_with_reason():
    """출력 스테이지도 동일한 포맷을 따른다."""
    assert (
        _block_message("output", "유해 콘텐츠 감지")
        == "출력 보안 검사 실패: 유해 콘텐츠 감지"
    )


def test_block_message_without_reason():
    """reason 이 None 이면 프리픽스만 반환한다."""
    assert _block_message("input", None) == "입력 보안 검사 실패"
    assert _block_message("output", None) == "출력 보안 검사 실패"


def test_build_block_error_full_metadata():
    """GuardrailResult 의 모든 메타데이터가 error 객체에 실린다."""
    result = GuardrailResult(
        status=CheckStatus.BLOCK,
        reason="prompt injection detected",
        layer="L3",
        severity="HIGH",
        confidence=0.92,
        tags=["prompt_injection"],
    )
    error = _build_block_error(result, "input")
    assert error["type"] == "guardrail_block"
    assert error["stage"] == "input"
    assert error["message"] == "입력 보안 검사 실패: prompt injection detected"
    assert error["layer"] == "L3"
    assert error["reason"] == "prompt injection detected"
    assert error["severity"] == "HIGH"
    assert error["confidence"] == 0.92
    assert error["tags"] == ["prompt_injection"]


def test_build_block_error_nullable_metadata():
    """메타데이터가 비어 있어도 고정 필드는 유지된다."""
    result = GuardrailResult(status=CheckStatus.BLOCK, reason=None)
    error = _build_block_error(result, "output")
    assert error["type"] == "guardrail_block"
    assert error["stage"] == "output"
    assert error["message"] == "출력 보안 검사 실패"
    assert error["layer"] is None
    assert error["severity"] is None
    assert error["confidence"] is None
    assert error["tags"] == []


# ---------------------------------------------------------------------------
# _summarize_user_prompts — 요청 로그에 실리는 사용자 입력 요약
# ---------------------------------------------------------------------------


def test_summarize_user_prompts_single_user_message():
    """단일 user 메시지는 `[user] 내용` 형태로 요약된다."""
    messages = [Message(role="user", content="안녕하세요")]
    assert _summarize_user_prompts(messages) == "[user] 안녕하세요"


def test_summarize_user_prompts_multiple_roles():
    """여러 role 이 섞여 있으면 role 접두사와 함께 ` | ` 로 이어 붙인다."""
    messages = [
        Message(role="system", content="친절하게 답해"),
        Message(role="user", content="안녕"),
    ]
    assert (
        _summarize_user_prompts(messages)
        == "[system] 친절하게 답해 | [user] 안녕"
    )


def test_summarize_user_prompts_replaces_newlines_with_space():
    """줄바꿈은 공백으로 치환해 한 줄로 만든다."""
    messages = [Message(role="user", content="안녕\n잘 지내?")]
    assert _summarize_user_prompts(messages) == "[user] 안녕 잘 지내?"


def test_summarize_user_prompts_truncates_long_content():
    """개별 메시지가 길면 말줄임표(…)로 자른다."""
    long_text = "가" * 500
    messages = [Message(role="user", content=long_text)]
    summary = _summarize_user_prompts(messages)
    assert summary.endswith("…")
    # 접두사 `[user] ` + 200자 + `…` 가 한계 구조다.
    assert summary.count("가") == 200


def test_summarize_user_prompts_handles_multimodal_parts():
    """multimodal content(list[dict]) 는 text 필드만 뽑아 연결한다."""
    messages = [
        Message(
            role="user",
            content=[
                {"type": "text", "text": "이 사진은"},
                {"type": "image_url", "image_url": {"url": "..."}},
                {"type": "text", "text": "뭔가요?"},
            ],
        )
    ]
    assert _summarize_user_prompts(messages) == "[user] 이 사진은 뭔가요?"


def test_summarize_user_prompts_handles_none_content():
    """assistant tool_call 처럼 content=None 인 경우 빈 텍스트로 취급한다."""
    messages = [Message(role="assistant", content=None)]
    assert _summarize_user_prompts(messages) == "[assistant] "
