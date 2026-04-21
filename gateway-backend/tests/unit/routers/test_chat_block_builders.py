"""차단 응답 빌더 헬퍼 테스트."""

import pytest

from app.models.chat import Message
from app.routers.chat import (
    _build_block_content,
    _summarize_user_prompts,
)

# ---------------------------------------------------------------------------
# _build_block_content — 사용자에게 노출되는 차단 안내문
# ---------------------------------------------------------------------------


def test_build_block_content_input_with_layer_and_reason():
    """입력 차단은 레이어 라벨·스테이지·사유가 담긴 다라인 안내문을 만든다."""
    assert _build_block_content("input", "L2", "프롬프트 인젝션 감지") == (
        "요청이 가드레일 L2(입력 보안) 단계에서 차단되었습니다.\n"
        "사유: 프롬프트 인젝션 감지\n"
        "다른 표현으로 다시 시도해 주세요."
    )


def test_build_block_content_output_with_layer_and_reason():
    """출력 차단은 '출력 보안' 라벨을 사용한다."""
    assert _build_block_content("output", "L4", "민감 정보 감지") == (
        "요청이 가드레일 L4(출력 보안) 단계에서 차단되었습니다.\n"
        "사유: 민감 정보 감지\n"
        "다른 표현으로 다시 시도해 주세요."
    )


def test_build_block_content_omits_reason_line_when_missing():
    """사유가 없으면 '사유:' 줄을 출력하지 않는다."""
    assert _build_block_content("input", "L1", None) == (
        "요청이 가드레일 L1(입력 보안) 단계에서 차단되었습니다.\n"
        "다른 표현으로 다시 시도해 주세요."
    )


def test_build_block_content_omits_layer_label_when_missing():
    """레이어가 없으면 레이어 라벨을 생략한 문구로 대체한다."""
    assert _build_block_content("output", None, "검출됨") == (
        "요청이 가드레일(출력 보안) 단계에서 차단되었습니다.\n"
        "사유: 검출됨\n"
        "다른 표현으로 다시 시도해 주세요."
    )


@pytest.mark.parametrize("layer", ["L1", "L2", "L3", "L4", "L5", "L6"])
def test_build_block_content_includes_layer_and_reason_substrings(layer):
    """임의의 L1~L6 에 대해 레이어 ID와 사유가 모두 본문에 포함된다."""
    reason = "테스트 사유"
    content = _build_block_content("input", layer, reason)
    assert layer in content
    assert reason in content
    assert "입력 보안" in content


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
