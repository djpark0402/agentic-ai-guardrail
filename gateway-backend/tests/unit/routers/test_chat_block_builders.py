"""차단 응답 빌더 헬퍼 테스트."""

from app.models.guardrail import CheckStatus, GuardrailResult
from app.routers.chat import _block_message, _build_block_error


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
