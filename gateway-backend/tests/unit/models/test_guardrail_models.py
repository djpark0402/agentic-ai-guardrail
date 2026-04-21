"""Guardrail 결과 모델 테스트."""

from app.models.guardrail import CheckStatus, GuardrailResult


def test_guardrail_result_pass():
    """PASS 상태의 GuardrailResult를 생성할 수 있다."""
    result = GuardrailResult(status=CheckStatus.PASS)
    assert result.status == CheckStatus.PASS
    assert result.reason is None
    assert result.layer is None


def test_guardrail_result_block_with_reason():
    """BLOCK 상태와 reason을 포함한 GuardrailResult를 생성할 수 있다."""
    result = GuardrailResult(
        status=CheckStatus.BLOCK,
        reason="프롬프트 인젝션 감지",
        layer="layer_1_prompt_injection",
    )
    assert result.status == CheckStatus.BLOCK
    assert result.reason == "프롬프트 인젝션 감지"
    assert result.layer == "layer_1_prompt_injection"


def test_check_status_has_two_distinct_members():
    """CheckStatus는 PASS와 BLOCK 두 멤버를 가지며 서로 다르다."""
    members = list(CheckStatus)
    assert len(members) == 2
    assert CheckStatus.PASS in members
    assert CheckStatus.BLOCK in members
    assert CheckStatus.PASS != CheckStatus.BLOCK
