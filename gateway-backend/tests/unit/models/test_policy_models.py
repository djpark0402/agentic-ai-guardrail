"""Policy 모델 테스트."""

import pytest
from pydantic import ValidationError

from app.models.policy import GuardrailPolicy, L5Setting


def test_guardrail_policy_all_enabled():
    """6개 레이어가 모두 활성화된 정책을 생성할 수 있다."""
    policy = GuardrailPolicy(
        l1=True, l2=True, l3=True, l4=True, l5=True, l6=True
    )
    assert policy.l1 is True
    assert policy.l6 is True
    assert policy.enabled_layers() == [1, 2, 3, 4, 5, 6]


def test_guardrail_policy_mixed():
    """일부 레이어만 활성화된 정책을 생성할 수 있다."""
    policy = GuardrailPolicy(
        l1=True, l2=False, l3=True, l4=False, l5=True, l6=False
    )
    assert policy.l2 is False
    assert policy.l3 is True
    assert policy.enabled_layers() == [1, 3, 5]


def test_guardrail_policy_parses_admin_api_payload():
    """admin-backend 응답(l1Enabled..l6Enabled)을 그대로 파싱한다."""
    payload = {
        "isUse": True,
        "createdAt": "2026-04-15T06:37:51.766295Z",
        "l1Enabled": True,
        "name": "테스트 정책 1",
        "l4Enabled": False,
        "description": "테스트 정책 입니다.",
        "l3Enabled": True,
        "id": 10,
        "l2Enabled": True,
        "l5Enabled": True,
        "l6Enabled": False,
        "updatedAt": "2026-04-15T07:43:48.397550Z",
    }
    policy = GuardrailPolicy.model_validate(payload)
    assert policy.enabled_layers() == [1, 2, 3, 5]


def test_guardrail_policy_parses_l5_setting():
    """ADMIN 응답의 l5Setting 을 L5 정책 설정으로 파싱한다."""
    payload = {
        "l1Enabled": True,
        "l2Enabled": True,
        "l3Enabled": False,
        "l4Enabled": False,
        "l5Enabled": True,
        "l6Enabled": False,
        "l5Setting": {
            "model": "pii_model_v11",
            "threshold": 0.82,
        },
    }
    policy = GuardrailPolicy.model_validate(payload)
    assert policy.l5_setting is not None
    assert policy.l5_setting.model == "pii_model_v11"
    assert policy.l5_setting.threshold == 0.82


def test_guardrail_policy_defaults_l5_setting_to_none_when_missing():
    """l5Setting 이 없으면 기존 기본 L5 동작을 유지한다."""
    policy = GuardrailPolicy.all_enabled()
    assert policy.l5_setting is None


def test_guardrail_policy_from_layer_indices_preserves_l5_setting():
    """정책 조회 생략용 팩토리도 환경변수 기반 L5 설정을 보존한다."""
    l5_setting = L5Setting(model="pii_model_v11", threshold=0.82)

    policy = GuardrailPolicy.from_layer_indices(
        [4, 5],
        outbound=True,
        l5_setting=l5_setting,
    )

    assert policy.enabled_layers() == [4, 5]
    assert policy.l5_setting == l5_setting


@pytest.mark.parametrize("threshold", [-0.01, 1.01])
def test_guardrail_policy_rejects_l5_threshold_out_of_range(
    threshold: float,
):
    """L5 threshold 는 NER score 범위인 0.0~1.0 만 허용한다."""
    payload = {
        "l1Enabled": True,
        "l2Enabled": True,
        "l3Enabled": True,
        "l4Enabled": True,
        "l5Enabled": True,
        "l6Enabled": True,
        "l5Setting": {
            "model": "pii_model_v11",
            "threshold": threshold,
        },
    }
    with pytest.raises(ValidationError):
        GuardrailPolicy.model_validate(payload)


def test_guardrail_policy_parses_outbound_enabled_true():
    """`outboundEnabled=true` 가 `policy.outbound=True` 로 매핑된다."""
    payload = {
        "l1Enabled": True,
        "l2Enabled": True,
        "l3Enabled": True,
        "l4Enabled": True,
        "l5Enabled": True,
        "l6Enabled": True,
        "outboundEnabled": True,
    }
    policy = GuardrailPolicy.model_validate(payload)
    assert policy.outbound is True


def test_guardrail_policy_parses_outbound_enabled_false():
    """`outboundEnabled=false` 가 `policy.outbound=False` 로 매핑된다."""
    payload = {
        "l1Enabled": True,
        "l2Enabled": True,
        "l3Enabled": True,
        "l4Enabled": True,
        "l5Enabled": True,
        "l6Enabled": True,
        "outboundEnabled": False,
    }
    policy = GuardrailPolicy.model_validate(payload)
    assert policy.outbound is False


def test_guardrail_policy_defaults_outbound_to_true_when_missing():
    """ADMIN 응답에 `outboundEnabled` 키가 없으면 기본값 True 를 적용해
    기존 동작(출력 가드레일 수행)을 유지한다 — 하위 호환성 보장."""
    payload = {
        "l1Enabled": True,
        "l2Enabled": True,
        "l3Enabled": True,
        "l4Enabled": True,
        "l5Enabled": True,
        "l6Enabled": True,
    }
    policy = GuardrailPolicy.model_validate(payload)
    assert policy.outbound is True


def test_all_enabled_sets_outbound_true():
    """`all_enabled()` 헬퍼는 outbound 까지 True 로 세팅한다."""
    policy = GuardrailPolicy.all_enabled()
    assert policy.outbound is True


def test_all_disabled_sets_outbound_false():
    """`all_disabled()` 헬퍼는 outbound 까지 False 로 세팅한다."""
    policy = GuardrailPolicy.all_disabled()
    assert policy.outbound is False


def test_from_layer_indices_subset():
    """레이어 인덱스 셋과 outbound 플래그로 정책을 생성할 수 있다."""
    policy = GuardrailPolicy.from_layer_indices({1, 4, 5}, outbound=True)
    assert policy.enabled_layers() == [1, 4, 5]
    assert policy.l1 is True
    assert policy.l2 is False
    assert policy.l3 is False
    assert policy.l4 is True
    assert policy.l5 is True
    assert policy.l6 is False
    assert policy.outbound is True


def test_from_layer_indices_empty_disables_outbound_when_requested():
    """빈 인덱스 셋과 outbound=False 면 모든 레이어가 비활성이다."""
    policy = GuardrailPolicy.from_layer_indices(set(), outbound=False)
    assert policy.enabled_layers() == []
    assert policy.outbound is False


def test_from_layer_indices_accepts_all_six():
    """1~6 전체 인덱스를 받아 all_enabled 와 동등한 정책을 만든다."""
    policy = GuardrailPolicy.from_layer_indices(
        {1, 2, 3, 4, 5, 6}, outbound=True
    )
    assert policy.enabled_layers() == [1, 2, 3, 4, 5, 6]
    assert policy.outbound is True


@pytest.mark.parametrize("invalid_index", [0, 7, -1, 100])
def test_from_layer_indices_rejects_out_of_range(invalid_index: int):
    """1~6 외 인덱스는 ValueError 를 발생시킨다."""
    with pytest.raises(ValueError, match="layer"):
        GuardrailPolicy.from_layer_indices({invalid_index}, outbound=True)


def test_from_layer_indices_accepts_iterable_with_duplicates():
    """중복이 있는 iterable 도 set 처럼 처리되어 정책이 만들어진다."""
    policy = GuardrailPolicy.from_layer_indices([1, 1, 3, 3], outbound=False)
    assert policy.enabled_layers() == [1, 3]
    assert policy.outbound is False


# ── useLlm / judgmentModel (LLM 판정 정책) ─────────────────────────


def test_guardrail_policy_parses_use_llm_and_judgment_model():
    """ADMIN 응답의 useLlm/judgmentModel 을 alias 로 파싱한다."""
    payload = {
        "l1Enabled": True,
        "l2Enabled": True,
        "l3Enabled": True,
        "l4Enabled": True,
        "l5Enabled": True,
        "l6Enabled": True,
        "useLlm": True,
        "judgmentModel": "solar-pro",
    }
    policy = GuardrailPolicy.model_validate(payload)
    assert policy.use_llm is True
    assert policy.judgment_model == "solar-pro"


def test_guardrail_policy_defaults_use_llm_to_false_when_missing():
    """useLlm 키가 없으면 기본값 False 로 기존 동작을 유지한다."""
    payload = {
        "l1Enabled": True,
        "l2Enabled": True,
        "l3Enabled": True,
        "l4Enabled": True,
        "l5Enabled": True,
        "l6Enabled": True,
    }
    policy = GuardrailPolicy.model_validate(payload)
    assert policy.use_llm is False
    assert policy.judgment_model is None


def test_guardrail_policy_judgment_model_alone_keeps_use_llm_false():
    """judgmentModel 만 와도 useLlm 기본값(False)이 적용된다."""
    payload = {
        "l1Enabled": True,
        "l2Enabled": True,
        "l3Enabled": True,
        "l4Enabled": True,
        "l5Enabled": True,
        "l6Enabled": True,
        "judgmentModel": "solar-pro",
    }
    policy = GuardrailPolicy.model_validate(payload)
    assert policy.use_llm is False
    assert policy.judgment_model == "solar-pro"


def test_guardrail_policy_use_llm_true_without_model_keeps_field_none():
    """useLlm=true 인데 judgmentModel 누락이면 judgment_model 은 None.

    SecurityLayerService 단계에서 fail-closed BLOCK 으로 변환할 책임을
    가지므로, 모델 단계에서는 필수 검증을 하지 않고 그대로 통과시킨다.
    """
    payload = {
        "l1Enabled": True,
        "l2Enabled": True,
        "l3Enabled": True,
        "l4Enabled": True,
        "l5Enabled": True,
        "l6Enabled": True,
        "useLlm": True,
    }
    policy = GuardrailPolicy.model_validate(payload)
    assert policy.use_llm is True
    assert policy.judgment_model is None
