"""Policy 모델 테스트."""

from app.models.policy import GuardrailPolicy


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
