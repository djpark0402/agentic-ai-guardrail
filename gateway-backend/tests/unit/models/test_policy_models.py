"""Policy 모델 테스트."""

from app.models.policy import GuardrailPolicy, LayerConfig


def test_layer_config_enabled():
    """LayerConfig를 enabled=True로 생성할 수 있다."""
    layer = LayerConfig(enabled=True)
    assert layer.enabled is True


def test_layer_config_disabled():
    """LayerConfig를 enabled=False로 생성할 수 있다."""
    layer = LayerConfig(enabled=False)
    assert layer.enabled is False


def test_guardrail_policy_all_enabled():
    """6개 레이어가 모두 enabled=True인 정책을 생성할 수 있다."""
    policy = GuardrailPolicy(
        layer_1_prompt_injection=LayerConfig(enabled=True),
        layer_2_sensitive_data=LayerConfig(enabled=True),
        layer_3_toxicity=LayerConfig(enabled=True),
        layer_4_hallucination=LayerConfig(enabled=True),
        layer_5_pii=LayerConfig(enabled=True),
        layer_6_compliance=LayerConfig(enabled=True),
    )
    assert policy.layer_1_prompt_injection.enabled is True
    assert policy.layer_6_compliance.enabled is True


def test_guardrail_policy_mixed():
    """일부 레이어만 활성화된 정책을 생성할 수 있다."""
    policy = GuardrailPolicy(
        layer_1_prompt_injection=LayerConfig(enabled=True),
        layer_2_sensitive_data=LayerConfig(enabled=False),
        layer_3_toxicity=LayerConfig(enabled=True),
        layer_4_hallucination=LayerConfig(enabled=False),
        layer_5_pii=LayerConfig(enabled=True),
        layer_6_compliance=LayerConfig(enabled=False),
    )
    assert policy.layer_2_sensitive_data.enabled is False
    assert policy.layer_3_toxicity.enabled is True
