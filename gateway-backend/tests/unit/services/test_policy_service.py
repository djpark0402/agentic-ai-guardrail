"""PolicyService 테스트."""

import logging

import pytest
from app.services.policy_service import PolicyService

from app.models.policy import GuardrailPolicy


@pytest.fixture
def service():
    """테스트용 PolicyService 인스턴스."""
    return PolicyService()


async def test_fetch_policy_returns_guardrail_policy(service):
    """fetch_policy()가 GuardrailPolicy 인스턴스를 반환한다."""
    result = await service.fetch_policy(session_id="test-session")
    assert isinstance(result, GuardrailPolicy)


async def test_fetch_policy_all_layers_enabled(service):
    """더미 구현은 6개 레이어가 모두 활성화된 정책을 반환한다."""
    policy = await service.fetch_policy(session_id="test-session")
    assert policy.layer_1_prompt_injection.enabled is True
    assert policy.layer_2_sensitive_data.enabled is True
    assert policy.layer_3_toxicity.enabled is True
    assert policy.layer_4_hallucination.enabled is True
    assert policy.layer_5_pii.enabled is True
    assert policy.layer_6_compliance.enabled is True


async def test_fetch_policy_logs_session_id(service, caplog):
    """fetch_policy()가 session_id를 로그에 기록한다."""
    with caplog.at_level(logging.INFO):
        await service.fetch_policy(session_id="my-session-123")
    assert "my-session-123" in caplog.text
