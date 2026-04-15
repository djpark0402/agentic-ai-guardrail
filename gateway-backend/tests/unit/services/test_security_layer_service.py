"""SecurityLayerService 테스트."""

import logging

import pytest
from app.services.security_layer_service import SecurityLayerService

from app.models.guardrail import CheckStatus
from app.models.policy import GuardrailPolicy, LayerConfig


@pytest.fixture
def service():
    """테스트용 SecurityLayerService 인스턴스."""
    return SecurityLayerService()


@pytest.fixture
def policy():
    """테스트용 GuardrailPolicy (모든 레이어 활성화)."""
    return GuardrailPolicy(
        layer_1_prompt_injection=LayerConfig(enabled=True),
        layer_2_sensitive_data=LayerConfig(enabled=True),
        layer_3_toxicity=LayerConfig(enabled=True),
        layer_4_hallucination=LayerConfig(enabled=True),
        layer_5_pii=LayerConfig(enabled=True),
        layer_6_compliance=LayerConfig(enabled=True),
    )


async def test_check_input_returns_pass(service, policy):
    """check_input()은 항상 PASS를 반환한다 (더미 구현)."""
    from app.models.chat import Message

    messages = [Message(role="user", content="안녕하세요")]
    result = await service.check_input(messages=messages, policy=policy)
    assert result.status == CheckStatus.PASS


async def test_check_output_returns_pass(service, policy):
    """check_output()은 항상 PASS를 반환한다 (더미 구현)."""
    result = await service.check_output(content="응답 내용", policy=policy)
    assert result.status == CheckStatus.PASS


async def test_check_input_logs_message_count(service, policy, caplog):
    """check_input()이 메시지 수를 로그에 기록한다."""
    from app.models.chat import Message

    messages = [
        Message(role="user", content="첫 번째"),
        Message(role="assistant", content="두 번째"),
    ]
    with caplog.at_level(logging.INFO):
        await service.check_input(messages=messages, policy=policy)
    assert "2" in caplog.text


async def test_check_output_logs_content_length(service, policy, caplog):
    """check_output()이 콘텐츠 길이를 로그에 기록한다."""
    content = "응답 내용입니다"
    with caplog.at_level(logging.INFO):
        await service.check_output(content=content, policy=policy)
    assert str(len(content)) in caplog.text
