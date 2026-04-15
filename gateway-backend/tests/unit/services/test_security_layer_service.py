"""SecurityLayerService 테스트."""

import logging

import pytest

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy
from app.services.security_layer_service import SecurityLayerService


def _policy(**overrides: bool) -> GuardrailPolicy:
    """기본 전체 활성 정책에서 일부 레이어를 덮어쓴다."""
    base = {f"l{i}": True for i in range(6)}
    base.update(overrides)
    return GuardrailPolicy.model_validate(base)


class _SpyService(SecurityLayerService):
    """어느 레이어가 호출됐는지 기록하는 SecurityLayerService."""

    def __init__(self) -> None:
        self.input_calls: list[int] = []
        self.output_calls: list[int] = []

    async def _run_layer_input(
        self, layer_idx: int, messages: list[Message]
    ) -> GuardrailResult:
        self.input_calls.append(layer_idx)
        return GuardrailResult(status=CheckStatus.PASS)

    async def _run_layer_output(
        self, layer_idx: int, content: str
    ) -> GuardrailResult:
        self.output_calls.append(layer_idx)
        return GuardrailResult(status=CheckStatus.PASS)


@pytest.fixture
def service():
    """테스트용 SecurityLayerService 인스턴스."""
    return SecurityLayerService()


async def test_check_input_returns_pass_when_all_enabled(service):
    """모든 레이어 활성 정책으로 check_input() 은 PASS 를 반환한다."""
    messages = [Message(role="user", content="안녕하세요")]
    result = await service.check_input(messages=messages, policy=_policy())
    assert result.status == CheckStatus.PASS


async def test_check_output_returns_pass_when_all_enabled(service):
    """모든 레이어 활성 정책으로 check_output() 은 PASS 를 반환한다."""
    result = await service.check_output(content="응답", policy=_policy())
    assert result.status == CheckStatus.PASS


async def test_check_input_runs_only_enabled_layers():
    """policy 에서 비활성화된 레이어는 입력 검사에서 호출되지 않는다."""
    spy = _SpyService()
    policy = _policy(l1=False, l3=False)
    messages = [Message(role="user", content="hi")]
    await spy.check_input(messages=messages, policy=policy)
    assert spy.input_calls == [0, 2, 4, 5]


async def test_check_output_runs_only_enabled_layers():
    """policy 에서 비활성화된 레이어는 출력 검사에서도 호출되지 않는다."""
    spy = _SpyService()
    policy = _policy(l0=False, l2=False, l4=False)
    await spy.check_output(content="content", policy=policy)
    assert spy.output_calls == [1, 3, 5]


async def test_check_input_all_disabled_returns_pass_without_calls():
    """전부 비활성이면 어떤 훅도 호출되지 않고 PASS 를 반환한다."""
    spy = _SpyService()
    policy = _policy(l0=False, l1=False, l2=False, l3=False, l4=False, l5=False)
    result = await spy.check_input(
        messages=[Message(role="user", content="x")], policy=policy
    )
    assert result.status == CheckStatus.PASS
    assert spy.input_calls == []


async def test_check_input_logs_enabled_layers(service, caplog):
    """check_input()이 활성 레이어 목록을 로그에 기록한다."""
    policy = _policy(l1=False, l4=False)
    with caplog.at_level(logging.INFO):
        await service.check_input(
            messages=[Message(role="user", content="x")], policy=policy
        )
    assert "[0, 2, 3, 5]" in caplog.text
