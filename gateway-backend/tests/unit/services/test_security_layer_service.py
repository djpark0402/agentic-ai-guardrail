"""SecurityLayerService 테스트."""

import logging

import pytest

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy
from app.services.security_layer_service import SecurityLayerService


def _policy(**overrides: bool) -> GuardrailPolicy:
    """기본 전체 활성 정책에서 일부 레이어를 덮어쓴다."""
    base = {f"l{i}": True for i in range(1, 7)}
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
    policy = _policy(l2=False, l4=False)
    messages = [Message(role="user", content="hi")]
    await spy.check_input(messages=messages, policy=policy)
    assert spy.input_calls == [1, 3, 5, 6]


async def test_check_output_runs_only_enabled_layers():
    """policy 에서 비활성화된 레이어는 출력 검사에서도 호출되지 않는다."""
    spy = _SpyService()
    policy = _policy(l1=False, l3=False, l5=False)
    await spy.check_output(content="content", policy=policy)
    assert spy.output_calls == [2, 4, 6]


async def test_check_input_all_disabled_returns_pass_without_calls():
    """전부 비활성이면 어떤 훅도 호출되지 않고 PASS 를 반환한다."""
    spy = _SpyService()
    policy = _policy(l1=False, l2=False, l3=False, l4=False, l5=False, l6=False)
    result = await spy.check_input(
        messages=[Message(role="user", content="x")], policy=policy
    )
    assert result.status == CheckStatus.PASS
    assert spy.input_calls == []


async def test_check_input_logs_enabled_layers(service, caplog):
    """check_input()이 활성 레이어 목록을 로그에 기록한다."""
    policy = _policy(l2=False, l5=False)
    with caplog.at_level(logging.INFO):
        await service.check_input(
            messages=[Message(role="user", content="x")], policy=policy
        )
    assert "[1, 3, 4, 6]" in caplog.text


# ── core-secure-layer 실연동 테스트 ─────────────────────────


async def test_run_layer_input_not_implemented_returns_pass(
    service,
):
    """미구현 레이어는 NotImplementedError를 PASS로 처리한다."""
    messages = [Message(role="user", content="테스트")]
    result = await service._run_layer_input(1, messages)
    assert result.status == CheckStatus.PASS


async def test_run_layer_output_not_implemented_returns_pass(
    service,
):
    """미구현 출력 레이어는 NotImplementedError를 PASS로 처리한다."""
    result = await service._run_layer_output(1, "응답 텍스트")
    assert result.status == CheckStatus.PASS


async def test_run_layer_input_unmapped_index_returns_pass(
    service,
):
    """매핑되지 않은 인덱스는 PASS를 반환한다."""
    messages = [Message(role="user", content="테스트")]
    result = await service._run_layer_input(99, messages)
    assert result.status == CheckStatus.PASS


async def test_run_layer_input_block_propagates(service, mocker):
    """레이어가 차단하면 BLOCK 결과가 전파된다."""
    from core_secure_layer.layers.types import (
        LayerResult,
        Severity,
    )

    mock_layer = mocker.AsyncMock()
    mock_layer.name = "L1"
    mock_layer.check.return_value = LayerResult(
        name="L1",
        allowed=False,
        reason="injection detected",
        severity=Severity.HIGH,
    )
    mocker.patch(
        "app.services.security_layer_service.get_layer",
        return_value=mock_layer,
    )

    messages = [Message(role="user", content="악성 입력")]
    result = await service._run_layer_input(1, messages)
    assert result.status == CheckStatus.BLOCK
    assert result.reason == "injection detected"
    assert result.layer == "L1"


async def test_run_layer_input_pass_propagates(service, mocker):
    """레이어가 통과하면 PASS 결과가 전파된다."""
    from core_secure_layer.layers.types import LayerResult

    mock_layer = mocker.AsyncMock()
    mock_layer.name = "L1"
    mock_layer.check.return_value = LayerResult(name="L1", allowed=True)
    mocker.patch(
        "app.services.security_layer_service.get_layer",
        return_value=mock_layer,
    )

    messages = [Message(role="user", content="정상 입력")]
    result = await service._run_layer_input(1, messages)
    assert result.status == CheckStatus.PASS
    assert result.layer == "L1"


async def test_run_layer_output_block_propagates(service, mocker):
    """출력 레이어가 차단하면 BLOCK 결과가 전파된다."""
    from core_secure_layer.layers.types import (
        LayerResult,
        Severity,
    )

    mock_layer = mocker.AsyncMock()
    mock_layer.name = "L3"
    mock_layer.check.return_value = LayerResult(
        name="L3",
        allowed=False,
        reason="sensitive data leak",
        severity=Severity.CRITICAL,
    )
    mocker.patch(
        "app.services.security_layer_service.get_layer",
        return_value=mock_layer,
    )

    result = await service._run_layer_output(3, "민감 데이터 포함")
    assert result.status == CheckStatus.BLOCK
    assert result.reason == "sensitive data leak"
    assert result.layer == "L3"


async def test_check_input_all_collects_every_enabled_layer_result(mocker):
    """check_input_all 은 BLOCK 이 있어도 모든 활성 레이어를 실행하고
    결과 리스트를 policy 순서대로 반환한다 (short-circuit 안 함)."""
    from core_secure_layer.layers.types import (
        LayerResult,
        Severity,
    )

    call_log: list[str] = []

    def _make_layer(name: str, allowed: bool, reason: str | None = None):
        mock = mocker.MagicMock()
        mock.name = name

        async def fake_check(request):
            call_log.append(name)
            return LayerResult(
                name=name,
                allowed=allowed,
                reason=reason,
                severity=(Severity.HIGH if not allowed else Severity.NONE),
            )

        mock.check = fake_check
        return mock

    mock_l1 = _make_layer("L1", allowed=False, reason="injection")
    mock_l2 = _make_layer("L2", allowed=True)
    mock_l3 = _make_layer("L3", allowed=False, reason="pii")

    def fake_get_layer(idx):
        return {1: mock_l1, 2: mock_l2, 3: mock_l3}.get(idx)

    mocker.patch(
        "app.services.security_layer_service.get_layer",
        side_effect=fake_get_layer,
    )

    service = SecurityLayerService()
    policy = _policy(l4=False, l5=False, l6=False)
    messages = [Message(role="user", content="데모 입력")]
    results = await service.check_input_all(messages=messages, policy=policy)

    # 모든 활성 레이어가 호출되었고 순서가 policy.enabled_layers() 와 일치.
    assert call_log == ["L1", "L2", "L3"]
    assert [r.layer for r in results] == ["L1", "L2", "L3"]
    assert [r.status for r in results] == [
        CheckStatus.BLOCK,
        CheckStatus.PASS,
        CheckStatus.BLOCK,
    ]
    assert results[0].reason == "injection"
    assert results[2].reason == "pii"


async def test_check_output_all_collects_every_enabled_layer_result(mocker):
    """check_output_all 도 BLOCK 이 있어도 모든 활성 레이어를 끝까지 실행."""
    from core_secure_layer.layers.types import LayerResult, Severity

    call_log: list[str] = []

    def _make_layer(name: str, allowed: bool):
        mock = mocker.MagicMock()
        mock.name = name

        async def fake_check(request):
            call_log.append(name)
            return LayerResult(
                name=name,
                allowed=allowed,
                severity=(Severity.LOW if not allowed else Severity.NONE),
            )

        mock.check = fake_check
        return mock

    mock_l2 = _make_layer("L2", allowed=False)
    mock_l4 = _make_layer("L4", allowed=True)

    def fake_get_layer(idx):
        return {2: mock_l2, 4: mock_l4}.get(idx)

    mocker.patch(
        "app.services.security_layer_service.get_layer",
        side_effect=fake_get_layer,
    )

    service = SecurityLayerService()
    policy = _policy(l1=False, l3=False, l5=False, l6=False)
    results = await service.check_output_all(
        content="demo output", policy=policy
    )

    assert call_log == ["L2", "L4"]
    assert [r.layer for r in results] == ["L2", "L4"]
    assert [r.status for r in results] == [
        CheckStatus.BLOCK,
        CheckStatus.PASS,
    ]


async def test_check_input_all_fills_layer_name_for_unmapped_index():
    """미매핑/PASS 레이어도 결과 리스트에 포함되며 layer 이름이 보존된다."""
    spy = _SpyService()
    policy = _policy(l2=False, l4=False, l5=False, l6=False)
    results = await spy.check_input_all(
        messages=[Message(role="user", content="x")], policy=policy
    )
    assert spy.input_calls == [1, 3]
    assert len(results) == 2
    assert all(r.status == CheckStatus.PASS for r in results)
    assert [r.layer for r in results] == ["L1", "L3"]


async def test_check_input_short_circuits_on_block(mocker):
    """첫 BLOCK 발생 시 후속 레이어를 호출하지 않는다."""
    from core_secure_layer.layers.types import (
        LayerResult,
        Severity,
    )

    call_log = []

    async def fake_check(request):
        call_log.append(mock_l1.name)
        return LayerResult(
            name="L1",
            allowed=False,
            reason="blocked",
            severity=Severity.HIGH,
        )

    mock_l1 = mocker.MagicMock()
    mock_l1.name = "L1"
    mock_l1.check = fake_check

    mock_l2 = mocker.MagicMock()
    mock_l2.name = "L2"
    mock_l2.check = mocker.AsyncMock()

    def fake_get_layer(idx):
        return {1: mock_l1, 2: mock_l2}.get(idx)

    mocker.patch(
        "app.services.security_layer_service.get_layer",
        side_effect=fake_get_layer,
    )

    service = SecurityLayerService()
    policy = _policy(l3=False, l4=False, l5=False, l6=False)
    messages = [Message(role="user", content="test")]
    result = await service.check_input(messages=messages, policy=policy)

    assert result.status == CheckStatus.BLOCK
    assert call_log == ["L1"]
    mock_l2.check.assert_not_called()
