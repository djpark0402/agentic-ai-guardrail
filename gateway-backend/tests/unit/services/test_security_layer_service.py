"""SecurityLayerService 테스트."""

import logging

import pytest

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy
from app.services.security_layer_service import SecurityLayerService


def _policy(**overrides: object) -> GuardrailPolicy:
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
        self,
        layer_idx: int,
        messages: list[Message],
        policy: GuardrailPolicy,
    ) -> GuardrailResult:
        self.input_calls.append(layer_idx)
        return GuardrailResult(status=CheckStatus.PASS)

    async def _run_layer_output(
        self,
        layer_idx: int,
        content: str,
        policy: GuardrailPolicy,
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
    result = await service.check_output(
        content="안녕하세요! 무엇을 도와드릴까요?", policy=_policy()
    )
    assert result.status == CheckStatus.PASS


async def test_check_input_runs_only_enabled_layers():
    """policy 에서 비활성화된 레이어는 입력 검사에서 호출되지 않는다."""
    spy = _SpyService()
    policy = _policy(l2=False, l4=False)
    messages = [Message(role="user", content="hi")]
    await spy.check_input(messages=messages, policy=policy)
    assert spy.input_calls == [1, 3, 5, 6]


async def test_check_input_records_layer_timings():
    """입력 검사 요약 로그용 레이어별 소요 시간을 기록한다."""
    spy = _SpyService()
    policy = _policy(l2=False, l4=False, l5=False, l6=False)
    timings: dict[str, float] = {}
    messages = [Message(role="user", content="hi")]

    await spy.check_input(messages=messages, policy=policy, timings=timings)

    assert spy.input_calls == [1, 3]
    assert set(timings) == {"input_guardrail_L1", "input_guardrail_L3"}
    assert all(elapsed >= 0 for elapsed in timings.values())


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


async def test_check_input_logs_layer_block_reason(service, mocker, caplog):
    """레이어가 BLOCK 이면 레이어명과 사유를 로그에 남긴다."""
    from core_secure_layer.layers.types import LayerResult, Severity

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

    with caplog.at_level(logging.INFO):
        await service.check_input(
            messages=[Message(role="user", content="악성 입력")],
            policy=_policy(l2=False, l3=False, l4=False, l5=False, l6=False),
        )

    assert "입력 레이어 결과" in caplog.text
    assert "layer=L1(인코딩 검사)" in caplog.text
    assert "status=block" in caplog.text
    assert "reason=injection detected" in caplog.text


async def test_run_layer_input_logs_unmapped_layer_reason(service, caplog):
    """매핑 없는 레이어 PASS 도 이유와 함께 로그에 남긴다."""
    with caplog.at_level(logging.INFO):
        await service._run_layer_input(
            99, [Message(role="user", content="테스트")]
        )

    assert "입력 레이어 결과" in caplog.text
    assert "layer=L99" in caplog.text
    assert "status=pass" in caplog.text
    assert "note=매핑 없음" in caplog.text


async def test_run_layer_output_logs_not_implemented_reason(
    service, mocker, caplog
):
    """미구현 출력 레이어 PASS 도 이유와 함께 로그에 남긴다."""
    mock_layer = mocker.AsyncMock()
    mock_layer.name = "L4"
    mock_layer.check.side_effect = NotImplementedError
    mocker.patch(
        "app.services.security_layer_service.get_layer",
        return_value=mock_layer,
    )

    with caplog.at_level(logging.INFO):
        await service._run_layer_output(4, "응답 텍스트")

    assert "출력 레이어 결과" in caplog.text
    assert "layer=L4(정책 위반 검사)" in caplog.text
    assert "status=pass" in caplog.text
    assert "note=미구현" in caplog.text


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


async def test_run_layer_input_uses_l5_policy_setting(service, mocker):
    """L5 입력 검사는 ADMIN 정책의 model/threshold 로 레이어를 고른다."""
    from core_secure_layer.layers.types import LayerResult

    mock_layer = mocker.AsyncMock()
    mock_layer.name = "L5"
    mock_layer.check.return_value = LayerResult(name="L5", allowed=True)
    get_l5_layer = mocker.patch(
        "app.services.security_layer_service.get_l5_layer",
        return_value=mock_layer,
    )
    get_layer = mocker.patch("app.services.security_layer_service.get_layer")

    policy = _policy(
        l5Setting={
            "model": "pii_model_v11",
            "threshold": 0.82,
        }
    )
    result = await service._run_layer_input(
        5,
        [Message(role="user", content="정상 입력")],
        policy,
    )

    assert result.status == CheckStatus.PASS
    get_l5_layer.assert_called_once_with(
        model_name="pii_model_v11",
        threshold=0.82,
    )
    get_layer.assert_not_called()


async def test_run_layer_output_uses_l5_policy_setting(service, mocker):
    """L5 출력 검사도 ADMIN 정책의 model/threshold 를 적용한다."""
    from core_secure_layer.layers.types import LayerResult

    mock_layer = mocker.AsyncMock()
    mock_layer.name = "L5"
    mock_layer.check.return_value = LayerResult(name="L5", allowed=True)
    get_l5_layer = mocker.patch(
        "app.services.security_layer_service.get_l5_layer",
        return_value=mock_layer,
    )

    policy = _policy(
        l5Setting={
            "model": "pii_model_v11",
            "threshold": 0.82,
        }
    )
    result = await service._run_layer_output(5, "정상 출력", policy)

    assert result.status == CheckStatus.PASS
    get_l5_layer.assert_called_once_with(
        model_name="pii_model_v11",
        threshold=0.82,
    )


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


async def test_check_input_records_timing_only_for_executed_layers(mocker):
    """BLOCK 으로 중단되면 실행된 입력 레이어 시간만 기록한다."""
    from core_secure_layer.layers.types import (
        LayerResult,
        Severity,
    )

    mock_l1 = mocker.MagicMock()
    mock_l1.name = "L1"
    mock_l1.check = mocker.AsyncMock(
        return_value=LayerResult(
            name="L1",
            allowed=False,
            reason="blocked",
            severity=Severity.HIGH,
        )
    )
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
    timings: dict[str, float] = {}
    result = await service.check_input(
        messages=[Message(role="user", content="test")],
        policy=policy,
        timings=timings,
    )

    assert result.status == CheckStatus.BLOCK
    assert set(timings) == {"input_guardrail_L1"}
    mock_l2.check.assert_not_called()


class _FakeLLMLayerGuard:
    """LLM 대체 경로 호출 인자를 기록하는 테스트 더블."""

    def __init__(self, result: GuardrailResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    async def check(
        self,
        *,
        layer_idx: int,
        surface: str,
        content: str,
        model: str | None = None,
    ) -> GuardrailResult:
        self.calls.append(
            {
                "layer_idx": layer_idx,
                "surface": surface,
                "content": content,
                "model": model,
            }
        )
        return self.result


async def test_run_layer_input_uses_llm_replacement_instead_of_core(mocker):
    """LLM 대체 대상 입력 레이어는 core-secure-layer 를 호출하지 않는다."""
    llm_guard = _FakeLLMLayerGuard(
        GuardrailResult(status=CheckStatus.PASS, layer="L5")
    )
    service = SecurityLayerService(
        llm_layer_guard=llm_guard,  # type: ignore[arg-type]
        llm_layer_replacement_layers=frozenset({5}),
    )
    get_l5_layer = mocker.patch(
        "app.services.security_layer_service.get_l5_layer"
    )

    result = await service._run_layer_input(
        5,
        [
            Message(role="user", content="old"),
            Message(role="assistant", content="ok"),
            Message(role="user", content="latest"),
        ],
        _policy(),
    )

    assert result.status == CheckStatus.PASS
    assert llm_guard.calls == [
        {
            "layer_idx": 5,
            "surface": "input",
            "content": "latest",
            "model": None,
        }
    ]
    get_l5_layer.assert_not_called()


async def test_run_layer_output_uses_llm_replacement_instead_of_core(mocker):
    """LLM 대체 대상 출력 레이어는 core-secure-layer 를 호출하지 않는다."""
    llm_guard = _FakeLLMLayerGuard(
        GuardrailResult(
            status=CheckStatus.BLOCK,
            layer="L4",
            reason="정책 위반",
            severity="HIGH",
        )
    )
    service = SecurityLayerService(
        llm_layer_guard=llm_guard,  # type: ignore[arg-type]
        llm_layer_replacement_layers=frozenset({4}),
    )
    get_layer = mocker.patch("app.services.security_layer_service.get_layer")

    result = await service._run_layer_output(4, "unsafe output", _policy())

    assert result.status == CheckStatus.BLOCK
    assert result.reason == "정책 위반"
    assert llm_guard.calls == [
        {
            "layer_idx": 4,
            "surface": "output",
            "content": "unsafe output",
            "model": None,
        }
    ]
    get_layer.assert_not_called()


async def test_llm_replacement_without_guard_fails_closed():
    """대체 레이어 설정만 있고 서비스가 없으면 fail-closed BLOCK."""
    service = SecurityLayerService(
        llm_layer_replacement_layers=frozenset({1}),
    )

    result = await service._run_layer_input(
        1,
        [Message(role="user", content="test")],
        _policy(),
    )

    assert result.status == CheckStatus.BLOCK
    assert result.layer == "L1"
    assert result.severity == "HIGH"
    assert "설정되지 않았습니다" in (result.reason or "")


# ── 정책 기반 useLlm / judgmentModel 분기 ─────────────────────────


async def test_check_input_routes_all_enabled_layers_to_llm_when_use_llm():
    """policy.use_llm=True 면 활성 레이어 전부가 LLM 대체 경로로 흐른다."""
    llm_guard = _FakeLLMLayerGuard(
        GuardrailResult(status=CheckStatus.PASS)
    )
    service = SecurityLayerService(
        llm_layer_guard=llm_guard,  # type: ignore[arg-type]
    )
    policy = _policy(
        l2=False,
        l4=False,
        useLlm=True,
        judgmentModel="solar-pro",
    )

    result = await service.check_input(
        messages=[Message(role="user", content="hi")],
        policy=policy,
    )

    assert result.status == CheckStatus.PASS
    assert [call["layer_idx"] for call in llm_guard.calls] == [1, 3, 5, 6]
    assert all(call["surface"] == "input" for call in llm_guard.calls)
    assert all(call["model"] == "solar-pro" for call in llm_guard.calls)


async def test_check_output_routes_all_enabled_layers_to_llm_when_use_llm():
    """출력 측에서도 use_llm=True 면 활성 레이어가 모두 LLM 으로 위임된다."""
    llm_guard = _FakeLLMLayerGuard(
        GuardrailResult(status=CheckStatus.PASS)
    )
    service = SecurityLayerService(
        llm_layer_guard=llm_guard,  # type: ignore[arg-type]
    )
    policy = _policy(
        l1=False,
        l3=False,
        useLlm=True,
        judgmentModel="custom-model",
    )

    await service.check_output(content="response", policy=policy)

    assert [call["layer_idx"] for call in llm_guard.calls] == [2, 4, 5, 6]
    assert all(call["model"] == "custom-model" for call in llm_guard.calls)
    assert all(call["surface"] == "output" for call in llm_guard.calls)


async def test_use_llm_without_judgment_model_fails_closed_block(mocker):
    """use_llm=True 인데 judgmentModel 누락 시 fail-closed BLOCK."""
    llm_guard = _FakeLLMLayerGuard(
        GuardrailResult(status=CheckStatus.PASS)
    )
    service = SecurityLayerService(
        llm_layer_guard=llm_guard,  # type: ignore[arg-type]
    )
    get_layer = mocker.patch(
        "app.services.security_layer_service.get_layer"
    )
    policy = _policy(useLlm=True)  # judgmentModel 누락 → None

    result = await service.check_input(
        messages=[Message(role="user", content="hi")],
        policy=policy,
    )

    assert result.status == CheckStatus.BLOCK
    assert result.severity == "HIGH"
    assert result.tags == ["llm_layer_misconfigured"]
    assert "judgmentModel" in (result.reason or "")
    # 첫 활성 레이어에서 즉시 BLOCK — LLM 호출도, core-secure-layer 호출도 없다.
    assert llm_guard.calls == []
    get_layer.assert_not_called()


async def test_use_llm_with_empty_judgment_model_fails_closed_block(mocker):
    """judgmentModel='' (빈 문자열) 도 미지정으로 간주해 BLOCK."""
    llm_guard = _FakeLLMLayerGuard(
        GuardrailResult(status=CheckStatus.PASS)
    )
    service = SecurityLayerService(
        llm_layer_guard=llm_guard,  # type: ignore[arg-type]
    )
    mocker.patch("app.services.security_layer_service.get_layer")
    policy = _policy(useLlm=True, judgmentModel="   ")

    result = await service.check_input(
        messages=[Message(role="user", content="hi")],
        policy=policy,
    )

    assert result.status == CheckStatus.BLOCK
    assert result.tags == ["llm_layer_misconfigured"]
    assert llm_guard.calls == []


async def test_use_llm_false_preserves_static_replacement_path(mocker):
    """policy.use_llm=False 면 기존 정적 셋 경로 동작이 유지된다."""
    from core_secure_layer.layers.types import LayerResult

    llm_guard = _FakeLLMLayerGuard(
        GuardrailResult(status=CheckStatus.PASS, layer="L4")
    )
    service = SecurityLayerService(
        llm_layer_guard=llm_guard,  # type: ignore[arg-type]
        llm_layer_replacement_layers=frozenset({4}),
    )
    mock_layer = mocker.AsyncMock()
    mock_layer.name = "L1"
    mock_layer.check.return_value = LayerResult(name="L1", allowed=True)
    mocker.patch(
        "app.services.security_layer_service.get_layer",
        return_value=mock_layer,
    )

    policy = _policy(
        l2=False, l3=False, l5=False, l6=False, useLlm=False
    )  # L1 + L4 활성, 정적 셋이 L4 만 대체
    result = await service.check_input(
        messages=[Message(role="user", content="hi")],
        policy=policy,
    )

    assert result.status == CheckStatus.PASS
    # L4 만 LLM 대체로 호출되고 L1 은 core-secure-layer 경로로 흐른다.
    assert [call["layer_idx"] for call in llm_guard.calls] == [4]
    # 정적 경로에서는 model 오버라이드 없이 기본 settings 모델 사용 (None 전달).
    assert llm_guard.calls[0]["model"] is None


async def test_use_llm_only_runs_enabled_layers(mocker):
    """use_llm=True + 일부 레이어만 활성화면 그 레이어들만 LLM 호출된다."""
    llm_guard = _FakeLLMLayerGuard(
        GuardrailResult(status=CheckStatus.PASS)
    )
    service = SecurityLayerService(
        llm_layer_guard=llm_guard,  # type: ignore[arg-type]
    )
    mocker.patch("app.services.security_layer_service.get_layer")

    policy = _policy(
        l1=True,
        l2=False,
        l3=True,
        l4=False,
        l5=False,
        l6=False,
        useLlm=True,
        judgmentModel="X",
    )
    await service.check_input(
        messages=[Message(role="user", content="hi")],
        policy=policy,
    )

    assert [call["layer_idx"] for call in llm_guard.calls] == [1, 3]


async def test_use_llm_without_guard_service_fails_closed(mocker):
    """use_llm=True 인데 LLMLayerGuardService 미주입이면 misconfigured BLOCK."""
    service = SecurityLayerService()  # llm_layer_guard 미설정
    get_layer = mocker.patch(
        "app.services.security_layer_service.get_layer"
    )
    policy = _policy(useLlm=True, judgmentModel="solar-pro")

    result = await service.check_input(
        messages=[Message(role="user", content="hi")],
        policy=policy,
    )

    assert result.status == CheckStatus.BLOCK
    assert result.severity == "HIGH"
    assert "설정되지 않았습니다" in (result.reason or "")
    get_layer.assert_not_called()
