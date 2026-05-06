"""LLM 레이어 대체 서비스 테스트."""

from __future__ import annotations

from types import SimpleNamespace

from pydantic import SecretStr

from app.config import Settings
from app.models.guardrail import CheckStatus
from app.services.llm_layer_guard import LLMLayerGuardService


def _settings() -> Settings:
    """LLM 레이어 대체 테스트용 Settings 를 반환한다."""
    return Settings(
        _env_file=None,
        llm_model="solar-pro",
        upstage_api_key=SecretStr("upstage-test"),
        llm_layer_replacement_layers="L4",
        llm_layer_base_url="http://localhost:4000/v1",
        llm_layer_api_key=SecretStr("layer-test"),
        llm_layer_model="guard-model",
    )


class _FakeCompletions:
    """OpenAI chat.completions.create 응답을 흉내내는 테스트 더블."""

    def __init__(self, content: str | Exception) -> None:
        self.content = content
        self.calls: list[dict[str, object]] = []

    async def create(self, **kwargs: object) -> object:
        """호출 인자를 기록하고 가짜 completion 객체를 반환한다."""
        self.calls.append(kwargs)
        if isinstance(self.content, Exception):
            raise self.content
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=self.content),
                )
            ]
        )


class _FakeClient:
    """AsyncOpenAI 클라이언트 shape 만 제공하는 테스트 더블."""

    def __init__(self, content: str | Exception) -> None:
        self.completions = _FakeCompletions(content)
        self.chat = SimpleNamespace(completions=self.completions)


async def test_llm_layer_guard_allowed_json_returns_pass() -> None:
    """LLM 이 allowed=true JSON 을 반환하면 PASS 로 변환된다."""
    client = _FakeClient(
        '{"allowed":true,"reason":null,"severity":"NONE",'
        '"confidence":0.88,"tags":["clean"]}'
    )
    service = LLMLayerGuardService(_settings(), client=client)  # type: ignore[arg-type]

    result = await service.check(
        layer_idx=4,
        surface="input",
        content="정상 요청",
    )

    assert result.status == CheckStatus.PASS
    assert result.layer == "L4"
    assert result.severity == "NONE"
    assert result.confidence == 0.88
    assert result.tags == ["clean"]
    call = client.completions.calls[0]
    assert call["model"] == "guard-model"
    assert call["temperature"] == 0
    assert call["response_format"] == {"type": "json_object"}


async def test_llm_layer_guard_block_json_returns_block() -> None:
    """LLM 이 allowed=false JSON 을 반환하면 BLOCK 으로 변환된다."""
    client = _FakeClient(
        '{"allowed":false,"reason":"프롬프트 인젝션 시도",'
        '"severity":"HIGH","confidence":0.97,"tags":["prompt_injection"]}'
    )
    service = LLMLayerGuardService(_settings(), client=client)  # type: ignore[arg-type]

    result = await service.check(
        layer_idx=4,
        surface="output",
        content="unsafe",
    )

    assert result.status == CheckStatus.BLOCK
    assert result.reason == "프롬프트 인젝션 시도"
    assert result.severity == "HIGH"
    assert result.tags == ["prompt_injection"]


async def test_llm_layer_guard_invalid_json_fails_closed() -> None:
    """JSON 파싱 실패는 fail-closed BLOCK 으로 변환된다."""
    service = LLMLayerGuardService(
        _settings(),
        client=_FakeClient("not json"),  # type: ignore[arg-type]
    )

    result = await service.check(
        layer_idx=6,
        surface="input",
        content="anything",
    )

    assert result.status == CheckStatus.BLOCK
    assert result.layer == "L6"
    assert result.severity == "HIGH"
    assert "LLM 레이어 판정 실패" in (result.reason or "")
    assert result.tags == ["llm_layer_failure"]


async def test_llm_layer_guard_call_error_fails_closed() -> None:
    """LLM 호출 예외도 fail-closed BLOCK 으로 변환된다."""
    service = LLMLayerGuardService(
        _settings(),
        client=_FakeClient(RuntimeError("boom")),  # type: ignore[arg-type]
    )

    result = await service.check(
        layer_idx=2,
        surface="input",
        content="anything",
    )

    assert result.status == CheckStatus.BLOCK
    assert result.layer == "L2"
    assert result.severity == "HIGH"
    assert "boom" in (result.reason or "")


async def test_llm_layer_guard_uses_model_override_when_provided() -> None:
    """`model` 인자가 주어지면 OpenAI payload 의 model 을 그 값으로 호출한다."""
    client = _FakeClient(
        '{"allowed":true,"reason":null,"severity":"NONE",'
        '"confidence":0.5,"tags":[]}'
    )
    service = LLMLayerGuardService(_settings(), client=client)  # type: ignore[arg-type]

    await service.check(
        layer_idx=4,
        surface="input",
        content="hi",
        model="custom-judgment-model",
    )

    call = client.completions.calls[0]
    assert call["model"] == "custom-judgment-model"


async def test_llm_layer_guard_falls_back_to_settings_model_when_none() -> (
    None
):
    """`model=None` 이면 기존처럼 settings.llm_layer_model 을 사용한다."""
    client = _FakeClient(
        '{"allowed":true,"reason":null,"severity":"NONE",'
        '"confidence":0.5,"tags":[]}'
    )
    service = LLMLayerGuardService(_settings(), client=client)  # type: ignore[arg-type]

    await service.check(
        layer_idx=4,
        surface="input",
        content="hi",
        model=None,
    )

    call = client.completions.calls[0]
    assert call["model"] == "guard-model"


async def test_llm_layer_guard_treats_empty_model_override_as_fallback() -> (
    None
):
    """빈 문자열 `model=""` 도 None 처럼 처리해 settings 값으로 폴백한다."""
    client = _FakeClient(
        '{"allowed":true,"reason":null,"severity":"NONE",'
        '"confidence":0.5,"tags":[]}'
    )
    service = LLMLayerGuardService(_settings(), client=client)  # type: ignore[arg-type]

    await service.check(
        layer_idx=4,
        surface="input",
        content="hi",
        model="",
    )

    call = client.completions.calls[0]
    assert call["model"] == "guard-model"
