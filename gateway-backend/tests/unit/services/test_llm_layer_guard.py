"""LLM 레이어 대체 서비스 테스트."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

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
        llm_layer_base_url="http://localhost:4000/v1",
        llm_layer_api_key=SecretStr("layer-test"),
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
        model="guard-model",
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
        model="guard-model",
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
        model="guard-model",
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
        model="guard-model",
    )

    assert result.status == CheckStatus.BLOCK
    assert result.layer == "L2"
    assert result.severity == "HIGH"
    assert "boom" in (result.reason or "")


async def test_llm_layer_guard_uses_model_argument_for_payload() -> None:
    """`model` 인자가 OpenAI payload 의 model 로 그대로 전달된다."""
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


async def test_llm_layer_guard_missing_model_fails_closed() -> None:
    """`model=None` (정책의 judgmentModel 누락) 이면 fail-closed BLOCK."""
    client = _FakeClient(
        '{"allowed":true,"reason":null,"severity":"NONE",'
        '"confidence":0.5,"tags":[]}'
    )
    service = LLMLayerGuardService(_settings(), client=client)  # type: ignore[arg-type]

    result = await service.check(
        layer_idx=4,
        surface="input",
        content="hi",
        model=None,
    )

    assert result.status == CheckStatus.BLOCK
    assert result.layer == "L4"
    assert result.severity == "HIGH"
    assert result.tags == ["llm_layer_misconfigured"]
    assert "judgmentModel" in (result.reason or "")
    # LLM 호출이 발생하지 않아야 한다.
    assert client.completions.calls == []


async def test_llm_layer_guard_blank_model_fails_closed() -> None:
    """공백·빈 문자열 model 도 judgmentModel 미지정으로 BLOCK 된다."""
    client = _FakeClient(
        '{"allowed":true,"reason":null,"severity":"NONE",'
        '"confidence":0.5,"tags":[]}'
    )
    service = LLMLayerGuardService(_settings(), client=client)  # type: ignore[arg-type]

    result = await service.check(
        layer_idx=4,
        surface="input",
        content="hi",
        model="   ",
    )

    assert result.status == CheckStatus.BLOCK
    assert result.tags == ["llm_layer_misconfigured"]
    assert client.completions.calls == []


def test_llm_layer_guard_passes_x_api_key_default_header() -> None:
    """AsyncOpenAI 클라이언트 생성 시 x-api-key 기본 헤더를 함께 보낸다.

    LiteLLM 등 일부 OpenAI 호환 프록시는 표준 `Authorization: Bearer`
    대신 `x-api-key` 헤더로 인증한다. 양쪽 모두를 송신해 호환성을 확보.
    """
    with patch("app.services.llm_layer_guard.AsyncOpenAI") as mock_openai:
        LLMLayerGuardService(_settings())

    assert mock_openai.called
    kwargs = mock_openai.call_args.kwargs
    assert kwargs.get("default_headers") == {"x-api-key": "layer-test"}
    assert kwargs.get("api_key") == "layer-test"
    assert kwargs.get("base_url") == "http://localhost:4000/v1"
