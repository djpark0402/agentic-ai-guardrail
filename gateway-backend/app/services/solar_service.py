"""Solar API 클라이언트 서비스 (실제 구현)."""

from typing import Any

from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion

from app.config import Settings

# OpenAI SDK 가 인식하는 표준 파라미터 화이트리스트.
# 이 집합에 없는 파라미터는 Solar 전용 확장으로 간주하고 extra_body 에
# 감싸서 전달한다 (OpenAI SDK 가 unknown kwarg 를 거절하는 것을 방지).
_OPENAI_STANDARD_PARAMS: frozenset[str] = frozenset(
    {
        "temperature",
        "top_p",
        "max_tokens",
        "n",
        "stop",
        "presence_penalty",
        "frequency_penalty",
        "seed",
        "response_format",
        "tools",
        "tool_choice",
        "user",
        "logit_bias",
        "logprobs",
        "top_logprobs",
    }
)


class SolarService:
    """Upstage Solar API를 호출하는 서비스.

    OpenAI 호환 AsyncOpenAI 클라이언트를 사용하여 Upstage AI의 Solar 모델에
    요청을 전송한다. LLM 호출은 **항상 비스트리밍**이며, 사용자 응답의
    스트리밍 재방출은 라우터 계층의 책임이다.

    Attributes:
        _client: AsyncOpenAI 클라이언트 인스턴스.
        _model: 사용할 LLM 모델 이름(기본값, 요청에 model 이 있으면 덮어씀).
    """

    def __init__(self, settings: Settings) -> None:
        """SolarService를 초기화한다.

        Args:
            settings: 애플리케이션 설정 인스턴스.
        """
        self._client = AsyncOpenAI(
            api_key=settings.upstage_api_key.get_secret_value(),
            base_url=settings.llm_base_url,
        )
        self._model = settings.llm_model

    async def chat(
        self,
        messages: list[dict[str, Any]],
        **params: Any,
    ) -> ChatCompletion:
        """Solar API에 비스트리밍 요청을 전송하고 응답 객체를 반환한다.

        Args:
            messages: OpenAI 포맷의 메시지 목록.
            **params: OpenAI Chat Completions 호환 파라미터. None 값은 제거되고,
                `stream` 은 True 로 덮어쓸 수 없으며, `model` 은 요청값이
                env 기본값보다 우선한다. `reasoning_effort` 등 Solar 전용
                파라미터는 `extra_body` 로 감싸서 전달된다.

        Returns:
            Solar API 응답 ChatCompletion 객체 (id/usage/choices 등 메타데이터
            포함).
        """
        # None 값 제거 — OpenAI SDK 가 unknown kwarg 로 거절하는 것을 방지.
        filtered: dict[str, Any] = {
            k: v for k, v in params.items() if v is not None
        }

        # stream 은 항상 False 강제 (가드레일 선검증 원칙).
        filtered.pop("stream", None)

        # 요청 model 이 있으면 우선, 없으면 env 기본값.
        model = filtered.pop("model", self._model)

        # OpenAI 표준 파라미터와 Solar 전용 파라미터 분리.
        extra_body: dict[str, Any] = dict(filtered.pop("extra_body", {}) or {})
        standard: dict[str, Any] = {}
        for key, value in filtered.items():
            if key in _OPENAI_STANDARD_PARAMS:
                standard[key] = value
            else:
                extra_body[key] = value

        call_kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            **standard,
        }
        if extra_body:
            call_kwargs["extra_body"] = extra_body

        return await self._client.chat.completions.create(**call_kwargs)
