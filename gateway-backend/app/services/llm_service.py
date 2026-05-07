"""범용 LLM 서비스 (LiteLLM Python SDK 기반).

OpenAI 호환 API를 제공하는 모든 LLM provider(Solar, OpenAI, Ollama 등)를
동일한 인터페이스로 호출할 수 있는 범용 서비스 클래스.
"""

from contextlib import suppress
from typing import Any

import litellm


class LLMService:
    """OpenAI 호환 LLM API를 호출하는 범용 서비스.

    LiteLLM Python SDK 를 사용하여 OpenAI 호환 엔드포인트에 요청을
    전송한다. LLM 호출은 **항상 비스트리밍**이며, 사용자 응답의
    스트리밍 재방출은 라우터 계층의 책임이다.

    Attributes:
        _api_key: LLM provider API 키.
        _base_url: LLM provider 엔드포인트 URL.
        _model: 사용할 기본 모델 이름.
        _provider_name: provider 식별자 (로깅/에러용).
        _litellm_provider: LiteLLM provider 접두사.
    """

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        provider_name: str = "llm",
        litellm_provider: str = "openai",
    ) -> None:
        """LLMService를 초기화한다.

        Args:
            api_key: LLM provider API 키.
            base_url: LLM provider 엔드포인트 URL.
            model: 기본 모델 이름.
            provider_name: provider 식별자.
            litellm_provider: LiteLLM provider 접두사. 현재 gateway 의
                upstream 은 모두 OpenAI 호환 Chat Completions 엔드포인트라
                기본값 `openai` 를 사용한다.
        """
        self._api_key = api_key
        self._base_url = base_url
        self._model = model
        self._provider_name = provider_name
        self._litellm_provider = litellm_provider.strip()

    @property
    def provider_name(self) -> str:
        """Provider 식별자를 반환한다."""
        return self._provider_name

    def _litellm_model_name(self, model: str) -> str:
        """LiteLLM 에 전달할 provider prefix 포함 모델명을 반환한다.

        Args:
            model: 사용자 요청에서 해석된 실제 모델명.

        Returns:
            LiteLLM provider prefix 를 포함한 모델명.
        """
        if not self._litellm_provider:
            return model
        prefix = f"{self._litellm_provider}/"
        if model.startswith(prefix):
            return model
        return f"{prefix}{model}"

    async def chat(
        self,
        messages: list[dict[str, Any]],
        **params: Any,
    ) -> object:
        """LLM API에 비스트리밍 요청을 전송하고 응답 객체를 반환한다.

        반환 객체는 ChatCompletion 호환 구조로, 라우터가
        ``completion.choices[0].message.content`` 등으로 접근할 수 있다.

        Args:
            messages: OpenAI 포맷의 메시지 목록.
            **params: OpenAI Chat Completions 호환 파라미터.

        Returns:
            ChatCompletion 호환 응답 객체.
        """
        filtered: dict[str, Any] = {
            key: value for key, value in params.items() if value is not None
        }
        # 출력 가드레일 선검사를 위해 upstream 호출은 항상 non-stream 이다.
        filtered.pop("stream", None)

        model = filtered.pop("model", None) or self._model
        response = await litellm.acompletion(
            model=self._litellm_model_name(model),
            messages=messages,
            api_key=self._api_key,
            base_url=self._base_url,
            stream=False,
            **filtered,
        )
        # LiteLLM 내부 라우팅용 `openai/` prefix 가 사용자-facing 응답 모델명에
        # 새지 않도록, 기존 래퍼처럼 resolve 된 모델명을 보존한다.
        with suppress(AttributeError):
            response.model = model
        return response
