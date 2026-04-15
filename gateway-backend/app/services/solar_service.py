"""Solar API 클라이언트 서비스 (실제 구현)."""

from collections.abc import AsyncGenerator

from openai import AsyncOpenAI

from app.config import Settings


class SolarService:
    """Upstage Solar API를 호출하는 서비스.

    OpenAI 호환 AsyncOpenAI 클라이언트를 사용하여
    Upstage AI의 Solar 모델에 요청을 전송한다.

    Attributes:
        _client: AsyncOpenAI 클라이언트 인스턴스.
        _model: 사용할 LLM 모델 이름.
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

    async def chat(self, messages: list[dict[str, str]]) -> str:
        """Solar API에 비스트리밍 요청을 전송하고 응답 텍스트를 반환한다.

        Args:
            messages: OpenAI 포맷의 메시지 목록.

        Returns:
            LLM 응답 텍스트.
        """
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            stream=False,
        )
        return response.choices[0].message.content

    async def stream_chat(
        self,
        messages: list[dict[str, str]],
    ) -> AsyncGenerator[str, None]:
        """Solar API에 스트리밍 요청을 전송하고 delta 청크를 yield한다.

        Args:
            messages: OpenAI 포맷의 메시지 목록.

        Yields:
            LLM 응답 텍스트 청크.
        """
        stream = await self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            stream=True,
        )
        async for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta is not None:
                yield delta
