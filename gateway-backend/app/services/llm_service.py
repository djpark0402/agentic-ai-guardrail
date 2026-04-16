"""범용 LLM 서비스 (LangChain ChatOpenAI 기반).

OpenAI 호환 API를 제공하는 모든 LLM provider(Solar, OpenAI 등)를
동일한 인터페이스로 호출할 수 있는 범용 서비스 클래스.
"""

import json
import time
from types import SimpleNamespace
from typing import Any

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_openai import ChatOpenAI

# LangChain ChatOpenAI 가 bind() 로 직접 받는 표준 파라미터.
_BIND_PARAMS: frozenset[str] = frozenset(
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


def _to_lc_tool_calls(
    tool_calls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """OpenAI 형식 tool_calls 를 LangChain 형식으로 변환한다.

    Args:
        tool_calls: OpenAI 형식 tool_calls 목록.

    Returns:
        LangChain 형식 tool_calls 목록.
    """
    result: list[dict[str, Any]] = []
    for tc in tool_calls:
        func = tc.get("function", {})
        args_raw = func.get("arguments", "{}")
        args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
        result.append(
            {
                "name": func.get("name", ""),
                "args": args,
                "id": tc.get("id", ""),
            }
        )
    return result


def _to_openai_tool_calls(
    tool_calls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """LangChain 형식 tool_calls 를 OpenAI 형식으로 변환한다.

    Args:
        tool_calls: LangChain 형식 tool_calls 목록.

    Returns:
        OpenAI 형식 tool_calls 목록.
    """
    result: list[dict[str, Any]] = []
    for tc in tool_calls:
        args = tc.get("args", {})
        arguments = (
            json.dumps(args, ensure_ascii=False)
            if isinstance(args, dict)
            else str(args)
        )
        result.append(
            {
                "id": tc.get("id", ""),
                "type": "function",
                "function": {
                    "name": tc.get("name", ""),
                    "arguments": arguments,
                },
            }
        )
    return result


def _to_langchain_messages(
    messages: list[dict[str, Any]],
) -> list[BaseMessage]:
    """OpenAI 포맷 메시지 딕셔너리를 LangChain 메시지로 변환한다.

    Args:
        messages: OpenAI 포맷의 메시지 목록.

    Returns:
        LangChain BaseMessage 목록.
    """
    result: list[BaseMessage] = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")

        if role == "system":
            result.append(SystemMessage(content=content))
        elif role == "user":
            result.append(HumanMessage(content=content))
        elif role == "assistant":
            tc = msg.get("tool_calls")
            kwargs: dict[str, Any] = {
                "content": content or "",
            }
            if tc:
                kwargs["tool_calls"] = _to_lc_tool_calls(tc)
            result.append(AIMessage(**kwargs))
        elif role == "tool":
            result.append(
                ToolMessage(
                    content=content or "",
                    tool_call_id=msg.get("tool_call_id", ""),
                )
            )
        else:
            result.append(HumanMessage(content=str(content)))
    return result


class LLMService:
    """OpenAI 호환 LLM API를 호출하는 범용 서비스.

    LangChain ChatOpenAI 를 사용하여 OpenAI 호환 엔드포인트에
    요청을 전송한다. LLM 호출은 **항상 비스트리밍**이며, 사용자 응답의
    스트리밍 재방출은 라우터 계층의 책임이다.

    Attributes:
        _llm: ChatOpenAI 인스턴스.
        _model: 사용할 LLM 모델 이름.
        _provider_name: provider 식별자 (로깅/에러용).
    """

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        provider_name: str = "llm",
    ) -> None:
        """LLMService를 초기화한다.

        Args:
            api_key: LLM provider API 키.
            base_url: LLM provider 엔드포인트 URL.
            model: 기본 모델 이름.
            provider_name: provider 식별자.
        """
        self._model = model
        self._provider_name = provider_name
        self._llm = ChatOpenAI(
            api_key=api_key,
            base_url=base_url,
            model=model,
        )

    @property
    def provider_name(self) -> str:
        """Provider 식별자를 반환한다."""
        return self._provider_name

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
        lc_messages = _to_langchain_messages(messages)

        # None 값 제거, stream 제거.
        filtered: dict[str, Any] = {
            k: v for k, v in params.items() if v is not None
        }
        filtered.pop("stream", None)

        # 요청 model 이 있으면 우선, 없으면 기본값.
        model = filtered.pop("model", None)

        # 표준 파라미터와 provider 전용 파라미터 분리.
        bind_kwargs: dict[str, Any] = {}
        model_kwargs: dict[str, Any] = {}
        for key, value in filtered.items():
            if key in _BIND_PARAMS:
                bind_kwargs[key] = value
            else:
                model_kwargs[key] = value

        if model_kwargs:
            bind_kwargs["model_kwargs"] = model_kwargs

        # model 오버라이드 시 bind 로 전달.
        llm = self._llm
        if model:
            llm = llm.bind(model=model)

        # 파라미터가 있으면 bind.
        if bind_kwargs:
            llm = llm.bind(**bind_kwargs)

        response: AIMessage = await llm.ainvoke(lc_messages)

        return self._to_completion(response, model)

    def _to_completion(
        self,
        response: AIMessage,
        model_override: str | None,
    ) -> object:
        """AIMessage 를 ChatCompletion 호환 객체로 변환한다.

        Args:
            response: LangChain AIMessage 응답.
            model_override: 요청에서 지정된 모델명.

        Returns:
            SimpleNamespace 기반 ChatCompletion 호환 객체.
        """
        metadata = response.response_metadata or {}
        model_name = model_override or metadata.get("model_name") or self._model
        finish_reason = metadata.get("finish_reason", "stop")
        created = int(time.time())

        # tool_calls 변환.
        tool_calls = None
        if response.tool_calls:
            openai_tcs = _to_openai_tool_calls(response.tool_calls)
            tool_calls = [
                SimpleNamespace(
                    **tc,
                    model_dump=lambda t=tc: t,
                )
                for tc in openai_tcs
            ]

        # usage 변환.
        usage = None
        usage_meta = response.usage_metadata
        if usage_meta:
            usage_dict = {
                "prompt_tokens": usage_meta.get("input_tokens", 0),
                "completion_tokens": usage_meta.get("output_tokens", 0),
                "total_tokens": usage_meta.get("total_tokens", 0),
            }
            usage = SimpleNamespace(
                **usage_dict,
                model_dump=lambda: usage_dict,
            )

        return SimpleNamespace(
            id=response.id or f"chatcmpl-{int(time.time())}",
            object="chat.completion",
            created=created,
            model=model_name,
            choices=[
                SimpleNamespace(
                    index=0,
                    message=SimpleNamespace(
                        role="assistant",
                        content=response.content or "",
                        tool_calls=tool_calls,
                    ),
                    finish_reason=finish_reason,
                )
            ],
            usage=usage,
        )
