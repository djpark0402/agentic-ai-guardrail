"""Chat 요청/응답 Pydantic 모델."""

from typing import Any

from pydantic import BaseModel, ConfigDict


class Message(BaseModel):
    """채팅 메시지 모델.

    OpenAI 호환 확장: multimodal content(list[dict]) 및 tool/function 메시지를
    허용하기 위해 content 는 느슨한 유니온으로 둔다. assistant 가 tool_call
    만 반환하는 경우 content 는 None 이 될 수 있다.

    Attributes:
        role: 메시지 역할 (system, user, assistant, tool).
        content: 메시지 내용. 문자열, content part 목록, 또는 None.
        name: function/tool 메시지의 이름.
        tool_call_id: tool 응답 메시지가 참조하는 tool_call ID.
        tool_calls: assistant 메시지가 요청한 tool call 목록.
    """

    model_config = ConfigDict(extra="allow")

    role: str
    content: str | list[dict[str, Any]] | None = None
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


class ChatRequest(BaseModel):
    """Solar/OpenAI 호환 채팅 완성 요청 모델.

    OpenAI Chat Completions 및 Upstage Solar 에서 사용하는 표준 파라미터를
    선언적으로 수용하여 하류 Solar 호출에 그대로 pass-through 할 수 있게
    한다. `extra="allow"` 는 유지하여 알려지지 않은 신규 파라미터도 거절하지
    않는다.

    Attributes:
        model: 사용할 LLM 모델 이름.
        messages: 대화 메시지 목록.
        stream: 사용자 응답의 SSE 스트리밍 여부. (LLM 호출은 항상 non-stream)
        temperature: 샘플링 온도.
        top_p: nucleus 샘플링 확률.
        max_tokens: 최대 생성 토큰 수.
        n: 생성할 선택지 개수.
        stop: 중지 시퀀스.
        presence_penalty: presence penalty 계수.
        frequency_penalty: frequency penalty 계수.
        seed: 재현성 시드.
        response_format: JSON mode 등 응답 포맷 지정.
        tools: 함수/툴 정의 목록.
        tool_choice: tool 선택 전략.
        reasoning_effort: Solar Pro 3 추론 강도 옵션.
        user: 최종 사용자 식별자.
    """

    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[Message]
    stream: bool = False

    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    n: int | None = None
    stop: str | list[str] | None = None
    presence_penalty: float | None = None
    frequency_penalty: float | None = None
    seed: int | None = None
    response_format: dict[str, Any] | None = None
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict[str, Any] | None = None
    reasoning_effort: str | None = None
    user: str | None = None


class ChatResponseMessage(BaseModel):
    """응답 메시지 모델.

    Attributes:
        role: 메시지 역할.
        content: 메시지 내용. tool_call 응답은 None 일 수 있다.
        tool_calls: assistant 가 요청한 tool call 목록.
    """

    role: str
    content: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


class ChatResponseChoice(BaseModel):
    """응답 선택지 모델.

    Attributes:
        index: 선택지 인덱스.
        message: 응답 메시지.
        finish_reason: 완료 이유.
    """

    index: int
    message: ChatResponseMessage
    finish_reason: str | None = None


class ChatResponse(BaseModel):
    """Solar/OpenAI 호환 채팅 완성 응답 모델.

    Attributes:
        id: 응답 고유 ID.
        object: 객체 타입.
        created: 생성 시각 (Unix timestamp).
        model: 사용된 모델 이름.
        choices: 응답 선택지 목록.
        usage: 토큰 사용량 통계 (Solar 가 제공할 경우).
        error: 가드레일 차단 시 첨부되는 비표준 error 블록. 정상 응답에서는
            None 으로 두고, 직렬화 시 존재할 때만 노출된다.
        guardrail_reports: 관찰 모드(`CONTINUE_ON_LAYER_FAILURE=true`)에서
            레이어별 판정 내역을 담는 비표준 메타데이터 블록. 일반 모드에서는
            None.
    """

    id: str
    object: str
    created: int
    model: str
    choices: list[ChatResponseChoice]
    usage: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    guardrail_reports: dict[str, Any] | None = None
