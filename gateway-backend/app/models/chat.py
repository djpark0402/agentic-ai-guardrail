"""Chat 요청/응답 Pydantic 모델."""

from pydantic import BaseModel, ConfigDict


class Message(BaseModel):
    """채팅 메시지 모델.

    Attributes:
        role: 메시지 역할 (system, user, assistant).
        content: 메시지 내용.
    """

    role: str
    content: str


class ChatRequest(BaseModel):
    """Solar/OpenAI 호환 채팅 완성 요청 모델.

    Attributes:
        model: 사용할 LLM 모델 이름.
        messages: 대화 메시지 목록.
        stream: 스트리밍 응답 여부.
    """

    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[Message]
    stream: bool = False


class ChatResponseMessage(BaseModel):
    """응답 메시지 모델.

    Attributes:
        role: 메시지 역할.
        content: 메시지 내용.
    """

    role: str
    content: str


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
    """

    id: str
    object: str
    created: int
    model: str
    choices: list[ChatResponseChoice]
