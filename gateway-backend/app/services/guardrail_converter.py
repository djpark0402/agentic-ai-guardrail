"""gateway 모델과 core-secure-layer 모델 간 변환 유틸리티."""

from core_secure_layer.layers.types import GuardrailRequest, LayerResult

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult


def messages_to_request(messages: list[Message]) -> GuardrailRequest:
    """마지막 user 메시지를 추출하여 GuardrailRequest를 생성한다.

    Args:
        messages: 사용자 입력 메시지 목록.

    Returns:
        마지막 user 메시지 텍스트를 담은 GuardrailRequest.
    """
    user_input = ""
    for msg in reversed(messages):
        if msg.role == "user" and msg.content is not None:
            if isinstance(msg.content, str):
                user_input = msg.content
            elif isinstance(msg.content, list):
                user_input = " ".join(
                    part.get("text", "")
                    for part in msg.content
                    if isinstance(part, dict) and part.get("type") == "text"
                )
            break
    return GuardrailRequest(user_input=user_input)


def content_to_request(content: str) -> GuardrailRequest:
    """출력 콘텐츠 문자열을 GuardrailRequest로 변환한다.

    Args:
        content: LLM 응답 텍스트.

    Returns:
        content를 user_input으로 담은 GuardrailRequest.
    """
    return GuardrailRequest(user_input=content)


def layer_result_to_guardrail_result(
    result: LayerResult,
) -> GuardrailResult:
    """Core LayerResult를 gateway GuardrailResult로 변환한다.

    Args:
        result: core-secure-layer 의 레이어 검사 결과.

    Returns:
        severity/confidence/tags 메타데이터가 보존된 GuardrailResult.
    """
    return GuardrailResult(
        status=(CheckStatus.PASS if result.allowed else CheckStatus.BLOCK),
        reason=result.reason,
        layer=result.name,
        severity=result.severity.name,
        confidence=result.confidence,
        tags=list(result.tags),
    )
