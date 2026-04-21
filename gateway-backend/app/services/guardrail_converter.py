"""gateway 모델과 core-secure-layer 모델 간 변환 유틸리티."""

from core_secure_layer.layers.types import GuardrailRequest, LayerResult

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult


def _extract_text(content: object) -> str:
    """Message.content 에서 가드레일 검사용 텍스트를 추출한다.

    Args:
        content: 문자열, content part 목록(list[dict]), 또는 None.

    Returns:
        문자열은 그대로, 멀티모달은 type=="text" part 의 text 만 공백 join,
        None 은 빈 문자열.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                text = part.get("text", "")
                if isinstance(text, str):
                    parts.append(text)
        return " ".join(parts)
    return str(content)


def messages_to_request(messages: list[Message]) -> GuardrailRequest:
    """가장 최근 `role='user'` 메시지 하나만 골라 검사 대상으로 직렬화한다.

    사용자가 이번 턴에 새로 입력한 프롬프트만 가드레일 검사 대상에 포함한다.
    과거 user 턴은 이미 그 시점에 한 번 검사되어 통과된 이력이므로, 히스토리
    누적으로 인해 중복 차단이 발생하지 않도록 이번 턴의 마지막 user 메시지만
    추출한다. system / assistant / tool 메시지 content 는 모두 제외한다.
    user 메시지가 하나도 없으면 빈 문자열을 전달한다.

    Args:
        messages: 요청 바디의 ``messages`` 배열.

    Returns:
        가장 최근 user 메시지의 텍스트 본문을 ``user_input`` 에 담은
        GuardrailRequest. user 메시지가 없으면 빈 문자열.
    """
    for msg in reversed(messages):
        if msg.role == "user":
            return GuardrailRequest(user_input=_extract_text(msg.content))
    return GuardrailRequest(user_input="")


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
