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
    r"""`messages` 전체 텍스트를 `\n\n` 으로 연결한 단일 문자열로 직렬화한다.

    멀티턴 공격(이전 턴에 심은 페이로드)과 system/tool 메시지 오염을 함께
    검사하기 위해, 메시지 순서를 보존한 채 모든 턴의 텍스트 본문을 한 번에
    레이어에 전달한다.

    Role 라벨(``[user]``, ``<|system|>`` 등)을 prefix 로 넣지 않는 이유:
    L5 의 한국어 PII NER 가 영문 ``user`` / ``system`` 토큰을
    ``login_id`` 엔티티로 오탐하는 false positive 가 관측되었기 때문이다.
    L1~L6 은 어느 것도 role 에 기반해 분기하지 않으므로 role 라벨 손실은
    검사 정확도에 영향이 없다.

    Args:
        messages: 사용자 입력 메시지 목록.

    Returns:
        각 메시지의 텍스트 본문이 ``\n\n`` 으로 연결된 단일 문자열을
        ``user_input`` 에 담은 GuardrailRequest.
    """
    texts = [_extract_text(msg.content) for msg in messages]
    return GuardrailRequest(user_input="\n\n".join(texts))


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
