"""Chat 완성 라우터 — 핵심 가드레일 파이프라인."""

import time
import uuid
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from app.dependencies import (
    get_policy_service,
    get_security_service,
    get_solar_service,
)
from app.models.chat import (
    ChatRequest,
    ChatResponse,
    ChatResponseChoice,
    ChatResponseMessage,
)
from app.models.guardrail import CheckStatus
from app.services.policy_service import PolicyService
from app.services.security_layer_service import SecurityLayerService
from app.services.solar_service import SolarService

router = APIRouter()

# 사용자 측 스트리밍 시 응답을 쪼개는 청크 길이(문자 단위).
_SSE_CHUNK_SIZE = 20


def _chunk_content(content: str, size: int = _SSE_CHUNK_SIZE) -> list[str]:
    """전체 응답 문자열을 고정 길이 청크 목록으로 분할한다.

    Args:
        content: 분할할 전체 문자열.
        size: 청크 하나의 최대 문자 길이.

    Returns:
        순서대로 연결하면 원본 문자열이 복원되는 청크 목록.
    """
    if not content:
        return [""]
    return [content[i : i + size] for i in range(0, len(content), size)]


async def _stream_content(content: str) -> AsyncGenerator[str, None]:
    """검증이 끝난 전체 content를 SSE 포맷으로 재방출한다.

    Args:
        content: 사용자에게 전송할 전체 응답 문자열.

    Yields:
        SSE `data:` 프레임 문자열.
    """
    for chunk in _chunk_content(content):
        yield f"data: {chunk}\n\n"
    yield "data: [DONE]\n\n"


async def _stream_error(reason: str | None) -> AsyncGenerator[str, None]:
    """출력 가드레일 BLOCK 시 에러 프레임 하나만 전송한다.

    원본 LLM 응답은 절대 유출하지 않는다.

    Args:
        reason: BLOCK 사유 문자열.

    Yields:
        SSE 에러 프레임과 종료 마커.
    """
    yield f"data: [ERROR] 출력 보안 검사 실패: {reason}\n\n"
    yield "data: [DONE]\n\n"


@router.post("/chat/completions", response_model=None)
async def chat_completions(
    request: ChatRequest,
    policy_service: Annotated[PolicyService, Depends(get_policy_service)],
    security_service: Annotated[
        SecurityLayerService, Depends(get_security_service)
    ],
    solar_service: Annotated[SolarService, Depends(get_solar_service)],
) -> ChatResponse | StreamingResponse:
    """Solar API 포맷의 채팅 완성 요청을 처리한다.

    가드레일 파이프라인:
    1. admin-backend에서 보안 정책 조회
    2. security-layer로 입력 프롬프트 검사
    3. Solar API 비스트리밍 호출 (항상 non-stream)
    4. security-layer로 출력 결과 검사 (사용자 전송 이전에 선행)
    5. `stream=False`면 JSON, `stream=True`면 SSE로 재방출

    Args:
        request: OpenAI/Solar 호환 채팅 완성 요청.
        policy_service: 보안 정책 조회 서비스.
        security_service: 보안 레이어 검사 서비스.
        solar_service: Solar API 클라이언트 서비스.

    Returns:
        비스트리밍: ChatResponse JSON 응답.
        스트리밍: SSE StreamingResponse.

    Raises:
        HTTPException: 입력 검사 실패 시 400, 비스트리밍 출력 검사 실패 시 400.
    """
    session_id = str(uuid.uuid4())

    # 1단계: admin-backend에서 보안 정책 조회 (더미)
    policy = await policy_service.fetch_policy(session_id=session_id)

    # 2단계: 입력 프롬프트 보안 검사 (더미)
    input_result = await security_service.check_input(
        messages=request.messages,
        policy=policy,
    )
    if input_result.status == CheckStatus.BLOCK:
        raise HTTPException(
            status_code=400,
            detail=f"입력 보안 검사 실패: {input_result.reason}",
        )

    # 3단계: Solar API 비스트리밍 호출 (stream 여부와 무관하게 항상 non-stream)
    api_messages = [
        {"role": msg.role, "content": msg.content} for msg in request.messages
    ]
    content = await solar_service.chat(messages=api_messages)

    # 4단계: 출력 결과 보안 검사 — 사용자 전송 이전에 선행하여 유출 방지
    output_result = await security_service.check_output(
        content=content,
        policy=policy,
    )

    # 5-a단계: 스트리밍 요청 — SSE로 재방출
    if request.stream:
        if output_result.status == CheckStatus.BLOCK:
            return StreamingResponse(
                _stream_error(output_result.reason),
                media_type="text/event-stream",
            )
        return StreamingResponse(
            _stream_content(content),
            media_type="text/event-stream",
        )

    # 5-b단계: 비스트리밍 요청 — 출력 BLOCK은 400, PASS는 ChatResponse
    if output_result.status == CheckStatus.BLOCK:
        raise HTTPException(
            status_code=400,
            detail=f"출력 보안 검사 실패: {output_result.reason}",
        )

    return ChatResponse(
        id=f"chatcmpl-{session_id}",
        object="chat.completion",
        created=int(time.time()),
        model=request.model,
        choices=[
            ChatResponseChoice(
                index=0,
                message=ChatResponseMessage(
                    role="assistant",
                    content=content,
                ),
                finish_reason="stop",
            )
        ],
    )
