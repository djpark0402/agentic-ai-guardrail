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


async def _sse_generator(chunks: list[str]) -> AsyncGenerator[str, None]:
    """SSE 포맷으로 청크를 yield하는 제너레이터.

    Args:
        chunks: 전송할 텍스트 청크 목록.

    Yields:
        SSE 포맷 문자열.
    """
    for chunk in chunks:
        yield f"data: {chunk}\n\n"
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
    3. Solar API 호출
    4. security-layer로 출력 결과 검사
    5. 결과 반환

    Args:
        request: OpenAI/Solar 호환 채팅 완성 요청.
        policy_service: 보안 정책 조회 서비스.
        security_service: 보안 레이어 검사 서비스.
        solar_service: Solar API 클라이언트 서비스.

    Returns:
        비스트리밍: ChatResponse JSON 응답.
        스트리밍: SSE StreamingResponse.

    Raises:
        HTTPException: 입력 또는 출력 보안 검사 실패 시 400.
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

    # OpenAI SDK 포맷으로 메시지 변환
    api_messages = [
        {"role": msg.role, "content": msg.content} for msg in request.messages
    ]

    # 스트리밍 요청 처리
    if request.stream:
        collected: list[str] = []

        async def _collect_and_stream() -> AsyncGenerator[str, None]:
            """Solar 응답을 수집하고 SSE로 스트리밍한다."""
            async for chunk in solar_service.stream_chat(messages=api_messages):
                collected.append(chunk)
                yield f"data: {chunk}\n\n"

            # 4단계: 출력 보안 검사 (스트리밍 완료 후)
            full_content = "".join(collected)
            output_result = await security_service.check_output(
                content=full_content,
                policy=policy,
            )
            if output_result.status == CheckStatus.BLOCK:
                yield (
                    f"data: [ERROR] 출력 보안 검사 실패: "
                    f"{output_result.reason}\n\n"
                )
                return

            yield "data: [DONE]\n\n"

        return StreamingResponse(
            _collect_and_stream(),
            media_type="text/event-stream",
        )

    # 3단계: Solar API 비스트리밍 호출
    content = await solar_service.chat(messages=api_messages)

    # 4단계: 출력 결과 보안 검사 (더미)
    output_result = await security_service.check_output(
        content=content,
        policy=policy,
    )
    if output_result.status == CheckStatus.BLOCK:
        raise HTTPException(
            status_code=400,
            detail=f"출력 보안 검사 실패: {output_result.reason}",
        )

    # 5단계: OpenAI 호환 포맷으로 응답 반환
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
