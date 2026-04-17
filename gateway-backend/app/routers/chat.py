"""Chat 완성 라우터 — 핵심 가드레일 파이프라인."""

import json
import logging
import time
import uuid
from collections.abc import AsyncGenerator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from app.config import Settings, get_settings
from app.dependencies import (
    get_policy_service,
    get_provider_router,
    get_security_service,
)
from app.models.chat import (
    ChatRequest,
    ChatResponse,
    ChatResponseChoice,
    ChatResponseMessage,
)
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy
from app.services.policy_service import PolicyService
from app.services.provider_router import ProviderRouter
from app.services.security_layer_service import SecurityLayerService

logger = logging.getLogger(__name__)

router = APIRouter()

# 사용자 측 스트리밍 시 응답을 쪼개는 청크 길이(문자 단위).
_SSE_CHUNK_SIZE = 20

# 스트리밍 응답에 프록시 버퍼링이 끼지 않도록 하기 위한 헤더.
_SSE_HEADERS: dict[str, str] = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
}


def _chunk_content(content: str, size: int = _SSE_CHUNK_SIZE) -> list[str]:
    """전체 응답 문자열을 고정 길이 청크 목록으로 분할한다.

    Args:
        content: 분할할 전체 문자열.
        size: 청크 하나의 최대 문자 길이.

    Returns:
        순서대로 연결하면 원본 문자열이 복원되는 청크 목록. 빈 입력에 대해서도
        한 개의 빈 문자열 청크를 반환하여 호출 측이 항상 delta 프레임을
        하나는 내보낼 수 있게 한다.
    """
    if not content:
        return [""]
    return [content[i : i + size] for i in range(0, len(content), size)]


def _format_sse_frame(payload: dict[str, Any]) -> str:
    r"""SSE `data:` 프레임 한 건을 OpenAI 규격으로 직렬화한다.

    Args:
        payload: chat.completion.chunk 객체에 해당하는 딕셔너리.

    Returns:
        `data: {...}\n\n` 형태의 SSE 프레임 문자열.
    """
    return "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"


def _build_chunk(
    *,
    chunk_id: str,
    created: int,
    model: str,
    delta: dict[str, Any],
    finish_reason: str | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """OpenAI `chat.completion.chunk` 객체를 조립한다.

    Args:
        chunk_id: 이 스트림 전체가 공유하는 응답 ID.
        created: Unix timestamp.
        model: 응답 모델 이름.
        delta: 이번 프레임에서 추가될 델타 필드.
        finish_reason: 마지막 프레임이면 종료 이유, 중간 프레임이면 None.
        extra: 비표준 확장 필드(예: guardrail error 블록).

    Returns:
        JSON 직렬화 가능한 chunk 딕셔너리.
    """
    chunk: dict[str, Any] = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }
        ],
    }
    if extra:
        chunk.update(extra)
    return chunk


async def _stream_openai_chunks(
    content: str,
    *,
    chunk_id: str,
    created: int,
    model: str,
    finish_reason: str,
) -> AsyncGenerator[str]:
    """검증이 끝난 전체 content를 OpenAI SSE 규격으로 재방출한다.

    첫 프레임은 `role=assistant` 를 담고, 중간 프레임들은 `content` 델타를,
    마지막 프레임은 finish_reason 을 싣는다. 마지막에 `data: [DONE]` 마커를
    한 번 더 전송한다.

    Args:
        content: 사용자에게 전송할 전체 응답 문자열.
        chunk_id: 스트림 응답 ID (세션 ID 연계).
        created: Unix timestamp.
        model: 응답 모델 이름.
        finish_reason: Solar 가 제공한 종료 이유. 비어 있으면 "stop".

    Yields:
        OpenAI 호환 SSE 프레임 문자열.
    """
    # 1. role 선언 프레임
    yield _format_sse_frame(
        _build_chunk(
            chunk_id=chunk_id,
            created=created,
            model=model,
            delta={"role": "assistant"},
            finish_reason=None,
        )
    )
    # 2. content delta 프레임들
    for chunk in _chunk_content(content):
        if not chunk:
            continue
        yield _format_sse_frame(
            _build_chunk(
                chunk_id=chunk_id,
                created=created,
                model=model,
                delta={"content": chunk},
                finish_reason=None,
            )
        )
    # 3. finish 프레임
    yield _format_sse_frame(
        _build_chunk(
            chunk_id=chunk_id,
            created=created,
            model=model,
            delta={},
            finish_reason=finish_reason or "stop",
        )
    )
    # 4. 종료 마커
    yield "data: [DONE]\n\n"


def _block_message(stage: str, reason: str | None) -> str:
    """차단 응답에 사용할 사람이 읽을 메시지를 조립한다.

    Args:
        stage: 차단이 발생한 단계 ("input" 또는 "output").
        reason: 레이어가 제공한 사유 문자열. None 이면 프리픽스만.

    Returns:
        `"<프리픽스>"` 또는 `"<프리픽스>: <사유>"` 형태의 문자열.
    """
    prefix = (
        "입력 보안 검사 실패" if stage == "input" else "출력 보안 검사 실패"
    )
    return f"{prefix}: {reason}" if reason else prefix


def _build_block_error(
    result: GuardrailResult,
    stage: str,
) -> dict[str, Any]:
    """차단 응답에 실릴 표준 error 객체를 조립한다.

    스트리밍·비스트리밍·입력·출력 차단에서 공통으로 사용하여 응답 스키마를
    단일화한다. LayerResult 에서 보존된 layer/severity/confidence/tags 를
    그대로 노출한다.

    Args:
        result: BLOCK 판정이 담긴 GuardrailResult.
        stage: "input" 또는 "output".

    Returns:
        OpenAI 비표준 error 블록 dict.
    """
    return {
        "type": "guardrail_block",
        "stage": stage,
        "message": _block_message(stage, result.reason),
        "layer": result.layer,
        "reason": result.reason,
        "severity": result.severity,
        "confidence": result.confidence,
        "tags": list(result.tags),
    }


async def _stream_guardrail_block(
    result: GuardrailResult,
    *,
    stage: str,
    chunk_id: str,
    created: int,
    model: str,
) -> AsyncGenerator[str]:
    """가드레일 BLOCK 시 OpenAI 규격 내에서 에러 프레임을 방출한다.

    원본 LLM 응답은 절대 유출하지 않는다. finish_reason 은 OpenAI 모더레이션
    관례대로 "content_filter" 로 세팅하고, 비표준 `error` 블록에 사유와 레이어
    메타데이터를 담아 LiteLLM 등 일부 클라이언트가 인식할 수 있게 한다.

    Args:
        result: BLOCK 판정이 담긴 GuardrailResult.
        stage: "input" 또는 "output".
        chunk_id: 스트림 응답 ID.
        created: Unix timestamp.
        model: 응답 모델 이름.

    Yields:
        단일 에러 chunk 프레임과 종료 마커.
    """
    yield _format_sse_frame(
        _build_chunk(
            chunk_id=chunk_id,
            created=created,
            model=model,
            delta={},
            finish_reason="content_filter",
            extra={"error": _build_block_error(result, stage)},
        )
    )
    yield "data: [DONE]\n\n"


def _build_block_response(
    result: GuardrailResult,
    *,
    stage: str,
    chunk_id: str,
    created: int,
    model: str,
) -> ChatResponse:
    """가드레일 BLOCK 시 비스트리밍 ChatResponse 를 조립한다.

    OpenAI 모더레이션 관례에 맞춰 HTTP 200 으로 반환한다. 원본 LLM 응답은
    유출하지 않기 위해 content 를 빈 문자열로 두고, finish_reason 을
    "content_filter" 로 설정한다. 비표준 `error` 블록에 사유와 레이어
    메타데이터를 담는다.

    Args:
        result: BLOCK 판정이 담긴 GuardrailResult.
        stage: "input" 또는 "output".
        chunk_id: 응답 ID (세션 ID 연계).
        created: Unix timestamp.
        model: 응답 모델 이름.

    Returns:
        error 블록이 채워진 ChatResponse.
    """
    return ChatResponse(
        id=chunk_id,
        object="chat.completion",
        created=created,
        model=model,
        choices=[
            ChatResponseChoice(
                index=0,
                message=ChatResponseMessage(role="assistant", content=""),
                finish_reason="content_filter",
            )
        ],
        usage=None,
        error=_build_block_error(result, stage),
    )


@router.post("/chat/completions", response_model=None)
async def chat_completions(
    request: ChatRequest,
    policy_service: Annotated[PolicyService, Depends(get_policy_service)],
    security_service: Annotated[
        SecurityLayerService, Depends(get_security_service)
    ],
    provider_router: Annotated[ProviderRouter, Depends(get_provider_router)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ChatResponse | StreamingResponse:
    """OpenAI 호환 채팅 완성 요청을 처리한다.

    가드레일 파이프라인:
    1. admin-backend에서 보안 정책 조회
    2. security-layer로 입력 프롬프트 검사
    3. 모델명 기반 provider 자동 감지 후 LLM 비스트리밍 호출
    4. security-layer로 출력 결과 검사 (사용자 전송 이전에 선행)
    5. `stream=False`면 JSON, `stream=True`면 SSE로 재방출

    Args:
        request: OpenAI 호환 채팅 완성 요청.
        policy_service: 보안 정책 조회 서비스.
        security_service: 보안 레이어 검사 서비스.
        provider_router: 모델명 기반 LLM provider 라우터.
        settings: 애플리케이션 설정 (정책 조회 생략 여부 포함).

    Returns:
        비스트리밍: ChatResponse JSON 응답.
        스트리밍: SSE StreamingResponse.

    Raises:
        HTTPException: 입력 검사 실패 시 400. (출력 검사 실패는 HTTP 200 +
            OpenAI content_filter 응답 스키마로 반환)
    """
    session_id = str(uuid.uuid4())
    t_request = time.perf_counter()

    logger.info(
        "[%s] 요청 수신: model=%s stream=%s messages=%d건",
        session_id,
        request.model,
        request.stream,
        len(request.messages),
    )

    # 1단계: admin-backend에서 보안 정책 조회
    t0 = time.perf_counter()
    if settings.skip_policy_fetch:
        # 정책 조회는 생략하되 L1~L6 전체 레이어를 강제로 실행한다.
        policy = GuardrailPolicy.all_enabled()
    else:
        policy = await policy_service.fetch_policy(
            session_id=session_id,
        )
    logger.info(
        "[%s] 1단계 정책 조회 완료: %.1fms enabled_layers=%s",
        session_id,
        (time.perf_counter() - t0) * 1000,
        policy.enabled_layers(),
    )

    # 2단계: 입력 프롬프트 보안 검사
    t0 = time.perf_counter()
    input_result = await security_service.check_input(
        messages=request.messages,
        policy=policy,
    )
    logger.info(
        "[%s] 2단계 입력 검사 완료: %.1fms result=%s",
        session_id,
        (time.perf_counter() - t0) * 1000,
        input_result.status.value,
    )
    if input_result.status == CheckStatus.BLOCK:
        raise HTTPException(
            status_code=400,
            detail=_block_message("input", input_result.reason),
        )

    # 3단계: 모델명 기반 provider 자동 감지 후 LLM 비스트리밍 호출
    # messages 는 None/옵션 필드를 제거한 뒤 그대로 전달하여
    # tool/multimodal 메시지도 온전히 보존한다.
    t0 = time.perf_counter()
    api_messages = [
        msg.model_dump(exclude_none=True) for msg in request.messages
    ]
    # 요청 바디의 OpenAI 호환 파라미터를 LLM 호출에 pass-through.
    passthrough = request.model_dump(
        exclude={"messages", "stream"},
        exclude_none=True,
    )
    llm_service, resolved_model = provider_router.resolve(request.model)
    passthrough["model"] = resolved_model
    completion = await llm_service.chat(messages=api_messages, **passthrough)
    content = completion.choices[0].message.content or ""
    logger.info(
        "[%s] 3단계 LLM 호출 완료: %.1fms provider=%s model=%s",
        session_id,
        (time.perf_counter() - t0) * 1000,
        llm_service.provider_name,
        resolved_model,
    )

    # 4단계: 출력 결과 보안 검사 — 사용자 전송 이전에 선행하여 유출 방지
    t0 = time.perf_counter()
    output_result = await security_service.check_output(
        content=content,
        policy=policy,
    )
    logger.info(
        "[%s] 4단계 출력 검사 완료: %.1fms result=%s",
        session_id,
        (time.perf_counter() - t0) * 1000,
        output_result.status.value,
    )

    # 스트리밍/비스트리밍 공통 메타데이터 — Solar 원본 completion 우선, 없으면
    # 게이트웨이에서 fallback 값을 주입한다.
    chunk_id = f"chatcmpl-{session_id}"
    created = getattr(completion, "created", None) or int(time.time())
    model_name = getattr(completion, "model", None) or request.model
    finish_reason = completion.choices[0].finish_reason or "stop"

    total_ms = (time.perf_counter() - t_request) * 1000

    # 5-a단계: 스트리밍 요청 — OpenAI 호환 SSE 규격으로 재방출
    if request.stream:
        if output_result.status == CheckStatus.BLOCK:
            logger.info(
                "[%s] 5단계 응답 전송: stream=True (BLOCK) 총 %.1fms",
                session_id,
                total_ms,
            )
            return StreamingResponse(
                _stream_guardrail_block(
                    output_result,
                    stage="output",
                    chunk_id=chunk_id,
                    created=created,
                    model=model_name,
                ),
                media_type="text/event-stream",
                headers=_SSE_HEADERS,
            )
        logger.info(
            "[%s] 5단계 응답 전송: stream=True 총 %.1fms",
            session_id,
            total_ms,
        )
        return StreamingResponse(
            _stream_openai_chunks(
                content,
                chunk_id=chunk_id,
                created=created,
                model=model_name,
                finish_reason=finish_reason,
            ),
            media_type="text/event-stream",
            headers=_SSE_HEADERS,
        )

    # 5-b단계: 비스트리밍 요청 — 출력 BLOCK도 OpenAI content_filter 규격으로
    # HTTP 200 반환 (스트리밍 경로와 인터페이스 일치).
    if output_result.status == CheckStatus.BLOCK:
        logger.info(
            "[%s] 5단계 응답 전송: stream=False (BLOCK) 총 %.1fms",
            session_id,
            total_ms,
        )
        return _build_block_response(
            output_result,
            stage="output",
            chunk_id=chunk_id,
            created=created,
            model=model_name,
        )

    logger.info(
        "[%s] 5단계 응답 전송: stream=False 총 %.1fms",
        session_id,
        total_ms,
    )

    # Solar 원본 completion 의 메타데이터(id 제외)를 그대로 보존하여
    # OpenAI 호환 클라이언트가 usage/finish_reason/tool_calls 를 받을 수 있게
    # 한다. id 는 가드레일 세션 추적을 위해 게이트웨이가 재할당.
    return ChatResponse(
        id=chunk_id,
        object="chat.completion",
        created=created,
        model=model_name,
        choices=[
            ChatResponseChoice(
                index=choice.index,
                message=ChatResponseMessage(
                    role=choice.message.role,
                    content=(choice.message.content or ""),
                    tool_calls=_dump_tool_calls(choice.message),
                ),
                finish_reason=choice.finish_reason,
            )
            for choice in completion.choices
        ],
        usage=(
            completion.usage.model_dump()
            if getattr(completion, "usage", None) is not None
            else None
        ),
    )


def _dump_tool_calls(
    message: object,
) -> list[dict[str, object]] | None:
    """Solar 응답 메시지의 tool_calls 를 dict 목록으로 변환한다.

    Args:
        message: ChatCompletion choice 의 message 객체.

    Returns:
        tool_calls 가 존재하면 dict 목록, 없으면 None.
    """
    tool_calls = getattr(message, "tool_calls", None)
    if not tool_calls:
        return None
    return [
        tc.model_dump() if hasattr(tc, "model_dump") else dict(tc)
        for tc in tool_calls
    ]
