"""Chat 완성 라우터 — 핵심 가드레일 파이프라인."""

import json
import logging
import time
import uuid
from collections.abc import AsyncGenerator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.config import Settings, get_settings
from app.dependencies import (
    get_nonce_store,
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
from app.services.request_verifier import (
    HeaderVerificationError,
    NonceStore,
    VerifiedHeaders,
    body_hash_hex,
    extract_headers,
    verify_and_remember_nonce,
    verify_timestamp,
)
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

# 로그에 찍히는 사용자 프롬프트 1건당 최대 길이. 이보다 길면 말줄임표로 잘린다.
_LOG_PROMPT_CHAR_LIMIT = 200

_TIMING_ORDER: tuple[str, ...] = (
    "header_verification",
    "policy_fetch",
    "input_guardrail",
    "llm_call",
    "output_guardrail",
    "response_emit",
    "total",
)


def _elapsed_ms(started_at: float) -> float:
    """지정 시각부터 현재까지의 경과 시간을 밀리초로 반환한다."""
    return (time.perf_counter() - started_at) * 1000


def _record_timing(
    timings: dict[str, float],
    name: str,
    started_at: float,
) -> float:
    """단계별 경과 시간을 기록하고 반환한다."""
    elapsed = _elapsed_ms(started_at)
    timings[name] = elapsed
    return elapsed


def _log_request_summary(
    session_id: str,
    *,
    final_status: str,
    stream: bool,
    timings: dict[str, float],
) -> None:
    """요청 종료 시점의 단계별 소요 시간을 구조화해 로그에 남긴다."""
    lines = [
        f"[{session_id}] 요청 완료 요약: "
        f"final_status={final_status} stream={stream}"
    ]
    for name in _TIMING_ORDER:
        elapsed = timings.get(name)
        if elapsed is None:
            continue
        lines.append(f"  {name}_ms={elapsed:.1f}")
    logger.info("\n".join(lines))


def _finalize_request_log(
    session_id: str,
    *,
    final_status: str,
    stream: bool,
    timings: dict[str, float],
    t_request: float,
    t_response: float,
) -> None:
    """응답 직전 시간을 포함해 최종 요약 로그를 남긴다."""
    _record_timing(timings, "response_emit", t_response)
    timings["total"] = _elapsed_ms(t_request)
    _log_request_summary(
        session_id,
        final_status=final_status,
        stream=stream,
        timings=timings,
    )


def _message_text(content: object) -> str:
    """Message.content 를 로그용 한 줄 문자열로 변환한다.

    OpenAI 호환 확장으로 content 는 문자열, content part 목록(dict 리스트),
    또는 None 이 될 수 있다. multimodal part 는 text 필드만 추려 연결한다.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, dict):
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return " ".join(parts)
    return str(content)


def _summarize_user_prompts(messages: list[Any]) -> str:
    """로그에 찍을 사용자 입력 요약 문자열을 조립한다.

    role 별로 접두사를 붙이고(`[user]`, `[system]` 등), 줄바꿈을 스페이스로
    치환하여 한 줄로 만든다. `_LOG_PROMPT_CHAR_LIMIT` 를 넘는 개별 메시지는
    말줄임표로 잘린다.
    """
    segments: list[str] = []
    for msg in messages:
        text = _message_text(getattr(msg, "content", None)).replace("\n", " ")
        if len(text) > _LOG_PROMPT_CHAR_LIMIT:
            text = text[:_LOG_PROMPT_CHAR_LIMIT] + "…"
        role = getattr(msg, "role", "?")
        segments.append(f"[{role}] {text}")
    return " | ".join(segments)


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
    final_extra: dict[str, Any] | None = None,
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
        final_extra: 마지막 finish 프레임에 병합할 비표준 확장 필드.
            관찰 모드에서 `{"guardrail_reports": {...}}` 를 싣기 위해 사용.

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
    # 3. finish 프레임 (관찰 모드면 guardrail_reports 를 여기 실어 보낸다)
    yield _format_sse_frame(
        _build_chunk(
            chunk_id=chunk_id,
            created=created,
            model=model,
            delta={},
            finish_reason=finish_reason or "stop",
            extra=final_extra,
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


def _report_entry(result: GuardrailResult) -> dict[str, Any]:
    """관찰 모드 `guardrail_reports` 항목 하나를 직렬화한다.

    PASS 는 layer/status 만, BLOCK 은 reason·severity·confidence·tags 까지
    함께 실어 플레이그라운드/데모에서 바로 시각화할 수 있게 한다.
    """
    entry: dict[str, Any] = {
        "layer": result.layer,
        "status": result.status.value,
    }
    if result.status is CheckStatus.BLOCK:
        entry["reason"] = result.reason
        entry["severity"] = result.severity
        entry["confidence"] = result.confidence
        entry["tags"] = list(result.tags)
    return entry


def _build_guardrail_reports(
    input_results: list[GuardrailResult],
    output_results: list[GuardrailResult],
) -> dict[str, Any]:
    """관찰 모드 응답에 첨부할 `guardrail_reports` 블록을 조립한다."""
    return {
        "mode": "observe",
        "input": [_report_entry(r) for r in input_results],
        "output": [_report_entry(r) for r in output_results],
    }


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


async def _run_observe_mode_pipeline(
    *,
    request: ChatRequest,
    session_id: str,
    t_request: float,
    timings: dict[str, float],
    policy: GuardrailPolicy,
    security_service: SecurityLayerService,
    provider_router: ProviderRouter,
) -> ChatResponse | StreamingResponse:
    """`CONTINUE_ON_LAYER_FAILURE=true` 데모 모드 전용 파이프라인.

    기본(차단) 경로와 달리 BLOCK 판정을 early-return 하지 않고 입력 레이어
    전체 → LLM 호출 → 출력 레이어 전체 순서로 끝까지 실행한 뒤, 응답에
    `guardrail_reports` 블록을 첨부한다. 스트리밍인 경우 마지막 finish
    프레임에 동일한 메타데이터를 실어 보낸다.

    Args:
        request: 원본 `ChatRequest`.
        session_id: 세션 UUID.
        t_request: 요청 시작 시각(perf_counter).
        timings: 단계별 소요 시간을 누적하는 딕셔너리.
        policy: 적용할 보안 정책.
        security_service: 보안 레이어 서비스.
        provider_router: LLM provider 라우터.

    Returns:
        스트리밍/비스트리밍에 따라 `StreamingResponse` 또는 `ChatResponse`.
    """
    # 2단계: 입력 레이어 전체 실행
    t0 = time.perf_counter()
    input_results = await security_service.check_input_all(
        messages=request.messages,
        policy=policy,
    )
    input_guardrail_ms = _record_timing(
        timings, "input_guardrail", t0
    )
    logger.info(
        "[%s] (관찰) 2단계 입력 검사 완료: %.1fms 결과=%s",
        session_id,
        input_guardrail_ms,
        [r.status.value for r in input_results],
    )
    for r in input_results:
        if r.status is CheckStatus.BLOCK:
            logger.warning(
                "[%s] (관찰) 입력 BLOCK 무시하고 진행: layer=%s reason=%s",
                session_id,
                r.layer,
                r.reason,
            )

    # 3단계: LLM 호출 (기존 경로와 동일)
    t0 = time.perf_counter()
    api_messages = [
        msg.model_dump(exclude_none=True) for msg in request.messages
    ]
    passthrough = request.model_dump(
        exclude={"messages", "stream"},
        exclude_none=True,
    )
    llm_service, resolved_model = provider_router.resolve(request.model)
    passthrough["model"] = resolved_model
    completion = await llm_service.chat(messages=api_messages, **passthrough)
    content = completion.choices[0].message.content or ""
    llm_call_ms = _record_timing(timings, "llm_call", t0)
    logger.info(
        "[%s] (관찰) 3단계 LLM 호출 완료: %.1fms provider=%s model=%s",
        session_id,
        llm_call_ms,
        llm_service.provider_name,
        resolved_model,
    )

    # 4단계: 출력 레이어 전체 실행
    t0 = time.perf_counter()
    output_results = await security_service.check_output_all(
        content=content,
        policy=policy,
    )
    output_guardrail_ms = _record_timing(
        timings, "output_guardrail", t0
    )
    logger.info(
        "[%s] (관찰) 4단계 출력 검사 완료: %.1fms 결과=%s",
        session_id,
        output_guardrail_ms,
        [r.status.value for r in output_results],
    )
    for r in output_results:
        if r.status is CheckStatus.BLOCK:
            logger.warning(
                "[%s] (관찰) 출력 BLOCK 무시하고 진행: layer=%s reason=%s",
                session_id,
                r.layer,
                r.reason,
            )

    reports = _build_guardrail_reports(input_results, output_results)

    chunk_id = f"chatcmpl-{session_id}"
    created = getattr(completion, "created", None) or int(time.time())
    model_name = getattr(completion, "model", None) or request.model
    finish_reason = completion.choices[0].finish_reason or "stop"
    total_ms = _elapsed_ms(t_request)

    # 5-a단계: 스트리밍 — 마지막 finish 프레임에 guardrail_reports 주입
    if request.stream:
        t_response = time.perf_counter()
        logger.info(
            "[%s] (관찰) 5단계 응답 전송: stream=True 총 %.1fms",
            session_id,
            total_ms,
        )
        response = StreamingResponse(
            _stream_openai_chunks(
                content,
                chunk_id=chunk_id,
                created=created,
                model=model_name,
                finish_reason=finish_reason,
                final_extra={"guardrail_reports": reports},
            ),
            media_type="text/event-stream",
            headers=_SSE_HEADERS,
        )
        _finalize_request_log(
            session_id,
            final_status="observe_success",
            stream=True,
            timings=timings,
            t_request=t_request,
            t_response=t_response,
        )
        return response

    # 5-b단계: 비스트리밍 — ChatResponse.guardrail_reports 로 첨부
    t_response = time.perf_counter()
    logger.info(
        "[%s] (관찰) 5단계 응답 전송: stream=False 총 %.1fms",
        session_id,
        total_ms,
    )
    response = ChatResponse(
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
        guardrail_reports=reports,
    )
    _finalize_request_log(
        session_id,
        final_status="observe_success",
        stream=False,
        timings=timings,
        t_request=t_request,
        t_response=t_response,
    )
    return response


def _header_error_response(reason: str) -> JSONResponse:
    """헤더 검증 실패 시 사용자에게 내려줄 401 응답을 조립한다."""
    return JSONResponse(
        status_code=401,
        content={
            "error": {
                "type": "header_verification_failed",
                "reason": reason,
            }
        },
    )


def _verify_user_headers(
    request: Request,
    *,
    settings: Settings,
    nonce_store: NonceStore,
    now: float,
) -> VerifiedHeaders:
    """사용자 요청 헤더 4개를 추출·검증하여 VerifiedHeaders 를 반환한다.

    `settings.skip_header_verification=True` 면 검증을 건너뛰고 헤더에서
    읽을 수 있는 값만 담아 반환한다(값이 없는 필드는 빈 문자열).

    Raises:
        HeaderVerificationError: 필수 헤더 누락/빈값, timestamp skew 초과,
            nonce 재연 중 하나라도 발생하면 호출측이 401 응답으로 전환하도록
            예외를 전파한다.
    """
    if settings.skip_header_verification:
        return VerifiedHeaders(
            api_key=request.headers.get("x-api-key", ""),
            timestamp=request.headers.get("x-timestamp", ""),
            nonce=request.headers.get("x-nonce", ""),
            signature=request.headers.get("x-signature", ""),
        )
    verified = extract_headers(request.headers)
    verify_timestamp(
        verified.timestamp,
        now=now,
        skew_sec=settings.request_timestamp_skew_sec,
    )
    verify_and_remember_nonce(verified.nonce, nonce_store, now=now)
    return verified


@router.post("/chat/completions", response_model=None)
async def chat_completions(
    http_request: Request,
    request: ChatRequest,
    policy_service: Annotated[PolicyService, Depends(get_policy_service)],
    security_service: Annotated[
        SecurityLayerService, Depends(get_security_service)
    ],
    provider_router: Annotated[ProviderRouter, Depends(get_provider_router)],
    nonce_store: Annotated[NonceStore, Depends(get_nonce_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ChatResponse | StreamingResponse | JSONResponse:
    """OpenAI 호환 채팅 완성 요청을 처리한다.

    가드레일 파이프라인:
    0. 사용자 헤더 4개(X-API-Key/X-Timestamp/X-Nonce/X-Signature) 검증
    1. admin-backend `/api/v1/gateway/verify` 로 검증+정책 조회
    2. security-layer로 입력 프롬프트 검사
    3. 모델명 기반 provider 자동 감지 후 LLM 비스트리밍 호출
    4. security-layer로 출력 결과 검사 (사용자 전송 이전에 선행)
    5. `stream=False`면 JSON, `stream=True`면 SSE로 재방출

    Args:
        http_request: 원본 HTTP 요청 (헤더·body 원문 접근 용).
        request: OpenAI 호환 채팅 완성 요청.
        policy_service: ADMIN 검증·정책 조회 서비스.
        security_service: 보안 레이어 검사 서비스.
        provider_router: 모델명 기반 LLM provider 라우터.
        nonce_store: 재연 방지용 in-memory nonce 저장소.
        settings: 애플리케이션 설정.

    Returns:
        헤더 검증 실패: HTTP 401 + `header_verification_failed` JSON.
        비스트리밍: ChatResponse JSON 응답.
        스트리밍: SSE StreamingResponse.
    """
    session_id = str(uuid.uuid4())
    t_request = time.perf_counter()
    timings: dict[str, float] = {}

    logger.info(
        "[%s] 요청 수신: model=%s stream=%s messages=%d건 내용=%s",
        session_id,
        request.model,
        request.stream,
        len(request.messages),
        _summarize_user_prompts(request.messages),
    )

    # 0단계: 사용자 요청 헤더 검증 (+ body hash 계산)
    raw_body = await http_request.body()
    body_hash = body_hash_hex(raw_body)
    t0 = time.perf_counter()
    try:
        verified_headers = _verify_user_headers(
            http_request,
            settings=settings,
            nonce_store=nonce_store,
            now=time.time(),
        )
    except HeaderVerificationError as exc:
        _record_timing(timings, "header_verification", t0)
        logger.warning("[%s] 헤더 검증 실패: %s", session_id, exc)
        t_response = time.perf_counter()
        response = _header_error_response(str(exc))
        _finalize_request_log(
            session_id,
            final_status="header_verification_failed",
            stream=request.stream,
            timings=timings,
            t_request=t_request,
            t_response=t_response,
        )
        return response
    _record_timing(timings, "header_verification", t0)

    # 1단계: admin-backend에서 보안 정책 조회 (검증 위임)
    t0 = time.perf_counter()
    if settings.skip_policy_fetch:
        # 정책 조회는 생략하되 L1~L6 전체 레이어를 강제로 실행한다.
        policy = GuardrailPolicy.all_enabled()
    else:
        policy = await policy_service.verify_and_fetch_policy(
            session_id=session_id,
            headers=verified_headers,
            body_hash=body_hash,
        )
    policy_fetch_ms = _record_timing(timings, "policy_fetch", t0)
    logger.info(
        "[%s] 1단계 정책 조회 완료: %.1fms enabled_layers=%s",
        session_id,
        policy_fetch_ms,
        policy.enabled_layers(),
    )

    # 관찰(데모) 모드: BLOCK 이 있어도 파이프라인을 끝까지 실행하고
    # 응답에 레이어별 판정 내역(`guardrail_reports`)을 첨부한다.
    if settings.continue_on_layer_failure:
        return await _run_observe_mode_pipeline(
            request=request,
            session_id=session_id,
            t_request=t_request,
            timings=timings,
            policy=policy,
            security_service=security_service,
            provider_router=provider_router,
        )

    # 2단계: 입력 프롬프트 보안 검사
    t0 = time.perf_counter()
    input_result = await security_service.check_input(
        messages=request.messages,
        policy=policy,
    )
    input_guardrail_ms = _record_timing(
        timings, "input_guardrail", t0
    )
    logger.info(
        "[%s] 2단계 입력 검사 완료: %.1fms result=%s",
        session_id,
        input_guardrail_ms,
        input_result.status.value,
    )
    if input_result.status == CheckStatus.BLOCK:
        # 입력 BLOCK — LLM 호출 전에 종료. 스트리밍/비스트리밍 모두 HTTP 200 +
        # OpenAI content_filter 규격으로 응답하여 인터페이스를 단일화한다.
        block_chunk_id = f"chatcmpl-{session_id}"
        block_created = int(time.time())
        block_model = request.model
        logger.info(
            "[%s] 2단계 입력 BLOCK 응답: stream=%s 총 %.1fms",
            session_id,
            request.stream,
            (time.perf_counter() - t_request) * 1000,
        )
        t_response = time.perf_counter()
        if request.stream:
            response = StreamingResponse(
                _stream_guardrail_block(
                    input_result,
                    stage="input",
                    chunk_id=block_chunk_id,
                    created=block_created,
                    model=block_model,
                ),
                media_type="text/event-stream",
                headers=_SSE_HEADERS,
            )
        else:
            response = _build_block_response(
                input_result,
                stage="input",
                chunk_id=block_chunk_id,
                created=block_created,
                model=block_model,
            )
        _finalize_request_log(
            session_id,
            final_status="blocked_input",
            stream=request.stream,
            timings=timings,
            t_request=t_request,
            t_response=t_response,
        )
        return response

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
    llm_call_ms = _record_timing(timings, "llm_call", t0)
    logger.info(
        "[%s] 3단계 LLM 호출 완료: %.1fms provider=%s model=%s",
        session_id,
        llm_call_ms,
        llm_service.provider_name,
        resolved_model,
    )

    # 4단계: 출력 결과 보안 검사 — 사용자 전송 이전에 선행하여 유출 방지
    t0 = time.perf_counter()
    output_result = await security_service.check_output(
        content=content,
        policy=policy,
    )
    output_guardrail_ms = _record_timing(
        timings, "output_guardrail", t0
    )
    logger.info(
        "[%s] 4단계 출력 검사 완료: %.1fms result=%s",
        session_id,
        output_guardrail_ms,
        output_result.status.value,
    )

    # 스트리밍/비스트리밍 공통 메타데이터 — Solar 원본 completion 우선, 없으면
    # 게이트웨이에서 fallback 값을 주입한다.
    chunk_id = f"chatcmpl-{session_id}"
    created = getattr(completion, "created", None) or int(time.time())
    model_name = getattr(completion, "model", None) or request.model
    finish_reason = completion.choices[0].finish_reason or "stop"

    total_ms = _elapsed_ms(t_request)

    # 5-a단계: 스트리밍 요청 — OpenAI 호환 SSE 규격으로 재방출
    if request.stream:
        t_response = time.perf_counter()
        if output_result.status == CheckStatus.BLOCK:
            logger.info(
                "[%s] 5단계 응답 전송: stream=True (BLOCK) 총 %.1fms",
                session_id,
                total_ms,
            )
            response = StreamingResponse(
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
            _finalize_request_log(
                session_id,
                final_status="blocked_output",
                stream=True,
                timings=timings,
                t_request=t_request,
                t_response=t_response,
            )
            return response
        logger.info(
            "[%s] 5단계 응답 전송: stream=True 총 %.1fms",
            session_id,
            total_ms,
        )
        response = StreamingResponse(
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
        _finalize_request_log(
            session_id,
            final_status="success",
            stream=True,
            timings=timings,
            t_request=t_request,
            t_response=t_response,
        )
        return response

    # 5-b단계: 비스트리밍 요청 — 출력 BLOCK도 OpenAI content_filter 규격으로
    # HTTP 200 반환 (스트리밍 경로와 인터페이스 일치).
    if output_result.status == CheckStatus.BLOCK:
        t_response = time.perf_counter()
        logger.info(
            "[%s] 5단계 응답 전송: stream=False (BLOCK) 총 %.1fms",
            session_id,
            total_ms,
        )
        response = _build_block_response(
            output_result,
            stage="output",
            chunk_id=chunk_id,
            created=created,
            model=model_name,
        )
        _finalize_request_log(
            session_id,
            final_status="blocked_output",
            stream=False,
            timings=timings,
            t_request=t_request,
            t_response=t_response,
        )
        return response

    t_response = time.perf_counter()
    logger.info(
        "[%s] 5단계 응답 전송: stream=False 총 %.1fms",
        session_id,
        total_ms,
    )

    # Solar 원본 completion 의 메타데이터(id 제외)를 그대로 보존하여
    # OpenAI 호환 클라이언트가 usage/finish_reason/tool_calls 를 받을 수 있게
    # 한다. id 는 가드레일 세션 추적을 위해 게이트웨이가 재할당.
    response = ChatResponse(
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
    _finalize_request_log(
        session_id,
        final_status="success",
        stream=False,
        timings=timings,
        t_request=t_request,
        t_response=t_response,
    )
    return response


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
