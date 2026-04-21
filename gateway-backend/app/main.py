"""Gateway Backend FastAPI 애플리케이션 진입점."""

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import openai
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from langchain_core.exceptions import LangChainException

from app.dependencies import get_http_client
from app.errors import (
    map_admin_backend_error,
    map_langchain_error,
    map_solar_error,
)
from app.routers import chat

# 앱 전체 로깅 포맷 설정 — uvicorn 기본 핸들러와 별개로 앱 로거 출력 보장.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
)

logger = logging.getLogger(__name__)

# 미들웨어 로깅에서 제외할 경로.
_SKIP_LOG_PATHS: frozenset[str] = frozenset({"/health", "/openapi.json"})


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """앱 수명주기 동안 httpx AsyncClient 를 관리한다.

    Args:
        _app: FastAPI 앱 인스턴스.

    Yields:
        None.
    """
    client = get_http_client()
    try:
        yield
    finally:
        await client.aclose()
        get_http_client.cache_clear()


app = FastAPI(
    title="Agentic AI Guardrail Gateway",
    description=(
        "LangChain 기반 Multi-provider LLM Gateway.\n\n"
        "모델명으로 provider를 자동 감지하여 라우팅합니다:\n"
        "- **Solar**: `solar-pro` 등 (기본값)\n"
        "- **OpenAI**: `gpt-4o`, `o1-preview` 등 (자동 감지)\n"
        "- **Ollama**: `ollama/llama3` 등 (접두사 명시)\n\n"
        "모든 요청은 5단계 가드레일 파이프라인을 거칩니다:\n"
        "정책 조회 → 입력 검사 → LLM 호출 → 출력 검사 → 응답"
    ),
    version="0.2.0",
    lifespan=lifespan,
)

# CORS — 사내망 전개 가정 하에 전 오리진 허용.
# 공개 배포 시에는 allow_origins를 화이트리스트로 좁히고 인증·레이트리밋 도입.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_request(request: Request, call_next) -> Response:  # noqa: ANN001
    """요청/응답을 로깅하고 총 소요 시간을 기록하는 미들웨어."""
    if request.url.path in _SKIP_LOG_PATHS:
        return await call_next(request)

    client = request.client.host if request.client else "-"
    logger.info(
        "요청 수신: %s %s client=%s",
        request.method,
        request.url.path,
        client,
    )
    start = time.perf_counter()
    response: Response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "응답 완료: %s %s status=%d %.1fms",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


# 가드레일 채팅 라우터 마운트
app.include_router(chat.router, prefix="/v1")

# 플레이그라운드 정적 페이지 마운트 (/playground/)
_STATIC_DIR = Path(__file__).parent / "static"
app.mount(
    "/playground",
    StaticFiles(directory=_STATIC_DIR, html=True),
    name="playground",
)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """서비스 헬스체크 엔드포인트.

    Returns:
        서비스 상태를 담은 딕셔너리.
    """
    return {"status": "ok"}


@app.get("/v1/models/default")
async def default_model() -> dict[str, str]:
    """환경 변수에 설정된 기본 모델명을 반환한다.

    Returns:
        기본 모델명을 담은 딕셔너리.
    """
    from app.config import get_settings

    settings = get_settings()
    return {"default_model": settings.llm_model}


@app.exception_handler(openai.APIError)
async def solar_error_handler(
    request: Request, exc: openai.APIError
) -> JSONResponse:
    """Solar(openai) 예외를 구조화된 JSON 으로 반환한다.

    Args:
        request: FastAPI 요청 객체.
        exc: OpenAI API 오류 인스턴스.

    Returns:
        구조화된 에러 JSON 응답.
    """
    status, detail = map_solar_error(exc)
    sid = getattr(
        getattr(request, "state", None),
        "session_id",
        None,
    )
    logger.error(
        "upstream_error: provider=%s "
        "exception_type=%s upstream_status=%s "
        "session_id=%s",
        detail.provider,
        type(exc).__name__,
        detail.upstream_status,
        sid,
    )
    return JSONResponse(
        status_code=status,
        content=detail.model_dump(),
    )


@app.exception_handler(httpx.HTTPError)
async def admin_backend_error_handler(
    request: Request, exc: httpx.HTTPError
) -> JSONResponse:
    """admin-backend(httpx) 예외를 구조화된 JSON 으로 반환.

    Args:
        request: FastAPI 요청 객체.
        exc: httpx 오류 인스턴스.

    Returns:
        구조화된 에러 JSON 응답.
    """
    status, detail = map_admin_backend_error(exc)
    sid = getattr(
        getattr(request, "state", None),
        "session_id",
        None,
    )
    logger.error(
        "upstream_error: provider=%s "
        "exception_type=%s upstream_status=%s "
        "session_id=%s",
        detail.provider,
        type(exc).__name__,
        detail.upstream_status,
        sid,
    )
    return JSONResponse(
        status_code=status,
        content=detail.model_dump(),
    )


@app.exception_handler(LangChainException)
async def langchain_error_handler(
    request: Request, exc: LangChainException
) -> JSONResponse:
    """LangChain 예외를 구조화된 JSON 으로 반환한다.

    openai.APIError 가 아닌 LangChain 고유 예외에 대한 fallback 핸들러.

    Args:
        request: FastAPI 요청 객체.
        exc: LangChain 오류 인스턴스.

    Returns:
        구조화된 에러 JSON 응답.
    """
    status, detail = map_langchain_error(exc)
    sid = getattr(
        getattr(request, "state", None),
        "session_id",
        None,
    )
    logger.error(
        "upstream_error: provider=%s "
        "exception_type=%s upstream_status=%s "
        "session_id=%s",
        detail.provider,
        type(exc).__name__,
        detail.upstream_status,
        sid,
    )
    return JSONResponse(
        status_code=status,
        content=detail.model_dump(),
    )
