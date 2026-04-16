"""Gateway Backend FastAPI 애플리케이션 진입점."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import openai
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.dependencies import get_http_client
from app.errors import (
    map_admin_backend_error,
    map_solar_error,
)
from app.routers import chat


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


app = FastAPI(title="Gateway Backend", lifespan=lifespan)

# CORS — 사내망 전개 가정 하에 전 오리진 허용.
# 공개 배포 시에는 allow_origins를 화이트리스트로 좁히고 인증·레이트리밋 도입.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    _request: Request, exc: openai.APIError
) -> JSONResponse:
    """Solar(openai) 예외를 구조화된 JSON 으로 반환한다.

    Args:
        _request: FastAPI 요청 객체.
        exc: OpenAI API 오류 인스턴스.

    Returns:
        구조화된 에러 JSON 응답.
    """
    status, detail = map_solar_error(exc)
    return JSONResponse(
        status_code=status,
        content=detail.model_dump(),
    )


@app.exception_handler(httpx.HTTPError)
async def admin_backend_error_handler(
    _request: Request, exc: httpx.HTTPError
) -> JSONResponse:
    """admin-backend(httpx) 예외를 구조화된 JSON 으로 반환.

    Args:
        _request: FastAPI 요청 객체.
        exc: httpx 오류 인스턴스.

    Returns:
        구조화된 에러 JSON 응답.
    """
    status, detail = map_admin_backend_error(exc)
    return JSONResponse(
        status_code=status,
        content=detail.model_dump(),
    )
