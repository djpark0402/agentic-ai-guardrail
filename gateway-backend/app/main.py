"""Gateway Backend FastAPI 애플리케이션 진입점."""

from pathlib import Path

import openai
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.routers import chat

app = FastAPI(title="Gateway Backend")

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


@app.exception_handler(openai.APIError)
async def openai_error_handler(
    _request: Request, exc: openai.APIError
) -> JSONResponse:
    """OpenAI/Solar API 오류를 처리하는 글로벌 예외 핸들러.

    Args:
        _request: FastAPI 요청 객체.
        exc: OpenAI API 오류 인스턴스.

    Returns:
        오류 메시지를 담은 JSON 응답.
    """
    return JSONResponse(
        status_code=502,
        content={"detail": f"Solar API 오류: {exc.message}"},
    )
