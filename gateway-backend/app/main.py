"""Gateway Backend FastAPI 애플리케이션 진입점."""

import html as html_lib
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import openai
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from langchain_core.exceptions import LangChainException

from app.dependencies import get_http_client
from app.errors import (
    map_admin_backend_error,
    map_langchain_error,
    map_solar_error,
)
from app.routers import chat, layers

# 앱 전체 로깅 포맷 설정 — uvicorn 기본 핸들러와 별개로 앱 로거 출력 보장.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
)

logger = logging.getLogger(__name__)


class _HealthAccessLogFilter(logging.Filter):
    """uvicorn.access 로거에서 /health 경로 라인을 억제한다.

    도커 healthcheck 가 수초마다 찍는 ``'"GET /health HTTP/1.1" 200 OK'``
    스팸을 제거해, 레이어 진단·실제 요청 로그가 화면에서 밀려나지
    않게 한다. uvicorn access 포맷은 ``(client_addr, method, full_path,
    http_version, status_code)`` 튜플을 args 로 넘기므로 이를 순회해
    ``/health`` 를 걸러내고, 포맷 변화에 대비해 포맷된 message 문자열
    fallback 도 둔다.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple):
            for item in args:
                if isinstance(item, str) and item.startswith("/health"):
                    return False
        return "GET /health " not in record.getMessage()


# 모듈 로드 시점에 필터 부착 — uvicorn 이 --reload 로 자식 프로세스를
# 재기동하더라도 app import 시 함께 적용된다. 전체 access log 를 끄지
# 않고 /health 라인만 제거하므로 POST /v1/chat/completions 등 실제
# 요청 로그는 그대로 남는다.
logging.getLogger("uvicorn.access").addFilter(_HealthAccessLogFilter())

# 미들웨어 로깅에서 제외할 경로.
_SKIP_LOG_PATHS: frozenset[str] = frozenset({"/health", "/openapi.json"})
_STATIC_DIR = Path(__file__).parent / "static"
_DOCS_CSS_PATH = _STATIC_DIR / "docs-overrides.css"
_DOCS_TITLE = "Agentic AI Guardrail Gateway - Swagger UI"
_SWAGGER_UI_PARAMETERS: dict[str, object] = {
    "defaultModelsExpandDepth": -1,
    "displayRequestDuration": True,
    "docExpansion": "list",
    "filter": True,
    "operationsSorter": "alpha",
    "persistAuthorization": True,
    "syntaxHighlight.theme": "nord",
    "tagsSorter": "alpha",
    "tryItOutEnabled": True,
}


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """앱 수명주기 동안 httpx AsyncClient 와 기동 진단 로그를 관리한다.

    기동 시 각 가드레일 레이어(L1~L6)의 모델 로드 상태를 INFO/WARNING
    로그로 출력해, docker 컨테이너 로그에서 바로 확인할 수 있게 한다.

    Args:
        _app: FastAPI 앱 인스턴스.

    Yields:
        None.
    """
    # `_LAYER_MAP` 의 import 부작용(L1~L6 싱글턴 인스턴스화)을 main.py
    # import 시점보다 뒤로 미루기 위해 지연 import.
    from app.services.layer_diagnostics import (
        collect_layer_statuses,
        log_layer_statuses,
    )

    client = get_http_client()
    log_layer_statuses(collect_layer_statuses())
    try:
        yield
    finally:
        await client.aclose()
        get_http_client.cache_clear()


app = FastAPI(
    title="Agentic AI Guardrail Gateway",
    description=(
        "LangChain 기반 Multi-provider LLM Gateway. **OpenAI "
        "`/v1/chat/completions` 호환** 엔드포인트를 제공하며, 요청/응답이 모두 "
        "OpenAI 스펙을 따르므로 `openai` SDK·LiteLLM·LangChain 클라이언트에서 "
        "base_url 만 바꿔 바로 사용할 수 있습니다.\n\n"
        "### Provider 라우팅\n"
        "모델명으로 자동 감지합니다:\n"
        "- **Solar**: `solar-pro` 등 (기본값)\n"
        "- **OpenAI**: `gpt-4o`, `o1-preview` 등 (자동 감지)\n"
        "- **Ollama**: `ollama/llama3` 등 (접두사 명시)\n\n"
        "### 가드레일 파이프라인\n"
        "모든 요청은 다음 순서로 검증됩니다:\n"
        "1. 사용자 헤더 4종 검증 (`X-API-Key`, `X-Timestamp`, `X-Nonce`, "
        "`X-Signature`)\n"
        "2. admin-backend 정책 조회 (`l1Enabled`..`l6Enabled`,"
        " `outboundEnabled`)\n"
        '3. 입력 가드레일 (L1~L6, `messages` 중 `role="user"` 메시지 '
        "본문만 검사 대상 — system / assistant / tool content 는 제외)\n"
        "4. provider 자동 감지 후 LLM 호출\n"
        "5. 출력 가드레일 (L1~L6) — 사용자 전송 전에 선행."
        " `outboundEnabled=false` 면 이 단계를 통째로 스킵하고 원본"
        " LLM 응답을 그대로 전달합니다.\n"
        "6. 비스트리밍 JSON 또는 SSE 스트리밍 응답\n\n"
        "### 가드레일 차단 응답\n"
        "차단 시에도 HTTP 200 과 정상 LLM 응답 shape 을 유지합니다."
        ' `finish_reason="stop"` 을 그대로 쓰고, `message.content` 에'
        " 어느 레이어(L1~L6)에서 어떤 사유로 차단되었는지 한글 안내문을"
        " 담아 반환합니다. 스트리밍 요청에는 문자 단위 SSE 프레임을 짧은"
        " 지연과 함께 흘려보내 실제 LLM 토큰 스트리밍을 흉내냅니다.\n\n"
        "### OpenAI 스펙 외 확장 필드\n"
        "관찰 모드에서만 다음 비표준 필드가 섞일 수 있습니다. OpenAI"
        " 공식 SDK 는 이를 무시하므로 호환성에는 영향이 없습니다.\n"
        "- `guardrail_reports`: `CONTINUE_ON_LAYER_FAILURE=true` +"
        " `APP_ENV=dev` (관찰 모드)에서만 채워지며, 레이어별 PASS/BLOCK"
        " 판정 내역을 배열로 반환합니다. `APP_ENV=prod` 에서는 이 조합이"
        " 기동 시 거부되어 관찰 모드가 절대 활성화되지 않습니다.\n\n"
        "### 레이어 진단\n"
        "각 가드레일 레이어(L1~L6)가 모델을 로드했는지, 그리고 실제로"
        " BLOCK 판정을 낼 수 있는 상태인지(`effective`) 를 두 경로로"
        " 확인할 수 있습니다.\n"
        "- **기동 로그**: FastAPI lifespan startup 단계에서"
        ' "가드레일 레이어 로드 상태 요약" 한 줄과 `• [Lx] ClassName:'
        " 로드 성공/실패했습니다.` 형태의 레이어별 한국어 라인을"
        " 출력합니다. 성공은 INFO, 실패(또는 부분 가용으로 WARNING 이"
        " 필요한 경우)는 WARNING 으로 올라오므로 "
        '`docker logs | grep "로드 실패했습니다"` 로 문제 레이어만 즉시'
        " 추려낼 수 있습니다. L4 처럼 NLI / 벡터+LLM 두 경로 중 한쪽만"
        " 살아 있는 부분 가용 상태에서는 어느 경로로 동작 중인지"
        " 힌트 문장이 함께 붙습니다.\n"
        "- **`GET /v1/layers/status`**: 각 레이어의 `model_loaded` /"
        " `effective` / `signals` (레이어별 내부 상태: L4 의"
        " `nli_rules_count`, `policy_collection_count`, `llm_attached`"
        " 등) 을 JSON 으로 반환합니다. 모델은 로드됐어도 규칙/컬렉션/LLM"
        " 이 비어 있어 조용히 PASS 되는 상태는 이 엔드포인트에서만"
        " 드러납니다.\n\n"
        "### 로그 필터\n"
        "도커 healthcheck 가 수초마다 찍는 "
        "`'\"GET /health HTTP/1.1\" 200 OK'` 라인은 `uvicorn.access`"
        " 로거에 부착된 필터가 자동으로 억제합니다. `/health` 경로만"
        " 제거되고 다른 요청(예: `POST /v1/chat/completions`) 의 access"
        " log 는 그대로 남습니다."
    ),
    version="0.2.0",
    openapi_tags=[
        {
            "name": "chat",
            "description": "OpenAI 호환 Chat Completions 엔드포인트.",
        },
        {
            "name": "meta",
            "description": (
                "헬스체크·기본값·레이어 진단용 보조 엔드포인트."
                " `/v1/layers/status` 에서 각 레이어의 모델 로드 여부와"
                " 실제 BLOCK 가능 여부(`effective`) 를 확인할 수 있다."
            ),
        },
    ],
    docs_url=None,
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

# 레이어 진단 라우터 마운트 — /v1/layers/status 로 모델 로드 상태 조회
app.include_router(layers.router, prefix="/v1")

# 플레이그라운드 정적 페이지 마운트 (/playground/)
app.mount(
    "/playground",
    StaticFiles(directory=_STATIC_DIR, html=True),
    name="playground",
)


@app.get("/docs", include_in_schema=False)
async def custom_swagger_docs(url: str | None = None) -> HTMLResponse:
    """기본 Swagger UI 에 개발 편의 설정만 적용한 문서를 반환한다."""
    docs_url = url or app.openapi_url
    swagger_html = get_swagger_ui_html(
        openapi_url=docs_url,
        title=_DOCS_TITLE,
        swagger_ui_parameters=_SWAGGER_UI_PARAMETERS,
    )
    html = swagger_html.body.decode("utf-8")
    css = _DOCS_CSS_PATH.read_text(encoding="utf-8")
    topbar = f"""
    <div class="gateway-swagger-topbar">
      <div class="gateway-swagger-topbar__brand">
        <span class="gateway-swagger-topbar__mark">{{}}</span>
        <div>
          <strong class="gateway-swagger-topbar__title">Swagger</strong>
          <span class="gateway-swagger-topbar__subtitle">
            Supported by SmartBear
          </span>
        </div>
      </div>
      <form
        class="gateway-swagger-topbar__controls"
        method="get"
        action="/docs"
      >
        <input
          type="text"
          name="url"
          aria-label="OpenAPI URL"
          value="{html_lib.escape(docs_url, quote=True)}"
        />
        <button type="submit">Explore</button>
      </form>
    </div>
    """
    html = html.replace("<body>", f"<body>{topbar}", 1)
    html = html.replace("</head>", f"<style>{css}</style></head>")
    return HTMLResponse(content=html, status_code=swagger_html.status_code)


@app.get("/health", tags=["meta"], summary="헬스체크")
async def health_check() -> dict[str, str]:
    """서비스 헬스체크 엔드포인트.

    Returns:
        서비스 상태를 담은 딕셔너리.
    """
    return {"status": "ok"}


@app.get(
    "/v1/models/default",
    tags=["meta"],
    summary="환경 기본 모델명 조회",
)
async def default_model() -> dict[str, str]:
    """환경 변수에 설정된 기본 모델명을 반환한다.

    Returns:
        기본 모델명을 담은 딕셔너리.
    """
    from app.config import get_settings

    settings = get_settings()
    return {"default_model": settings.llm_model}


@app.get(
    "/v1/playground/defaults",
    tags=["meta"],
    summary="Playground 기본 입력값 조회",
    include_in_schema=False,
)
async def playground_defaults() -> dict[str, str]:
    """Playground 페이지의 X-API-Key / HMAC SECRET 기본값을 반환한다.

    `APP_ENV=dev` 일 때만 환경변수 값을 반환하고, 그 외(`prod`) 에서는
    빈 문자열을 반환해 브라우저로 시크릿이 새지 않게 한다.

    Returns:
        `api_key` / `hmac_secret` 두 개의 문자열을 담은 딕셔너리.
    """
    from app.config import get_settings

    settings = get_settings()
    if settings.app_env != "dev":
        return {"api_key": "", "hmac_secret": ""}
    return {
        "api_key": settings.playground.default_api_key,
        "hmac_secret": (
            settings.playground.default_hmac_secret.get_secret_value()
        ),
    }


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
