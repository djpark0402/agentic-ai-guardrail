# syntax=docker/dockerfile:1.7

# ---------- Stage 1: builder ----------
# uv 로 의존성을 해결하고 .venv 를 만든다.
# 빌드 컨텍스트는 monorepo 루트(../) 기준이다.
FROM python:3.14-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv 바이너리를 공식 이미지에서 복사
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

# 1) core-secure-layer 소스 전체 복사 (모델 파일 ~7.2GB 포함)
#    editable install 이 이 디렉토리(/app/core-secure-layer)를 .pth 로 가리키게 된다.
COPY core-secure-layer/ /app/core-secure-layer/

# 2) gateway-backend 메타 및 애플리케이션 소스 복사
COPY gateway-backend/pyproject.toml gateway-backend/uv.lock /app/gateway-backend/
COPY gateway-backend/app /app/gateway-backend/app
COPY gateway-backend/README.md /app/gateway-backend/README.md

# 3) 의존성 설치 (.venv 는 /app/gateway-backend/.venv 에 생성됨)
WORKDIR /app/gateway-backend
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ---------- Stage 2: runtime ----------
FROM python:3.14-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/gateway-backend/.venv/bin:$PATH"

# 런타임에도 ca-certificates 는 필요 (외부 LLM/admin-backend HTTPS 호출)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 appuser \
    && useradd  --system --uid 1000 --gid appuser --home-dir /app appuser

# builder 에서 /app 전체 복사 (editable .pth 가 /app/core-secure-layer 를 가리킴)
COPY --from=builder --chown=appuser:appuser /app /app

WORKDIR /app/gateway-backend

USER appuser

EXPOSE 8000

# python-only healthcheck (slim 이미지에 curl 이 없음)
HEALTHCHECK --interval=30s --timeout=10s --start-period=300s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5).status == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
