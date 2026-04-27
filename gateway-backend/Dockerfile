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

# 3) uv.lock 에서 torch 와 'torch 때문에만 딸려온' transitive deps
#    (nvidia-cublas, nvidia-cudnn-*, triton 등 16개) 를 dep graph 기준으로
#    잘라낸 requirements.txt 를 생성.
#    - --prune torch 는 dep tree 에서 torch 와 torch 경유로만 도달 가능한
#      패키지를 함께 제거 → 향후 torch 업그레이드로 새 nvidia 패키지가
#      추가돼도 Dockerfile 수정 없이 자동 제외된다.
#    - --no-hashes: hash 엄격검증으로 인한 빌드 실패 여지 제거 (버전 pin 은 유지).
#    - pyproject.toml / uv.lock 은 건드리지 않는다 (로컬 macOS 환경과 분리).
WORKDIR /app/gateway-backend
RUN --mount=type=cache,target=/root/.cache/uv \
    uv export --frozen --no-dev \
        --prune torch \
        --format requirements.txt \
        --no-hashes \
        -o /tmp/requirements.txt

# 4) 가상환경 생성 + non-torch 의존성 설치.
#    requirements.txt 에는 editable path-dep 인 core-secure-layer 가
#    -e file:///app/core-secure-layer 로, gateway-backend 자체도 editable
#    project 로 포함되어 함께 설치된다 (각자 .pth 로 source 트리 연결).
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -r /tmp/requirements.txt

# 5) torch 는 PyTorch 공식 CPU 인덱스에서만 설치.
#    이 index 의 Linux wheel 은 nvidia-* 를 Requires-Dist 로 선언하지
#    않으므로 .venv 에 CPU torch 만 추가되고 CUDA 바이너리 다운로드
#    자체가 발생하지 않는다.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install \
        --index-url https://download.pytorch.org/whl/cpu \
        torch

# ---------- Stage 2: runtime ----------
FROM python:3.14-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Seoul \
    PATH="/app/gateway-backend/.venv/bin:$PATH"

# 런타임에 필요한 패키지
# - ca-certificates: 외부 LLM/admin-backend HTTPS 호출에 필요
# - tzdata: TZ=Asia/Seoul 이 실제로 KST 로 동작하려면 zoneinfo 데이터가 필요
#   (slim 이미지는 tzdata 가 기본 포함되어 있지 않다)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
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

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000","--log-level", "debug", "--proxy-headers", "--forwarded-allow-ips=*"]
