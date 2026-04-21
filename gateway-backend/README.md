# gateway-backend

Agentic AI Guardrail의 API Gateway. **LangChain** 기반으로 Upstage Solar(Pro) 호출을
프록시하면서 `core-secure-layer`의 보안 검증을 입·출력 양방향에 적용한다.
외부 API는 OpenAI 호환 형식(`/v1/chat/completions`)을 유지한다.

## 파이프라인

```
client → [policy fetch] → [input check] → [LLM (non-stream)] → [output check] → client
                                                                                    └ stream=true 시 SSE 재방출
```

- **Multi-provider 지원:** 모델명으로 provider를 자동 감지한다.
  `gpt-*`, `o1-*`, `o3-*`, `ft:gpt-*`, `chatgpt-*` → OpenAI /
  `ollama/모델명` → Ollama / 그 외 → Solar (기본값).
- LLM 호출은 **항상 비스트리밍**이다. 전체 응답을 받은 뒤 출력 가드레일 검사를
  먼저 수행한 다음, 사용자 응답만 선택적으로 SSE로 재방출한다.
- 입력/출력 가드레일이 BLOCK 하면 `stream` 플래그와 무관하게 **HTTP 200 +
  OpenAI `content_filter` 규격**으로 응답한다. 원본 LLM 응답은 절대 유출되지
  않고, `choices[0].finish_reason="content_filter"` + 비표준 `error` 블록에
  사유와 레이어 메타데이터가 담긴다.

#### 차단 응답 스키마

비스트리밍 (HTTP 200, `application/json`):

```json
{
  "id": "chatcmpl-<session-id>",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "solar-pro",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": ""},
    "finish_reason": "content_filter"
  }],
  "usage": null,
  "error": {
    "type": "guardrail_block",
    "stage": "input",
    "message": "입력 보안 검사 실패: prompt injection detected",
    "layer": "L1",
    "reason": "prompt injection detected",
    "severity": "CRITICAL",
    "confidence": 1.0,
    "tags": ["prompt_injection"]
  }
}
```

스트리밍 (HTTP 200, `text/event-stream`) — 단일 `chat.completion.chunk`
프레임을 내보내고 `data: [DONE]` 로 종료한다. `error` 블록 스키마는
비스트리밍과 동일.

> **브레이킹 변경:**
> 1. 이전 버전은 입력/출력 BLOCK 을 HTTP 400 + `{"detail"}` 으로 반환했다. HTTP 상태 코드 기반 에러 감지를 하던 클라이언트는 `choices[0].finish_reason == "content_filter"` 또는 `error.type == "guardrail_block"` 검사로 이행해야 한다.
> 2. **기본 포트 번호가 `8000`에서 `54081`로 변경되었다.** Docker 배포 및 로컬 실행 시 해당 포트를 사용해야 한다.

#### 가드레일 입력 범위

입력 검사는 `messages` 배열 중 **`role="user"` 메시지 본문만** 순서대로
`\n\n` 으로 이어 붙여 L1~L6 에 전달한다. 사용자가 직접 입력한 프롬프트만
검사 대상이다. 여러 user 턴이 있으면 원래 순서를 유지해 모두 포함한다.
user 메시지가 하나도 없으면 빈 문자열이 전달된다.

검사 대상이 **아닌** 항목:

- **`system` 메시지**: 시스템 프롬프트 content 자체.
- **`assistant` 메시지**: 이전 턴의 모델 응답 content 와 `tool_calls`.
- **`tool` 메시지**: 도구 호출 결과 content.
- 요청 바디의 `tools` / `tool_choice` 정의 (tool description injection).
- 멀티모달 content 의 `image_url` 등 non-text part.

> **운영 주의**: 멀티턴 공격, system 프롬프트 오염, tool 응답 오염은 현재
> 입력 가드레일이 탐지하지 않는다. 이러한 페이로드를 검사하려면 호출
> 측에서 해당 본문을 별도의 `user` 메시지로 감싸 전달해야 한다.

#### 관찰 모드 (`CONTINUE_ON_LAYER_FAILURE=true`)

데모용 대체 경로다. 이 환경변수를 `true` 로 두면 가드레일 레이어가 BLOCK 을
내려도 파이프라인을 **끝까지 실행**(LLM 호출 + 후속 레이어 + 원본 응답 전송)
하고, 응답에 레이어별 판정 내역을 담은 **`guardrail_reports` 블록**을
첨부한다. 차단 응답(`content_filter` + `error`)은 내려가지 않는다.

비스트리밍 응답 예시 (정상 200):

```json
{
  "id": "chatcmpl-<session-id>",
  "object": "chat.completion",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "안녕하세요! 무엇을 도와드릴까요?"},
    "finish_reason": "stop"
  }],
  "usage": {...},
  "guardrail_reports": {
    "mode": "observe",
    "input": [
      {"layer": "L1", "status": "block", "reason": "prompt injection pattern matched", "severity": "HIGH", "confidence": 0.91, "tags": ["prompt_injection"]},
      {"layer": "L3", "status": "pass"}
    ],
    "output": [
      {"layer": "L2", "status": "pass"}
    ]
  }
}
```

스트리밍에서도 content 는 그대로 재방출되고, 마지막 finish 프레임에 동일한
`guardrail_reports` 블록이 추가 필드로 실린다.

> 관찰 모드는 **보안 기능을 무력화**한다. 실제 운영에서는 절대 켜지 말고,
> 플레이그라운드/데모/디버깅 용도로만 사용할 것.

### 사용자 요청 헤더 검증 + 정책 조회

클라이언트는 `/v1/chat/completions` 호출 시 4개 추가 헤더를 반드시 함께
전송해야 한다.

| 헤더 | 설명 |
|---|---|
| `X-API-Key` | 사용자가 ADMIN 에게 미리 발급받은 API Key. |
| `X-Timestamp` | Unix epoch 초(ms 아님). 서버 시각과 `REQUEST_TIMESTAMP_SKEW_SEC`(기본 300초) 이상 차이가 나면 차단. |
| `X-Nonce` | 요청마다 유일한 랜덤 문자열. 재연(replay) 방지용. |
| `X-Signature` | `HMAC-SHA256(SECRET, "{timestamp}.{nonce}.{sha256(body)}")` 의 소문자 hex 64자. |

게이트웨이는 다음 순서로 요청을 처리한다.

1. **로컬 검증** — `X-Timestamp` skew 확인 후, in-memory `NonceStore` 로
   재연 여부를 확인한다. 실패 시 즉시 **HTTP 401** 응답:

   ```json
   {
     "error": {
       "type": "header_verification_failed",
       "reason": "X-Timestamp 시간차가 허용 범위(300초)를 초과했습니다"
     }
   }
   ```

2. **ADMIN 위임 검증 + 정책 조회** — `${ADMIN_BACKEND_URL}/api/v1/gateway/verify`
   로 다음 body 를 `POST` 한다. 헤더에는 게이트웨이 자신의 `ADMIN_API_KEY`
   가 `X-API-Key` 로 실린다.

   ```json
   {
     "apiKey": "<사용자 X-API-Key 그대로>",
     "timestamp": "<사용자 X-Timestamp 그대로>",
     "nonce": "<사용자 X-Nonce 그대로>",
     "bodyHash": "sha256(요청 body) hex 64자",
     "signature": "<사용자 X-Signature 그대로>"
   }
   ```

   서명 검증 자체는 ADMIN 이 수행한다. ADMIN 이 통과시키면 현재 활성
   정책(`l1Enabled`..`l6Enabled`) 을 반환하고, 게이트웨이는 그 플래그에
   따라 `core-secure-layer` L1~L6 를 선택적으로 실행한다. 4xx/5xx 가
   돌아오면 예외가 전파되어 해당 요청은 실패 처리된다.

`SKIP_HEADER_VERIFICATION=true` 로 두면 4개 헤더 검증을 건너뛴다. 이 경우
헤더가 없는 빈 문자열 값이 ADMIN 으로 전달되므로 ADMIN 이 4xx 를 낼 수
있다. 정책 조회까지 완전히 우회하려면 `SKIP_POLICY_FETCH=true` 를
함께 설정한다. 두 플래그는 독립 동작한다.

| 레이어 | 의미 |
|---|---|
| L1 | prompt injection |
| L2 | sensitive data |
| L3 | toxicity |
| L4 | hallucination |
| L5 | PII |
| L6 | compliance |

`core-secure-layer` 의 각 레이어(`L1Layer`~`L6Layer`)를
`layer_registry` 를 통해 싱글턴으로 관리하며, 아직 구현되지 않은
레이어(`NotImplementedError`)는 자동으로 PASS 처리된다.
레이어 구현이 완료되면 gateway 변경 없이 즉시 활성화된다.

admin-backend 가 응답하지 않거나 4xx/5xx 를 반환하면 예외가 전파되어 해당
요청은 실패로 처리된다.

## 엔드포인트

| Method | Path | 설명 |
|---|---|---|
| POST | `/v1/chat/completions` | OpenAI/Solar 호환 채팅 완성 (stream 지원) |
| GET | `/v1/models/default` | `.env` 의 `LLM_MODEL` 로 설정된 기본 모델명 반환 |
| GET | `/health` | 헬스체크 |
| GET | `/docs` | 커스텀 Swagger UI (상단 바 + `static/docs-overrides.css`) |
| GET | `/openapi.json` | OpenAPI 스키마 |
| GET | `/playground/` | 커스텀 API 설명 + 테스트 플레이그라운드 |

### 요청 예시

모든 요청에는 4개 검증 헤더(`X-API-Key` / `X-Timestamp` / `X-Nonce` /
`X-Signature`) 가 필요하다. 로컬에서 검증을 우회하려면
`SKIP_HEADER_VERIFICATION=true` 로 서버를 띄운다.

```bash
# 정상 경로 (검증 헤더 포함)
API_KEY="uak_xxx"
SECRET="..."                 # ADMIN 이 사용자에게 발급한 서명 시크릿
TS=$(date +%s); NONCE=$(uuidgen)
BODY='{"model":"solar-pro","messages":[{"role":"user","content":"안녕"}]}'
BODY_HASH=$(printf "%s" "$BODY" | shasum -a 256 | cut -d' ' -f1)
SIG=$(printf "%s.%s.%s" "$TS" "$NONCE" "$BODY_HASH" \
      | openssl dgst -sha256 -hmac "$SECRET" -r | cut -d' ' -f1)

curl -X POST http://localhost:54081/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $API_KEY" \
  -H "X-Timestamp: $TS" \
  -H "X-Nonce: $NONCE" \
  -H "X-Signature: $SIG" \
  --data "$BODY"

# SKIP_HEADER_VERIFICATION=true 로 띄운 로컬 개발 서버에서 헤더 없이 호출
curl -X POST http://localhost:54081/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "안녕"}]}'
```

`stream: true`로 요청하면 `text/event-stream` 응답이 반환되며,
`data: <chunk>\n\n` 형태의 프레임이 순차로 전송되고 마지막에 `data: [DONE]`이
온다. 모든 provider에서 동일하게 동작한다.

## 플레이그라운드

FastAPI 기본 Swagger UI(`/docs`)와 별개로,
`/playground/`에 가드레일 파이프라인을 설명하고 직접 테스트할 수 있는
정적 HTML 페이지를 제공한다.

- `/openapi.json`에서 스펙을 동적으로 로드하여 요청/응답 스키마 표시
- messages 행 추가·제거, `stream` 토글, SSE 청크 실시간 누적
- BLOCK 시 상태 코드와 본문을 그대로 노출

## 개발 환경 (uv)

| 명령 | 설명 |
|---|---|
| `uv sync` | 의존성 설치 |
| `uv run uvicorn app.main:app --reload --port 54081` | 개발 서버 실행 |
| `uv run pytest` | 전체 테스트 |
| `uv run pytest tests/unit/routers/test_chat_router.py -v` | 단일 파일 테스트 |
| `uv run ruff check .` | 린트 |
| `uv run ruff format .` | 포맷 |

### 환경 변수

`.env.example`를 복사하여 `.env`를 만든다. 주요 항목:

**Solar (필수)**
- `UPSTAGE_API_KEY` — Upstage Solar API 키
- `LLM_BASE_URL` — Solar 엔드포인트 (기본 `https://api.upstage.ai/v1`)
- `LLM_MODEL` — Solar 기본 모델명

**OpenAI (선택)**
- `OPENAI_API_KEY` — OpenAI API 키 (미설정 시 OpenAI 모델 요청은 에러)
- `OPENAI_BASE_URL` — OpenAI 엔드포인트 (기본 `https://api.openai.com/v1`)
- `OPENAI_MODEL` — OpenAI 기본 모델명 (기본 `gpt-4o`)

**Ollama (선택)**
- `OLLAMA_BASE_URL` — Ollama 엔드포인트 (기본 `http://localhost:11434/v1`). API 키 불필요. `ollama/모델명` 형식으로 요청.

**공통**
- `ADMIN_BACKEND_URL` — 검증·정책 조회용 admin-backend 주소
- `ADMIN_API_KEY` — admin-backend `/api/v1/gateway/verify` 호출 시 게이트웨이가 `X-API-Key` 헤더로 제시할 키. 사용자의 `X-API-Key` 와는 별개 (기본 빈 값 = 헤더 미전송)
- `REQUEST_TIMESTAMP_SKEW_SEC` — `X-Timestamp` 허용 오차(초). 기본 `300` (5분)
- `SKIP_HEADER_VERIFICATION` — `true`로 설정하면 사용자 4개 헤더 검증을 건너뛴다. 로컬·데모용이며 `SKIP_POLICY_FETCH` 와 독립 동작 (기본 `false`)
- `SKIP_POLICY_FETCH` — `true`로 설정하면 admin-backend 정책 조회를 생략하고 **L1~L6 전체 레이어를 강제 실행**. admin-backend 없이 로컬 풀 파이프라인을 검증할 때 사용 (기본 `false`)
- `CONTINUE_ON_LAYER_FAILURE` — `true`로 설정하면 가드레일이 BLOCK 을 내려도 파이프라인을 끝까지 실행하고 응답에 `guardrail_reports` 블록을 첨부한다(**관찰 모드**, 위 섹션 참고). 데모·디버깅 전용이며 운영에서는 사용 금지 (기본 `false`)

> `.env` 파일은 **절대 커밋하지 않는다.** 새 환경 변수가 필요하면
> `.env.example`에 먼저 추가한다.

## Docker 배포

팀 개발 서버(Linux x86_64, CPU 추론) 배포용 구성 파일이 포함되어 있다.
로컬 macOS 환경과 어긋나지 않도록 `pyproject.toml` / `uv.lock` 은 손대지
않고 Docker 레이어만으로 배포 차이를 흡수한다.

### 포함 파일

| 파일 | 역할 |
|---|---|
| `Dockerfile` | Python 3.14-slim-bookworm 기반 multi-stage 빌드. `uv export --frozen --prune torch` 로 `uv.lock` 에서 torch·nvidia-\*/triton 을 dep graph 기준으로 제거한 `requirements.txt` 를 만들어 non-torch 의존성을 설치하고, `torch` 는 PyTorch 공식 CPU 인덱스에서 별도 설치한다 (CUDA 바이너리·nvidia-\* 이미지 미포함). `core-secure-layer` 는 editable path-dep 으로 설치되어 `layers/l*/model/*` 의 모델 파일 (~7.2GB) 을 source 트리에서 그대로 로드한다. 비-root `appuser` 로 기동. |
| `Dockerfile.dockerignore` | BuildKit 의 Dockerfile 전용 ignore. 빌드 컨텍스트(monorepo 루트) 에서 `admin-backend/`, `admin-frontend/`, `docs/`, `.venv/`, `.git`, `.env`, `tests/`, `*.egg-info` 등을 제외한다. |
| `docker-compose.yml` | `context: ..` 로 monorepo 루트를 빌드 컨텍스트로 잡고, `platform: linux/amd64` 고정. `env_file: .env`, `extra_hosts: host.docker.internal:host-gateway`, `start_period: 300s` (모델 로드 유예). |

### 아키텍처 / 런타임 특성

- **빌드 컨텍스트**: `gateway-backend/` 단독이 아니라 `agentic-ai-guardrail/`
  (monorepo 루트). `core-secure-layer/` 를 함께 포함해야 editable path-dep
  (`../core-secure-layer`) 이 컨테이너 안에서 `/app/core-secure-layer` 로
  resolve 된다.
- **플랫폼**: 맥북 Apple Silicon 에서 빌드해도 `linux/amd64` 이미지가 나오도록
  compose 에 플랫폼을 고정. 개발 서버(x86) 에서는 native 빌드가 수행된다.
- **CPU / GPU**: 빌드 단계에서 `torch` 를 PyTorch 공식 CPU 인덱스
  (`https://download.pytorch.org/whl/cpu`) 에서만 설치하고, `uv export
  --prune torch` 로 `uv.lock` 의 nvidia-\*/triton 런타임 의존성을 dep graph
  기준으로 제거한다. 결과적으로 이미지에 CUDA 바이너리가 포함되지 않는다.
  `pyproject.toml` / `uv.lock` 은 수정하지 않아 로컬 macOS 개발 환경과 완전히
  분리되어 있다 (배포 전용 오버라이드는 Dockerfile 안에만 존재). 런타임에는
  transformers / sentence-transformers 가 device 자동 선택으로 CPU 추론.
- **모델 로드 시점**: `app/services/layer_registry.py` 가 import 될 때 L1~L6
  싱글턴이 즉시 인스턴스화된다 → uvicorn 이 `"Application startup complete"`
  를 찍는 시점에는 이미 모델 로드가 끝난 상태. 초기 로드는 1~3분 소요.

### 배포 절차 (개발 서버에서 수행)

```bash
# 1) 레포 clone / 갱신 후 gateway-backend 로 진입
cd agentic-ai-guardrail/gateway-backend

# 2) .env 준비 — .env.example 를 복사해 값 채움
cp .env.example .env
$EDITOR .env
#  - 필수: LLM_MODEL, UPSTAGE_API_KEY
#  - admin-backend 가 호스트 프로세스면
#      ADMIN_BACKEND_URL=http://host.docker.internal:8001
#    admin-backend 를 같은 compose 네트워크로 띄우면
#      ADMIN_BACKEND_URL=http://admin-backend:8001

# 3) 이미지 빌드 (x86 native 이면 QEMU 없이 바로 빌드됨)
docker compose build

# 4) 기동 (백그라운드)
docker compose up -d

# 5) 모델 로드 진행 상황 모니터링 (1~3분)
docker compose logs -f gateway-backend
#  -> "Application startup complete" 확인

# 6) 헬스체크
curl -fsS http://localhost:54081/health
#  -> {"status":"ok"}
curl -fsS http://localhost:54081/v1/models/default
#  -> {"default_model":"..."}

# 7) Docker healthcheck 상태
docker inspect --format='{{json .State.Health}}' gateway-backend \
  | python3 -m json.tool

# 8) 중지 / 재시작
docker compose stop     # 정지
docker compose up -d    # 재기동
docker compose down     # 컨테이너 제거 (이미지·네트워크는 유지)
```

### 주의사항

- **`core-secure-layer` 를 볼륨 마운트로 덮지 말 것.** editable install 의
  `.pth` 가 `/app/core-secure-layer` 절대경로를 가리키고 있어, 호스트 경로로
  마운트하면 모델/vectordb 리소스가 사라지고 `ModuleNotFoundError` 혹은
  모델 로드 실패가 발생한다.
- **`.env` 는 이미지에 들어가지 않는다.** `Dockerfile.dockerignore` 에서
  명시적으로 제외하고 compose 의 `env_file` 로 런타임에 주입한다. 새 키가
  필요하면 `.env.example` 에 먼저 추가.
- **로컬 macOS 에서 실제 이미지 빌드는 비권장**: `linux/amd64` QEMU 에뮬레이션
  으로 1~2시간 이상 소요될 수 있다. 구문 검증은 `docker compose config`
  (단, `.env` 값이 표준 출력으로 노출되므로 `--no-interpolate` 사용 권장)
  + `docker buildx build --check` 로 충분하며, 실제 빌드는 개발 서버 native
  에서 수행한다.
- **첫 기동이 5분 이상 걸리면 `start_period` 확장**: 디스크 I/O 가 느린
  환경에서는 `docker-compose.yml` 의 `start_period: 300s` 를 `600s` 로 늘려
  healthcheck 가 unhealthy 로 떨어지는 것을 방지한다.

### 트러블슈팅

| 증상 | 진단 포인트 |
|---|---|
| 기동 로그에 `core_secure_layer.layers.l*` import 오류 | editable 설치가 깨진 상태. `.dockerignore` 가 `core-secure-layer/` 의 모델 디렉토리를 제외하지 않는지 재확인. |
| `모델 로드 실패` 워닝만 나오고 요청은 동작 | fail-open 설계 동작. 해당 레이어만 비활성. 로그에서 구체적인 레이어·경로 확인 후 이미지에 모델 파일이 복사됐는지 (`docker exec gateway-backend ls /app/core-secure-layer/core_secure_layer/layers/l4/model`) 점검. |
| 컨테이너가 healthcheck 로 `unhealthy` 되어 재시작 반복 | 모델 로드가 `start_period` 를 초과. `docker compose logs` 로 실제 로드 시간 확인 후 `start_period` 상향. |
| admin-backend 연결 실패 (`policy_service` 로그) | `ADMIN_BACKEND_URL` 값 확인. `docker exec gateway-backend python -c "import urllib.request; print(urllib.request.urlopen('$ADMIN_BACKEND_URL/health').status)"` 로 도달성 점검. 호스트 프로세스인 경우 admin-backend 가 `0.0.0.0` 에 바인딩돼 있어야 한다. |
| CUDA / `libcu*` / `nvidia-*` 관련 경고 또는 오류 | CPU-only `torch` wheel 만 설치되어 CUDA 런타임 로드 경로 자체가 없어야 정상. 만약 빌드 로그에서 `Downloading nvidia-*` / `Downloading triton` 이 다시 보이면 이미지 캐시에 이전 빌드가 재사용됐을 가능성 → `docker builder prune -f --filter "label=com.docker.compose.project=gateway-backend"` 후 재빌드. transformers 가 단순 probe 차원에서 찍는 CUDA 관련 info 메시지는 무해. |

## 프로젝트 구조

```
app/
├── main.py              # FastAPI 진입점 + 커스텀 /docs + StaticFiles 마운트
├── config.py            # pydantic-settings 기반 Settings
├── dependencies.py      # DI factory 함수
├── errors.py            # 업스트림(Solar/admin/LangChain) 예외 → JSON 매퍼
├── models/              # Pydantic 모델 (chat, guardrail, policy)
├── routers/
│   └── chat.py          # /v1/chat/completions 가드레일 파이프라인
├── services/
│   ├── llm_service.py         # 범용 LLM 서비스 (LangChain ChatOpenAI 기반)
│   ├── solar_service.py       # Solar 전용 래퍼 (LLMService 상속)
│   ├── provider_router.py     # 모델명 기반 provider 자동 라우팅
│   ├── security_layer_service.py  # core-secure-layer 연동 보안 검사
│   ├── layer_registry.py      # policy index → core layer 싱글턴 매핑
│   ├── guardrail_converter.py # gateway ↔ core 타입 변환
│   ├── request_verifier.py    # 사용자 헤더·timestamp·nonce·bodyHash 검증
│   └── policy_service.py      # ADMIN /api/v1/gateway/verify 위임 호출
└── static/
    ├── index.html       # 플레이그라운드 페이지
    └── docs-overrides.css  # /docs 커스텀 Swagger UI 스타일
tests/unit/              # pytest 단위 테스트
```

## 참고 문서
- [Solar Chat Docs](https://console.upstage.ai/docs/capabilities/generate/chat)