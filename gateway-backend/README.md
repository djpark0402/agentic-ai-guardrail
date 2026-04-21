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
  `gpt-*`, `o1-*`, `o3-*` → OpenAI / `ollama/모델명` → Ollama / 그 외 → Solar (기본값).
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

> **브레이킹 변경:** 이전 버전은 입력/출력 BLOCK 을 HTTP 400 + `{"detail"}`
> 으로 반환했다. HTTP 상태 코드 기반 에러 감지를 하던 클라이언트는
> `choices[0].finish_reason == "content_filter"` 또는
> `error.type == "guardrail_block"` 검사로 이행해야 한다.

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
| GET | `/health` | 헬스체크 |
| GET | `/docs` | FastAPI 기본 Swagger UI |
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

curl -X POST http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $API_KEY" \
  -H "X-Timestamp: $TS" \
  -H "X-Nonce: $NONCE" \
  -H "X-Signature: $SIG" \
  --data "$BODY"

# SKIP_HEADER_VERIFICATION=true 로 띄운 로컬 개발 서버에서 헤더 없이 호출
curl -X POST http://localhost:8000/v1/chat/completions \
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
| `uv run uvicorn app.main:app --reload` | 개발 서버 실행 |
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

## 프로젝트 구조

```
app/
├── main.py              # FastAPI 진입점 + StaticFiles 마운트
├── config.py            # pydantic-settings 기반 Settings
├── dependencies.py      # DI factory 함수
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
    └── index.html       # 플레이그라운드 페이지
tests/unit/              # pytest 단위 테스트
```

## 참고 문서
- [Solar Chat Docs](https://console.upstage.ai/docs/capabilities/generate/chat)