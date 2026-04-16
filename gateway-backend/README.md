# gateway-backend

Agentic AI Guardrail의 API Gateway. Upstage Solar(Pro) 호출을 프록시하면서
`core-secure-layer`의 보안 검증을 입·출력 양방향에 적용한다.

## 파이프라인

```
client → [policy fetch] → [input check] → [LLM (non-stream)] → [output check] → client
                                                                                    └ stream=true 시 SSE 재방출
```

- LLM 호출은 **항상 비스트리밍**이다. 전체 응답을 받은 뒤 출력 가드레일 검사를
  먼저 수행한 다음, 사용자 응답만 선택적으로 SSE로 재방출한다.
- 출력이 BLOCK되면 비스트리밍은 HTTP 400, 스트리밍은
  `finish_reason=content_filter` 를 단 chunk 한 건만 전송하여 원본 응답이
  클라이언트로 유출되지 않도록 한다.
- TTFB 주의: 출력 선검증 때문에 `stream=true` 여도 LLM 전체 생성이 끝나야
  첫 chunk 가 나간다. 사용자 스트리밍은 UX용 재방출이며 지연 단축 효과는
  없다.

### OpenAI 호환성

- 요청 바디는 OpenAI Chat Completions 파라미터를 선언적으로 수용한다.
  `temperature`, `top_p`, `max_tokens`, `n`, `stop`, `presence_penalty`,
  `frequency_penalty`, `seed`, `response_format`, `tools`, `tool_choice`,
  `user` 가 Solar 호출로 그대로 pass-through 된다.
- Solar 전용 필드(`reasoning_effort` 등)는 OpenAI SDK 가 unknown kwarg 로
  거절하는 것을 막기 위해 `extra_body` 로 감싸 전달된다.
- 응답은 Solar 원본 completion 의 `created`/`model`/`finish_reason`/
  `usage`/`tool_calls` 를 그대로 노출한다. 가드레일 세션 추적을 위해 `id`
  만 `chatcmpl-<session_id>` 로 재할당한다.
- `messages` 는 `content: str | list[dict] | None` 유니온을 허용하여
  multimodal content 와 tool/function 메시지를 지원한다.

### 정책 조회 & 레이어 게이팅

요청마다 `${ADMIN_BACKEND_URL}/api/v1/policies/active` 를 `GET` 으로 호출하여
현재 활성 정책을 가져오고, 응답의 `l0Enabled`..`l5Enabled` 플래그에 따라
security-layer 가 해당 레이어(L0~L5)에 대해서만 프롬프트 검사를 수행한다.

| 레이어 | 의미 |
|---|---|
| L0 | prompt injection |
| L1 | sensitive data |
| L2 | toxicity |
| L3 | hallucination |
| L4 | PII |
| L5 | compliance |

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

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "solar-pro2",
    "messages": [{"role": "user", "content": "안녕"}],
    "temperature": 0.2,
    "stream": false
  }'
```

`stream: true` 로 요청하면 `text/event-stream` 응답이 반환된다. 각 프레임은
OpenAI `chat.completion.chunk` JSON 이며 `data: {...}\n\n` 형태로 순차
전송되고 마지막에 `data: [DONE]` 마커가 붙는다.

```
data: {"id":"chatcmpl-<uuid>","object":"chat.completion.chunk","created":...,
       "model":"solar-pro2","choices":[{"index":0,"delta":{"role":"assistant"},
       "finish_reason":null}]}

data: {"id":"chatcmpl-<uuid>","object":"chat.completion.chunk","created":...,
       "model":"solar-pro2","choices":[{"index":0,"delta":{"content":"안녕"},
       "finish_reason":null}]}

...

data: {"id":"chatcmpl-<uuid>","object":"chat.completion.chunk","created":...,
       "model":"solar-pro2","choices":[{"index":0,"delta":{},
       "finish_reason":"stop"}]}

data: [DONE]
```

출력 가드레일 BLOCK 시에는 content delta 대신 `finish_reason=content_filter`
를 단 chunk 1건과 비표준 `error` 블록(`type: guardrail_block`)이 방출되며
원본 응답은 포함되지 않는다.

OpenAI 공식 Python SDK 로도 `base_url` 만 게이트웨이로 바꾸면 동일하게
동작한다:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key="dummy")
stream = client.chat.completions.create(
    model="solar-pro2",
    messages=[{"role": "user", "content": "안녕"}],
    stream=True,
)
for chunk in stream:
    print(chunk.choices[0].delta.content or "", end="", flush=True)
```

## 플레이그라운드

FastAPI 기본 Swagger UI(`/docs`)와 별개로,
`/playground/`에 가드레일 파이프라인을 설명하고 직접 테스트할 수 있는
정적 HTML 페이지를 제공한다.

- `/openapi.json`에서 스펙을 동적으로 로드하여 요청/응답 스키마 표시
- messages 행 추가·제거, `stream` 토글, SSE `chat.completion.chunk` JSON 을
  파싱해 `delta.content` 를 실시간 누적
- BLOCK 시 상태 코드와 본문, 가드레일 `error` 블록을 꼬리에 함께 노출

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

- `UPSTAGE_API_KEY` — Upstage Solar API 키
- `LLM_BASE_URL` — Solar 엔드포인트 (기본 `https://api.upstage.ai/v1`)
- `LLM_MODEL` — 사용할 모델 (기본 `solar-pro2`)
- `ADMIN_BACKEND_URL` — 정책 조회용 admin-backend 주소

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
│   ├── solar_service.py       # Upstage Solar 클라이언트 (non-stream only)
│   ├── security_layer_service.py
│   └── policy_service.py
└── static/
    └── index.html       # 플레이그라운드 페이지
tests/unit/              # pytest 단위 테스트
```

## 개발 규칙

- **TDD 필수**: RED → GREEN → REFACTOR → COMMIT
- **커밋 단위**: 하나의 논리적 변경, 구조 변경과 동작 변경을 분리
- **커밋 메시지**: 한글로 작성, `feat:` / `fix:` / `refactor:` / `test:` / `docs:` / `chore:`
- **Docstring**: Google 스타일, 라인 길이 80자, 모든 시그니처에 타입 힌트
- **주석**: 가능한 한 한글 (docstring 섹션 키워드는 영문 유지)


## 참고 문서
- [Solar Chat Docs](https://console.upstage.ai/docs/capabilities/generate/chat)
