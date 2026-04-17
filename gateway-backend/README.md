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
- 출력이 BLOCK되면 비스트리밍은 HTTP 400, 스트리밍은 에러 프레임 1건만 전송하여
  원본 응답이 클라이언트로 유출되지 않도록 한다.

### 정책 조회 & 레이어 게이팅

요청마다 `${ADMIN_BACKEND_URL}/api/v1/policies/active` 를 `GET` 으로 호출하여
현재 활성 정책을 가져오고, 응답의 `l1Enabled`..`l6Enabled` 플래그에 따라
`core-secure-layer` 가 해당 레이어(L1~L6)에 대해서만 검사를 수행한다.

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

```bash
# Solar (기본값 — 접두사 불필요)
curl -X POST http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model": "solar-pro", "messages": [{"role": "user", "content": "안녕"}]}'

# OpenAI (모델명 자동 감지)
curl -X POST http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "안녕"}]}'

# Ollama (ollama/ 접두사 명시)
curl -X POST http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model": "ollama/gemma3:12b", "messages": [{"role": "user", "content": "안녕"}]}'
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
- `ADMIN_BACKEND_URL` — 정책 조회용 admin-backend 주소
- `SKIP_POLICY_FETCH` — `true`로 설정하면 admin-backend 정책 조회를 생략하고 **L1~L6 전체 레이어를 강제 실행**. admin-backend 없이 로컬 풀 파이프라인을 검증할 때 사용 (기본 `false`)

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
│   └── policy_service.py
└── static/
    └── index.html       # 플레이그라운드 페이지
tests/unit/              # pytest 단위 테스트
```

## 참고 문서
- [Solar Chat Docs](https://console.upstage.ai/docs/capabilities/generate/chat)