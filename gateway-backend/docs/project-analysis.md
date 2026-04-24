# gateway-backend 프로젝트 분석

> 작성일: 2026-04-16
> 대상 브랜치: `gateway`
> 범위: `gateway-backend/` 디렉터리 로컬 소스만 기준 (외부 advisor 미사용)

## 1. 프로젝트 목적 요약

OpenAI 호환 `chat/completions` 요청을 받아 다음 파이프라인을 거쳐 Upstage Solar
API에 프록시하는 가드레일 데모 게이트웨이이다.

```
client → [verify + policy fetch] → [input guardrail] → [Solar non-stream]
       → [output guardrail] → client (JSON or SSE)
```

- 정책은 `admin-backend`의 `/api/v1/gateway/verify`에서 레이어별 플래그(L1~L6)와 L5 전용 `l5Setting`으로 수신
- 활성 레이어만 순차적으로 입력/출력 검사
- L5 는 `l5Setting.model` 을 모델 폴더명으로, `l5Setting.threshold` 를 NER score 컷오프로 적용
- LLM 호출은 **항상 non-stream**으로 수행하고, `stream=true`는 검증이 끝난 뒤
  내부에서 청크를 만들어 SSE로 재방출 — 유출 방지 목적

## 2. 구현 현황 매핑

| 책임 | 구현 파일 | 상태 |
|---|---|---|
| 엔트리포인트 / CORS / lifespan | `app/main.py` | OK |
| 환경 설정 (Settings) | `app/config.py` | OK |
| DI 팩토리 | `app/dependencies.py` | OK |
| Chat 파이프라인 | `app/routers/chat.py` | OK (핵심 로직 분리 양호) |
| Solar 클라이언트 | `app/services/solar_service.py` | 실연동 (AsyncOpenAI) |
| 정책 조회 | `app/services/policy_service.py` | 실연동 (httpx) |
| 보안 레이어 실행 | `app/services/security_layer_service.py` | core-secure-layer 실연동 |
| 요청/응답 모델 | `app/models/chat.py`, `guardrail.py`, `policy.py` | OK |
| 플레이그라운드 | `app/static/index.html` | 제공 |
| 단위 테스트 | `tests/unit/**` (9개 파일) | OK |

## 3. 목적 충족도 평가

### 3.1 충족되는 항목
- **OpenAI 호환 표면**: `ChatRequest`가 `extra="allow"`라 추가 필드 수신 가능,
  응답 모델은 `id/object/created/model/choices` 구조로 OpenAI와 호환.
- **파이프라인 순서**: 정책 → 입력검사 → LLM → 출력검사 → 응답의 순서가
  `chat_completions`에 명확히 구현되어 있음.
- **스트리밍 유출 방지**: `stream=true`에서도 LLM을 non-stream으로 호출하고,
  출력 BLOCK 시 원본을 버린 뒤 에러 프레임 1건만 내보내도록 설계(`_stream_error`).
  데모 수준의 가드레일 요구를 올바르게 반영.
- **레이어 게이팅**: `GuardrailPolicy.enabled_layers()`로 활성 레이어 리스트를
  만들어 `SecurityLayerService`가 순차 실행 → BLOCK 시 즉시 단락(short-circuit).
- **DI 구조**: 테스트에서 서비스 대체가 쉬운 FastAPI Depends 기반 구조.
- **에러 핸들링**: `openai.APIError`를 502로 매핑하는 전역 핸들러 존재.
- **테스트 커버리지**: 모델/서비스/라우터/health/cors 각 레이어에 단위 테스트가
  존재하여 TDD 규칙과 일관.

### 3.2 의도된 한계 (데모 수준)
- L5 모델 선택은 ADMIN 의 `l5Setting.model` 이 실제 배포된
  `core-secure-layer/layers/l5/model/<model>` 폴더명과 일치해야 한다.
  경로가 틀리면 core L5 의 fail-open 정책에 따라 NER 단계가 no-op 이 될 수 있다.
- 관측/감사 로그는 logging 한 줄 수준이며, 감사 추적(감사로그 저장소)은 없음.
- 인증/레이트 리미팅은 없음 — README에 "사내망 가정"이라고 명시.

## 4. 보완 권고 사항

### 4.1 파이프라인 정합성 / 기능
1. **Solar 응답의 None content 대응 누락**
   `solar_service.chat()`은 `response.choices[0].message.content`를 그대로
   반환한다. OpenAI/Solar 스펙상 content가 `None`(예: function/tool call 응답
   경로)일 수 있어, 이후 `check_output(content=...)`에서
   `len(content)` 계산이 `TypeError`를 유발할 수 있다. `content or ""`로
   정규화하고, 빈 응답/툴콜 응답 처리 정책을 결정해야 한다.

2. **messages 필드가 OpenAI 스펙의 부분만 수용**
   `Message.content: str`로 고정되어 있어, OpenAI가 허용하는
   multimodal content(`list[ContentPart]`) 또는 tool/function role
   메시지를 거부한다. "OpenAI 호환"을 자칭한다면 최소한
   `content: str | list[dict]` 유니온 허용 + role 확장 처리 필요.

3. **stream 응답 포맷이 OpenAI SSE 규격과 다름**
   OpenAI 호환 SSE는 `data: {JSON chunk}\n\n` 형식(각 청크가 `chat.completion.chunk`
   객체)인 반면, 현재는 `data: <raw text>\n\n`으로 내보낸다. OpenAI SDK
   클라이언트는 이를 파싱하지 못한다. 호환성을 원하면 `chat.completion.chunk`
   스키마로 감싸야 한다.

4. **`extra="allow"` 필드가 Solar로 전달되지 않음**
   라우터에서 `api_messages`를 `role/content`만 뽑아 재조립하고,
   `temperature`/`top_p`/`max_tokens`/`tools` 등은 버려진다.
   요청 본문의 추가 파라미터를 Solar에 pass-through 해야 실질적 프록시가 된다.

5. **입력 검사가 메시지 역할을 구분하지 않음**
   system 메시지까지 동일하게 검사 대상에 포함된다. 실제 prompt injection/
   sensitive data 검사가 들어가면, 사용자 메시지만 검사해야 하는 레이어와
   전체를 검사할 레이어가 달라질 수 있으므로 레이어별 스코프 정의가 필요하다.

### 4.2 가드레일 설계
6. **출력 BLOCK 사유 노출 수준 검토**
   `_stream_error`와 400 응답이 `reason`을 그대로 노출한다. 실서비스 전환 시
   사유 일부는 내부 로그로만 남기고 사용자에게는 일반화된 문구를 주는 정책이
   필요하다.

7. **감사 로그/이벤트 훅 없음**
   어떤 레이어가 어떤 이유로 BLOCK 했는지 외부 저장소(관제/감사 파이프라인)로
   송출하는 훅이 없다. `SecurityLayerService`에 결과 이벤트 콜백이나
   OpenTelemetry span을 덧붙여두면 core_secure_layer 실연동 시 바로 활용 가능.

8. **정책 캐싱 없음**
   매 요청마다 `admin-backend`를 HTTP 호출한다. 타임아웃 5초, 실패 시 예외
   전파 구조는 단일 장애점을 만든다. 짧은 TTL 캐시 + stale-on-error fallback
   정책을 추가하면 가용성과 지연이 모두 개선된다.

9. **레이어 실행 병렬화 가능성**
   현재는 순차 실행 + 첫 BLOCK에서 단락. 대부분의 실 가드레일 백엔드는 I/O
   bound이므로 `asyncio.gather` + 조기취소 패턴으로 꼬리 레이턴시를 줄일 수
   있다. 다만 단락 우선순위 결정 요건이 있으면 순차가 맞을 수 있음.

### 4.3 운영·보안
10. **CORS 전 허용**
    `allow_origins=["*"]`가 디폴트로 박혀 있어, "사내망 가정" 주석에도 불구하고
    실수로 공개 배포 시 그대로 노출될 위험. 환경변수로 화이트리스트를 주입해
    기본값을 안전한 값으로 두는 것을 권장.

11. **인증/레이트리밋 부재**
    API 키/서비스 토큰 검증과 사용자/IP 단위 쿼터가 없다. 데모여도
    `X-Api-Key` 검증 미들웨어 훅 정도는 자리를 잡아두면 추후 확장 비용이 낮다.

12. **`httpx.AsyncClient` 설정 최소화**
    `dependencies.get_http_client()`가 기본 설정으로 생성된다. 타임아웃/
    커넥션 풀/재시도 정책을 `Settings`로 주입하고, admin-backend 전용 client와
    LLM 전용 client를 분리하면 외부 의존 특성이 달라질 때 독립 조정이 가능하다.

13. **Solar content None에 대한 응답 타입 타이트닝**
    `SolarService.chat` 반환 타입이 `str`이지만 실제로는 `str | None`이다.
    타입 안전성을 위해 반환 전에 단언 또는 정규화가 필요하다 (위 1번과 연계).

14. **`/playground/` 정적 페이지 노출 경계**
    내부망 가정이면 무해하지만, 배포 환경별로 마운트를 환경변수 플래그로
    토글할 수 있게 해두면 운영 시 공격 표면을 줄일 수 있다.

### 4.4 코드 품질 / 유지보수
15. **`session_id` 로그 전파 불일치**
    정책 조회 시에만 `session_id`가 로그에 들어가고, 입력/출력 검사
    로그에는 전파되지 않는다. `contextvars`나 로거 어댑터로 session_id를
    모든 단계에 주입하면 관제에서 한 요청을 선형적으로 추적할 수 있다.

16. **`Message.role`이 문자열**
    `Literal["system","user","assistant","tool"]`로 좁히면 검증과 IDE 지원이
    모두 개선된다.

17. **`GuardrailResult.layer`가 문자열**
    `layer_idx: int`를 다루는 코드와 타입이 불일치. `Literal[0..5]` 또는
    전용 Enum을 두는 편이 자기문서화에 좋다.

18. **예외 → HTTP 매핑이 admin-backend/httpx에는 없음**
    `policy_service`가 `httpx.HTTPError`를 그대로 전파하므로, 클라이언트는
    FastAPI 기본 500을 받게 된다. 전역 핸들러를 추가해 503/502로 사상하는 것이
    UX와 관제 모두에 유리.

19. **스트리밍 보조 함수 테스트 보강 필요**
    `_stream_content` / `_stream_error` / `_chunk_content`에 대한 단위 테스트
    보강 여부를 확인(현재 `test_chat_router.py` 수준). 스트리밍 경로는
    회귀가 쉬운 영역이므로 전용 테스트를 반드시 유지.

## 5. 우선순위 제안

| 우선순위 | 항목 |
|---|---|
| P0 (정합성/호환성) | 1 Solar content None 방어, 3 SSE 청크 OpenAI 스키마 준수, 4 추가 파라미터 pass-through |
| P1 (가드레일 신뢰성) | 7 감사 훅 설계, 8 정책 캐싱+stale fallback, 6 사유 노출 정책 |
| P2 (운영 안전) | 10 CORS 화이트리스트 기본값, 11 인증/레이트리밋 자리 확보, 18 httpx 예외 매핑 |
| P3 (품질/관측) | 15 session_id 로그 전파, 16-17 타입 강화, 2 multimodal content 모델 확장 |

## 6. 종합 결론

현재 구현은 **데모 목적으로는 목적을 충분히 달성**한다.
- 파이프라인 순서와 "LLM 응답을 사용자에게 주기 전에 반드시 출력 검사를 선행"
  이라는 핵심 원칙이 스트리밍/비스트리밍 모두에서 지켜진다.
- 레이어 게이팅 구조가 명확해, `core_secure_layer` 실연동 시 단일 훅
  (`_run_layer_input/output`) 교체만으로 기능이 확장 가능하다.
- 그러나 "OpenAI 호환"을 내세운다면 SSE 포맷과 요청 파라미터 pass-through가
  부족하고, 실 가드레일을 붙이기 전에 감사·캐싱·사유노출 정책 3종 세트를
  정리해두면 실서비스 전환 비용이 크게 줄어든다.

위 P0 3건을 우선 처리하면 "OpenAI 호환 가드레일 프록시"라는 슬로건을
코드가 온전히 뒷받침할 수 있다.
