# llm_judge: LLM 기반 보강 판정 레이어

## 1. 목적

L1~L6 의 휴리스틱(인코딩·perplexity·벡터 시그니처·OWASP NLI/RAG·PII·Safety 모델) 검사를 모두 통과한 입력에 대해, **운영자가 직접 주입한 system_prompt** 와 단일 LLM 호출로 통합 보강 판정을 수행한다. L1~L6 가 잡지 못한 도메인 특화·문맥 의존 위협에 대한 마지막 방어선이며, 동시에 운영자가 프롬프트만 갱신해도 정책을 빠르게 조정할 수 있는 유연성을 제공한다.

기존 L1~L8 은 가드레일 카테고리별 휴리스틱 슬롯이지만, 이 레이어는 **L 번호를 부여하지 않는 별도 카테고리** 로 두어 향후 L7/L8 가 채워지는 것과 충돌하지 않도록 한다.

## 판정 원칙

> **미탐(false negative)은 허용, 오탐(false positive)은 절대 불허.**
>
> LLM 응답 실패·파싱 실패·클라이언트 미초기화 → 모두 fail-open(`allowed=True`).
> 정상 문장을 차단하는 것은 절대 안 된다.

이 원칙은 core-secure-layer 의 글로벌 원칙과 동일하며, llm_judge 는 휴리스틱이 모두 PASS 한 뒤의 추가 검사이므로 fail-open 시에도 시스템 전체로는 L1~L6 의 PASS 판단을 그대로 따른다.

## 2. 판정 기준

런타임 흐름:

```
LayerResult (L1~L6 모두 allowed=True)
    │
    ▼
[오케스트레이터 가드: 이전 결과 모두 PASS 인가?]
    │  No  → llm_judge 호출 생략 (전 단계 BLOCK 결과 그대로 사용)
    │  Yes
    ▼
[1] system_prompt = (호출자 주입 본문) + (시스템이 append 하는 JSON 출력 instruction)
[2] human_message = user_input
[3] await llm.ainvoke([SystemMessage, HumanMessage])
    │
    ▼
[4] 응답을 Pydantic JudgeOutput 으로 파싱
    │  파싱 실패 → fail-open(allowed=True)
    │  성공
    ▼
[5] LayerResult 매핑
    - allowed       ← JudgeOutput.allowed
    - reason        ← JudgeOutput.reason  (allowed=True 면 빈 문자열)
    - severity      ← JudgeOutput.severity → Severity enum
    - tags          ← JudgeOutput.categories
    - confidence    ← clamp(JudgeOutput.confidence, 0.0, 1.0)
```

### 차단/허용 결정

LLM 이 반환한 `allowed` 가 `False` 이고 파싱이 성공한 경우에만 차단한다. 그 외는 모두 PASS:

| 상황 | 결과 |
|---|---|
| LLM 이 `allowed=true` 응답 | `LayerResult(allowed=True)` |
| LLM 이 `allowed=false` 응답 + 파싱 성공 | `LayerResult(allowed=False, reason, severity, tags=categories)` |
| LLM 호출 자체 예외 (timeout, 네트워크, key 오류 등) | fail-open `LayerResult(allowed=True)` |
| 응답이 JSON 으로 파싱 안 됨 | fail-open `LayerResult(allowed=True)` |
| Pydantic 검증 실패 (필드 누락/타입 불일치) | fail-open `LayerResult(allowed=True)` |
| 클라이언트(`llm`)가 `None` | fail-open `LayerResult(allowed=True)` |

오탐 절대 불허 원칙에 따라 **차단은 LLM 이 명시적으로 `allowed=false` 를 응답한 경우에만** 발생한다.

## 3. 입력 / 출력

### LlmJudgeLayer 초기화

```python
from langchain_core.language_models import BaseChatModel
from core_secure_layer.layers.llm_judge.llm_judge import LlmJudgeLayer

layer = LlmJudgeLayer(
    llm=solar_chat_model,                  # LangChain BaseChatModel (Solar/OpenAI 호환)
    system_prompt=OPERATOR_SYSTEM_PROMPT,   # 운영자가 직접 주입하는 정책 본문
    layer_id="llm_judge",                   # LayerResult.name
)
```

| 파라미터 | 타입 | 기본값 | 설명 |
|---|---|---|---|
| `llm` | `BaseChatModel \| None` | `None` | LangChain 채팅 모델. None 이면 모든 호출 fail-open |
| `system_prompt` | `str` | (필수) | 운영자가 직접 작성한 정책/판단 기준 본문. 출력 형식 instruction 은 시스템이 자동 append |
| `layer_id` | `str` | `"llm_judge"` | `LayerResult.name` 으로 사용 |

### 입력: `GuardrailRequest`

| 필드 | 사용 | 비고 |
|---|---|---|
| `user_input` | LLM `HumanMessage` 본문 | 그대로 전달 |
| `session_id` | (현재 미사용) | 향후 멀티턴 컨텍스트 확장 여지 |
| `metadata` | (현재 미사용) | 향후 LLM 컨텍스트 hint 로 확장 가능 |

### 출력: `LayerResult`

| 필드 | 값 |
|---|---|
| `name` | `layer_id` (기본 `"llm_judge"`) |
| `allowed` | LLM `allowed` 값. 파싱/예외 실패 시 항상 `True` |
| `reason` | LLM `reason`. `allowed=True` 면 빈 문자열 |
| `severity` | `JudgeOutput.severity` 문자열 → `Severity` enum 매핑. 알 수 없으면 `Severity.NONE` |
| `confidence` | `JudgeOutput.confidence` 를 `[0.0, 1.0]` 으로 클램프. 누락 시 `0.0` |
| `tags` | `JudgeOutput.categories` 그대로. 빈 리스트 허용 |
| `execution_time_ms` | `BaseLayer.check()` 가 자동 측정 |

### LLM 응답 schema (Pydantic `JudgeOutput`)

```json
{
  "allowed": true,
  "reason": "",
  "severity": "none",
  "categories": [],
  "confidence": 0.95
}
```

```python
class JudgeOutput(BaseModel):
    allowed: bool
    reason: str = ""
    severity: str = "none"          # "none" | "low" | "medium" | "high" | "critical"
    categories: list[str] = []      # LLM 자유 분류 (e.g. ["jailbreak", "pii_leak"])
    confidence: float = 0.0         # 0.0~1.0
```

`severity` 문자열은 `Severity` enum 값(`none`/`low`/`medium`/`high`/`critical`) 과 1:1 대응. 알 수 없는 값은 `Severity.NONE` 으로 디그레이드(fail-open 일관성).

### 시스템이 append 하는 출력 형식 instruction

운영자 prompt 본문 끝에 다음을 자동 append 한다:

```
You MUST respond with a single JSON object on one line, with these exact fields:
{"allowed": <bool>, "reason": <string>, "severity": "none|low|medium|high|critical", "categories": [<string>...], "confidence": <number 0~1>}
Do NOT include any text outside of the JSON.
```

이로써 운영자는 정책 본문에만 집중하면 되고, 출력 형식 일탈 위험은 시스템이 책임진다.

## 4. 엣지 케이스

| 케이스 | 동작 |
|---|---|
| 빈 `user_input` | 그대로 LLM 에 전달. LLM 이 의미 없는 질의로 처리. 대부분 `allowed=true` 응답 |
| 매우 긴 `user_input` | LangChain/LLM 의 토큰 제한에 의존. 초과 시 LLM 이 예외 발생 → fail-open |
| LLM 응답이 JSON 코드 블록(```json … ```) 으로 감싸짐 | 파서가 마지막 `{ ... }` 객체를 robust 하게 추출하여 처리 |
| LLM 응답에 추가 prose 가 섞임 | 첫 번째 valid JSON 객체만 파싱. 실패 시 fail-open |
| `allowed=false` 인데 `reason` 이 비어 있음 | reason 그대로 (빈 문자열). UI 단에서 "사유 미상" 처리 |
| `categories` 가 누락 | 빈 리스트로 처리 |
| `confidence` 가 범위 밖 (음수 / >1) | 클램프 후 사용 |
| 운영자 system_prompt 가 출력 형식 instruction 을 무시하도록 작성됨 | 시스템 append 가 항상 수행되므로 영향 최소화. 그래도 LLM 이 형식 위반 시 fail-open |
| 호출자가 `system_prompt` 를 빈 문자열로 줌 | 인스턴스화는 허용하되 시스템 instruction 만으로 동작 (운영자 책임) |
| `llm` 인자가 None | 모든 호출에서 fail-open (CLI 가 키 누락 시 None 을 넘기는 케이스) |

## 5. 보안 고려

- **fail-open 일관성**: LLM 응답이 모호하거나 인프라가 흔들려도 절대로 정상 입력을 차단하지 않는다. core-secure-layer 의 글로벌 원칙과 일치.
- **차단 비결정성 최소화**: severity / categories / confidence 같은 필드를 시스템이 강제 schema 로 받아서 BLOCK 사유를 감사·재현 가능하게 만든다.
- **prompt injection 내성**:
  - LLM 호출 시 `system` 메시지에는 운영자 prompt + 출력 형식 instruction 만 두고, `user` 메시지에 사용자 입력을 분리. 메시지 분리만으로 100% 막을 수는 없으나 단일 message 직접 결합 대비 위험 완화.
  - 사용자 입력에 의한 시스템 instruction 오버라이드 시도(예: "이전 지시 무시") 가 LLM 을 흔들어도, 출력 schema 위반이 발생하면 파싱 실패 → fail-open. 이는 보안 측면에서는 위협이지만 글로벌 원칙(미탐 허용)과 일치.
  - 보다 강한 prompt-injection 차단은 L1~L3 휴리스틱 레이어가 1차 책임이며 llm_judge 는 보강 가드.
- **API 키 / 비용**: Solar API 호출은 외부 네트워크 트래픽을 발생시킨다. 호출자(orchestrator) 가 prior 결과 모두 PASS 일 때만 호출하도록 강제해 비용·latency 최소화.
- **로깅**: 사용자 입력 raw 를 그대로 로깅하지 않는다 (PII 가능성). reason / categories 만 LayerResult 로 흘려 보낸다.

## 6. 의존성

### 외부 라이브러리

- `langchain-core` — `BaseChatModel`, `SystemMessage`, `HumanMessage`
- `langchain-openai` — `ChatOpenAI` (Solar API 호환, 호출자 측 책임)
- `pydantic` — `JudgeOutput` 모델

이미 `pyproject.toml` 에 포함된 의존성만 사용하므로 추가 패키지 설치 없음.

### 환경변수

`.env` 의 기존 Solar 키를 그대로 사용:

| 변수 | 용도 |
|---|---|
| `SOLAR_API_KEY` | Solar API 키 |
| `SOLAR_BASE_URL` | Solar API 엔드포인트 |
| `SOLAR_MODEL_NAME` | 모델 이름 |

llm_judge 전용 환경변수는 도입하지 않는다 (system_prompt 는 코드 인자로 주입).

### 선행 레이어

- L1~L6 모두 PASS 한 입력만 처리하는 것이 운영 의도. **이 조건은 오케스트레이터(`cli.py:_run_layers`) 책임** 이며, 레이어 자체는 prior 결과를 알지 못한 채 단독 호출되어도 동작한다.

## 7. 향후 확장

- **멀티턴 컨텍스트**: `GuardrailRequest.session_id` / `metadata` 를 활용해 이전 턴 요약을 system message 에 포함. 현 범위 외.
- **prompt 템플릿 패키지**: 운영 도메인별 (금융/의료/일반) 디폴트 system_prompt 모음을 별도 모듈로 제공. 현재는 호출자가 직접 작성.
- **provider 추상화**: Claude / 기타 LLM 으로 스왑 가능하도록 LangChain `BaseChatModel` 외 다른 어댑터 추가. 현재는 Solar(`ChatOpenAI`) 만 가정.
- **카테고리 화이트리스트**: 운영 통계가 쌓이면 LLM 이 채우는 categories 를 사전 정의된 enum 으로 제한. 현재는 자유 텍스트.
- **응답 캐싱**: 동일 입력에 대해 LLM 호출 비용을 줄이는 short-TTL 캐시. 현재는 매 요청마다 호출.
- **타임아웃·재시도 정책**: LangChain 단의 기본값에 의존. 운영 데이터 기반으로 조정 필요 시 별도 작업.
