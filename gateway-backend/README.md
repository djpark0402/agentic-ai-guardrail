# gateway-backend

Agentic AI Guardrail의 API Gateway. **LangChain** 기반으로 Upstage Solar(Pro) 호출을
프록시하면서 `core-secure-layer`의 보안 검증을 입·출력 양방향에 적용한다.
외부 API는 OpenAI 호환 형식(`/v1/chat/completions`)을 유지한다.

## 파이프라인

```
client → [policy fetch] → [input check] → [LLM (non-stream)] → [output check*] → client
                                                                                    └ stream=true 시 SSE 재방출
* outboundEnabled=false 면 [output check] 단계는 통째로 스킵된다.
```

- **Multi-provider 지원:** 모델명으로 provider를 자동 감지한다.
  `gpt-*`, `o1-*`, `o3-*`, `ft:gpt-*`, `chatgpt-*` → OpenAI /
  `ollama/모델명` → Ollama / 그 외 → Solar (기본값).
- LLM 호출은 **항상 비스트리밍**이다. 전체 응답을 받은 뒤 출력 가드레일 검사를
  먼저 수행한 다음, 사용자 응답만 선택적으로 SSE로 재방출한다.
- ADMIN 정책의 **`outboundEnabled=false`** 이면 L1~L6 활성 레이어와 무관하게
  출력 가드레일을 전부 스킵하고 원본 LLM 응답을 그대로 전달한다. 입력
  가드레일은 영향을 받지 않는다.
- 입력/출력 가드레일이 BLOCK 하면 `stream` 플래그와 무관하게 **HTTP 200 과
  정상 LLM 응답 shape**(`finish_reason="stop"`) 을 유지한다. 원본 LLM 응답은
  절대 유출되지 않고, `choices[0].message.content` 에 **몇 번째 레이어에서
  어떤 사유로 차단되었는지** 한글 안내문이 담긴다. 스트리밍 요청에는 이
  안내문을 문자 단위 SSE 프레임으로 짧은 지연과 함께 흘려보내 실제 LLM 토큰
  스트리밍을 흉내낸다.

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
    "message": {
      "role": "assistant",
      "content": "요청이 가드레일 L1(입력 보안) 단계에서 차단되었습니다.\n사유: prompt injection detected\n다른 표현으로 다시 시도해 주세요."
    },
    "finish_reason": "stop"
  }],
  "usage": null
}
```

스트리밍 (HTTP 200, `text/event-stream`) — 정상 스트림과 동일한 3-part 구조
(role → content delta 여러 개 → finish) 로 방출되며, 마지막에 `data: [DONE]`
으로 종료한다. content delta 프레임 사이에는 기본 20ms 지연이 들어가 실제
LLM 토큰 스트리밍과 유사한 타이핑 UX 를 준다. 지연은 환경변수
`GUARDRAIL_BLOCK_STREAM_DELAY_MS` (기본 `20`) 로 조정할 수 있다.

> **브레이킹 변경:**
> 1. 이전 버전은 차단을 `finish_reason="content_filter"` + 비표준 `error`
>    블록으로 반환했다. 현재는 정상 LLM 응답과 동일한 shape 이므로
>    `finish_reason` 기반 분기나 `error.type == "guardrail_block"` 검사는
>    더 이상 매치되지 않는다. 차단 여부를 서버 측에서 구분해야 하는 경우
>    관찰 모드(`guardrail_reports`) 또는 서버 로그를 사용한다.
> 2. **외부 접속 포트 번호가 `54088`로 변경되었다.** (컨테이너 내부 포트는 `8000` 유지)

#### 가드레일 입력 범위

입력 검사는 `messages` 배열 중 **이번 턴에 새로 보낸 `role="user"` 메시지
하나만** 본문으로 추출해 L1~L6 에 전달한다. 사용자가 직접 입력한 프롬프트만
검사 대상이며, 여러 user 턴이 누적되어 있어도 **가장 최근 user 메시지 하나**
만 검사된다. 과거 user 턴은 이미 그 시점에 한 번 검사된 이력이므로, 히스토리
누적에 의한 중복 차단(한 번 차단되면 이후 모든 요청이 계속 차단되는 회귀)을
방지하기 위해 재검사 대상에서 제외된다. user 메시지가 하나도 없으면 빈
문자열이 전달된다.

검사 대상이 **아닌** 항목:

- **`system` 메시지**: 시스템 프롬프트 content 자체.
- **`assistant` 메시지**: 이전 턴의 모델 응답 content 와 `tool_calls`.
- **`tool` 메시지**: 도구 호출 결과 content.
- 요청 바디의 `tools` / `tool_choice` 정의 (tool description injection).
- 멀티모달 content 의 `image_url` 등 non-text part.

> **운영 주의**: 멀티턴 공격, system 프롬프트 오염, tool 응답 오염은 현재
> 입력 가드레일이 탐지하지 않는다. 이러한 페이로드를 검사하려면 호출
> 측에서 해당 본문을 별도의 `user` 메시지로 감싸 전달해야 한다.

#### 관찰 모드 (`CONTINUE_ON_LAYER_FAILURE=true`, `APP_ENV=dev` 전용)

데모용 대체 경로다. 이 환경변수를 `true` 로 두면 가드레일 레이어가 BLOCK 을
내려도 파이프라인을 **끝까지 실행**(LLM 호출 + 후속 레이어 + 원본 응답 전송)
하고, 응답에 레이어별 판정 내역을 담은 **`guardrail_reports` 블록**을
첨부한다. 차단 안내문 content 재작성은 일어나지 않고, 원본 LLM 응답이
그대로 전달된다.

관찰 모드는 **`APP_ENV=dev` 일 때만 허용**된다. `APP_ENV` 의 기본값은
`prod` 이므로 명시적으로 `dev` 를 지정하지 않은 환경에서는 관찰 모드가
**기동 시점에 `pydantic.ValidationError` 로 거부**되어 아예 활성화되지
않는다.

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

> 관찰 모드는 **보안 기능을 무력화**하므로 `APP_ENV=dev` 에서만 허용된다.
> `APP_ENV` 가 `prod` (기본값) 일 때 `CONTINUE_ON_LAYER_FAILURE=true` 를
> 설정하면 **프로세스 기동이 실패**한다 (`pydantic.ValidationError`).
> 운영 사고를 기술적으로 차단하기 위한 가드이며, README 경고 외에 코드
> 레벨 방어선으로도 강제된다.

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
   정책(`l1Enabled`..`l6Enabled`, `outboundEnabled`, `l5Setting`) 을
   반환하고, 게이트웨이는 그 플래그에 따라 `core-secure-layer` L1~L6 를
   선택적으로 실행한다. `outboundEnabled=false` 면 출력 가드레일
   파이프라인 전체를 건너뛰며, `l5Setting` 이 있으면 L5 실행 시 해당
   모델 폴더와 NER threshold 를 적용한다. 4xx/5xx 가 돌아오면 예외가
   전파되어 해당 요청은 실패 처리된다.

   ADMIN 응답 예시 (핵심 필드만):

   ```json
   {
     "l1Enabled": true,
     "l2Enabled": true,
     "l3Enabled": true,
     "l4Enabled": true,
     "l5Enabled": true,
     "l6Enabled": true,
     "l5Setting": {
       "model": "pii_model_v11",
       "threshold": 0.82
     },
     "outboundEnabled": true
   }
   ```

   > 기존 호환: ADMIN 응답에 `outboundEnabled` 키가 없으면 기본값
   > `true` 로 간주되어 출력 가드레일이 기존과 동일하게 동작한다.
   > `l5Setting` 이 없으면 기본 L5 모델 설정(`L5Layer()`) 을 사용한다.

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

#### 파이프라인 스위치 — `outboundEnabled`

| 플래그 | 대상 | 동작 |
|---|---|---|
| `outboundEnabled` | 출력 가드레일 전체 | `false` 면 L1~L6 활성 여부와 관계없이 LLM 응답에 대한 검사(`check_output`) 를 통째로 스킵하고 원본 응답을 그대로 반환. `true` (기본값) 면 활성 레이어로 검사 수행. |

- 입력 가드레일에는 영향이 없다 — `lN_enabled` 플래그는 그대로 적용된다.
- 관찰 모드(`CONTINUE_ON_LAYER_FAILURE=true`)에서도 동일하게 스킵되며,
  응답의 `guardrail_reports.output` 은 빈 배열로 실려 클라이언트가 스킵
  여부를 확인할 수 있다.
- ADMIN 응답에 `outboundEnabled` 키가 없으면 하위 호환을 위해 `true` 로
  간주한다.

admin-backend 가 응답하지 않거나 4xx/5xx 를 반환하면 예외가 전파되어 해당
요청은 실패로 처리된다.

### 레이어 진단

각 가드레일 레이어(L1~L6)가 모델을 로드했는지는 물론, **현재 상태에서
실제로 BLOCK 판정을 낼 수 있는지(`effective`)** 를 두 경로로 확인할 수
있다. 모델은 로드됐어도 규칙/컬렉션/LLM 이 비어 있어 조용히 PASS 되는
레이어가 있을 수 있으므로, 단순 로드 여부만으로 "동작 중" 이라고 판단하지
않도록 한다.

#### 1) 기동 시 요약 로그

FastAPI lifespan startup 단계에서 `app.services.layer_diagnostics` 가
"가드레일 레이어 로드 상태 요약" 을 한 번 출력한다. 판정 결과가 한국어
문장으로 풀어서 찍히므로 `docker logs` 를 훑을 때 어느 레이어가 문제인지
한눈에 보인다. `effective=True` 인 레이어는 `INFO`, 하나라도
`effective=False` 이면 맨 위 요약 라인과 해당 레이어 라인이 함께
`WARNING` 으로 올라간다.

```bash
# 실패한 레이어만 추려 보기
docker compose logs gateway-backend | grep "로드 실패했습니다"

# 전체 진단 블록을 한 번에 훑기
docker compose logs gateway-backend | grep -E "레이어 로드 상태 요약|\[L[1-6]\]"
```

출력 예 (L6 모델 파일 미배포 + L4 가 NLI 경로만 동작 중):

```
WARNING [app.services.layer_diagnostics] 가드레일 레이어 로드 상태 요약 — 전체 6개 중 5개 성공, 1개는 동작 준비에 실패했습니다. 실패 레이어는 조용히 PASS 되므로 아래 상세를 점검하세요.
INFO    [app.services.layer_diagnostics]   • [L1] L1Layer: 로드 성공했습니다. 규칙 기반, 모델 없음. (signals: rule_based=True)
INFO    [app.services.layer_diagnostics]   • [L3] L3Layer: 로드 성공했습니다. 공격 패턴 210건 적재됨. 모델 경로: /app/.../l3/model/all-MiniLM-L6-v2. (signals: embedding_ready=True, attack_patterns_collection=True, attack_patterns_count=210)
INFO    [app.services.layer_diagnostics]   • [L4] L4Layer: 로드 성공했습니다. NLI 규칙 기반 경로(규칙 21건)로 동작합니다. 참고: LLM 이 연결되지 않아 벡터+LLM 경로는 비활성(llm_attached=False). 모델 경로: /app/.../l4/model. (signals: ... llm_attached=False, nli_path_ok=True, vector_llm_path_ok=False)
WARNING [app.services.layer_diagnostics]   • [L6] L6Layer: 로드 실패했습니다. 지정된 경로에서 모델 파일(kanana-safeguard-8b)을 찾지 못했습니다 — 이 레이어는 호출되더라도 조용히 PASS 됩니다. 모델 경로: /app/.../l6/model/kanana-safeguard-8b. (signals: safety_model_loaded=False, model_name=kanana-safeguard-8b)
```

판정 문구는 `loaded` × `effective` 조합에 따라 네 가지로 갈린다.

| loaded | effective | 문구 |
|---|---|---|
| True | True | `로드 성공했습니다.` (+ 경로·보조 힌트) |
| False | True | `로드 성공했습니다. 주 모델은 로드되지 않았지만 대체 경로(규칙 기반)로 동작합니다.` (예: L5 regex-only) |
| True | False | `로드 실패했습니다. 모델 파일은 로드되었지만 판정에 필요한 보조 설정(규칙/컬렉션/LLM)이 비어 있어 조용히 PASS 됩니다.` |
| False | False | `로드 실패했습니다. 지정된 경로에서 모델 파일(<모델명>)을 찾지 못했습니다 — 이 레이어는 호출되더라도 조용히 PASS 됩니다.` |

L4 처럼 `nli_path_ok` / `vector_llm_path_ok` 중 한쪽만 True 인 **부분
가용** 상태에서는 어느 경로로 동작 중이고 어느 경로가 왜 비활성인지를
한 줄 힌트로 덧붙인다. `signals` 는 가독성을 위해 쉼표 구분으로 바뀌었지만
키 이름(예: `nli_rules_count`, `llm_attached`) 은 기존 grep 워크플로우
호환을 위해 그대로 유지된다.

#### 2) `GET /v1/layers/status`

런타임에 HTTP 로 같은 정보를 조회한다. `/docs` 의 **meta** 태그에 함께
노출되며, 외부 모니터링에서도 폴링 가능하다.

```bash
curl -s http://localhost:54088/v1/layers/status | jq .
```

응답 예 (축약):

```json
{
  "all_loaded": false,
  "all_effective": false,
  "layers": [
    {
      "index": 4,
      "name": "L4",
      "class_name": "L4Layer",
      "model_loaded": true,
      "effective": true,
      "signals": {
        "nli_model_loaded": true,
        "embed_model_loaded": true,
        "reranker_model_loaded": true,
        "nli_rules_count": 21,
        "policy_collection_count": 35,
        "llm_attached": false,
        "nli_path_ok": true,
        "vector_llm_path_ok": false
      },
      "model_paths": ["/app/core-secure-layer/core_secure_layer/layers/l4/model"],
      "detail": null
    },
    {
      "index": 6,
      "name": "L6",
      "class_name": "L6Layer",
      "model_loaded": false,
      "effective": false,
      "signals": {"safety_model_loaded": false, "model_name": "kanana-safeguard-8b"},
      "model_paths": ["/app/core-secure-layer/core_secure_layer/layers/l6/model/kanana-safeguard-8b"],
      "detail": "_model_loaded=False"
    }
  ]
}
```

- `model_loaded`: 모델 바이너리가 로드되었는지.
- `effective`: 현재 상태에서 이 레이어가 실제로 BLOCK 판정을 낼 수 있는지.
  모델은 로드됐어도 규칙/컬렉션/LLM 이 비어 있으면 `false`.
- `signals`: 레이어별 런타임 상태. 예를 들어 L4 의 `nli_rules_count=0` 은
  NLI 판정 경로가, `llm_attached=false` 는 LLM 판정 경로가 **조용히
  스킵된다**는 뜻.
- **fail-open 정책은 유지**된다. `effective=false` 여도 서비스는 정상
  기동하며 해당 레이어만 PASS 로 처리된다. 본 엔드포인트/로그는
  **가시성**만 제공한다.

##### L5 전용 signals — `available_models` 와 `min_score`

L5 는 다른 레이어와 달리 `core-secure-layer/layers/l5/model/` 아래에
**여러 모델을 동시에 배포**할 수 있고, 각 모델은 자기 계약 파일
`pii_labels.json` 으로 판정 임계값(`min_score`) · 정규화 매핑
(`label_map`) · 단일 차단 목록(`block_singletons`) · HF 파이프라인
aggregation 전략(`aggregation_strategy`) 을 선언한다. 상태 API 는 이
정보를 한 번에 노출해 운영자가 "어떤 모델이 있고 어떤 임계값으로
동작하는가" 를 확인할 수 있게 한다.

```json
{
  "index": 5,
  "name": "L5",
  "class_name": "L5Layer",
  "model_loaded": true,
  "effective": true,
  "signals": {
    "ner_model_loaded": true,
    "regex_ready": true,
    "model_name": "ner-ko",
    "min_score": 0.7,
    "available_models": [
      {"name": "ner-ko",        "min_score": 0.7, "block_singletons_count": 15, "aggregation_strategy": "simple"},
      {"name": "pii_model_v11", "min_score": 0.7, "block_singletons_count": 16, "aggregation_strategy": "simple"}
    ]
  },
  "model_paths": [
    "/app/core-secure-layer/core_secure_layer/layers/l5/model/ner-ko",
    "/app/core-secure-layer/core_secure_layer/layers/l5/model"
  ],
  "detail": null
}
```

| 필드 | 의미 |
|---|---|
| `signals.model_name` | 현재 활성 모델 폴더명. |
| `signals.min_score` | 현재 활성 모델의 NER 스코어 컷오프. `_check_ner` 가 매 호출 시 이 속성을 직접 참조하므로, 런타임에 `layer.min_score` 를 대입 갱신하면 다음 요청부터 즉시 반영된다. |
| `signals.available_models[].name` | 모델 폴더명. |
| `signals.available_models[].min_score` | 해당 모델의 `pii_labels.json` 에 선언된 임계값. 파일이 없으면 `null`. |
| `signals.available_models[].block_singletons_count` | 단일 검출로 차단할 정규화 PII 타입 개수. |
| `signals.available_models[].aggregation_strategy` | HF NER pipeline `aggregation_strategy`. |
| `model_paths` | 1번째: 활성 모델 폴더 절대경로. 2번째: 모델 루트(`.../model`). |

> **ADMIN 정책 주입 경로**: ADMIN 이 `l5Setting.model` 과
> `l5Setting.threshold` 를 내려주면 게이트웨이는
> `L5Layer(model_name=<model>, min_score=<threshold>)` 인스턴스를
> 설정 조합별로 캐시해 L5 호출에 사용한다. `model` 값은
> `core-secure-layer/layers/l5/model/<model>` 폴더명 그대로 해석된다.
> `l5Setting` 이 없으면 기존 기본 L5 싱글턴을 사용한다.

###### L5 모델 계약 파일 `pii_labels.json`

각 모델 폴더는 반드시 `pii_labels.json` 을 포함해야 L5 가 NER 기반
차단을 수행한다. 파일이 없으면 L5 는 fail-open 으로 NER 단계를 no-op
처리하고 Regex 경로만 살아남는다.

```json
{
  "label_map":         { "이름": "person", "전화번호": "phone_number", "...": "..." },
  "block_singletons":  ["person", "phone_number", "resident_id", "..."],
  "block_combinations": [],
  "min_score":         0.7,
  "aggregation_strategy": "simple"
}
```

- `label_map`: 모델 로컬 라벨(B-/I- 접두 제거 후) → 정규화 PII 타입.
- `block_singletons`: 정규화 타입이 이 집합에 속하면 단일 검출로 차단.
- `block_combinations`: 현재 미사용(예약). 차후 조합 기반 차단용.
- `min_score`: NER 예측의 score 가 이 값 이상이어야 차단 후보로 간주.
- `aggregation_strategy`: HF `pipeline("ner", ...)` 에 전달되는 집계 전략.

## 엔드포인트

| Method | Path | 설명 |
|---|---|---|
| POST | `/v1/chat/completions` | OpenAI/Solar 호환 채팅 완성 (stream 지원) |
| GET | `/v1/models/default` | `.env` 의 `LLM_MODEL` 로 설정된 기본 모델명 반환 |
| GET | `/v1/layers/status` | L1~L6 각 레이어의 모델 로드 여부 + 실제 BLOCK 가능 여부(`effective`) + 레이어별 `signals` 진단 조회 (아래 _레이어 진단_ 참고) |
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

curl -X POST http://localhost:54088/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $API_KEY" \
  -H "X-Timestamp: $TS" \
  -H "X-Nonce: $NONCE" \
  -H "X-Signature: $SIG" \
  --data "$BODY"

# SKIP_HEADER_VERIFICATION=true 로 띄운 로컬 개발 서버에서 헤더 없이 호출
curl -X POST http://localhost:54088/v1/chat/completions \
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
| `uv run uvicorn app.main:app --reload --port 8000` | 개발 서버 실행 |
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
- `APP_ENV` — 실행 환경. `"dev"` 또는 `"prod"` 만 허용 (기본 `"prod"`, safe-by-default). 관찰 모드(`CONTINUE_ON_LAYER_FAILURE=true`) 는 `APP_ENV=dev` 일 때만 허용되며, 그 외 조합은 기동 시점에 거부된다. `"staging"` 등 다른 값은 `ValidationError` 로 즉시 차단.
- `ADMIN_BACKEND_URL` — 검증·정책 조회용 admin-backend 주소
- `ADMIN_API_KEY` — admin-backend `/api/v1/gateway/verify` 호출 시 게이트웨이가 `X-API-Key` 헤더로 제시할 키. 사용자의 `X-API-Key` 와는 별개 (기본 빈 값 = 헤더 미전송)
- `REQUEST_TIMESTAMP_SKEW_SEC` — `X-Timestamp` 허용 오차(초). 기본 `300` (5분)
- `SKIP_HEADER_VERIFICATION` — `true`로 설정하면 사용자 4개 헤더 검증을 건너뛴다. 로컬·데모용이며 `SKIP_POLICY_FETCH` 와 독립 동작 (기본 `false`)
- `SKIP_POLICY_FETCH` — `true`로 설정하면 admin-backend 정책 조회를 생략하고 **L1~L6 전체 레이어를 강제 실행**. admin-backend 없이 로컬 풀 파이프라인을 검증할 때 사용 (기본 `false`)
- `CONTINUE_ON_LAYER_FAILURE` — `true`로 설정하면 가드레일이 BLOCK 을 내려도 파이프라인을 끝까지 실행하고 응답에 `guardrail_reports` 블록을 첨부한다(**관찰 모드**, 위 섹션 참고). 데모·디버깅 전용. **`APP_ENV=dev` 일 때만 `true` 허용**되며, 그 외 환경에서 `true` 로 설정하면 기동 시 `ValidationError` 로 실패한다 (기본 `false`)

> `.env` 파일은 **절대 커밋하지 않는다.** 새 환경 변수가 필요하면
> `.env.example`에 먼저 추가한다.

## Docker 배포

팀 개발 서버(Linux x86_64, CPU 추론) 배포용 구성 파일이 포함되어 있다.
로컬 macOS 환경과 어긋나지 않도록 `pyproject.toml` / `uv.lock` 은 손대지
않고 Docker 레이어만으로 배포 차이를 흡수한다.

### 포함 파일

| 파일 | 역할 |
|---|---|
| `Dockerfile` | Python 3.14-slim-bookworm 기반 multi-stage 빌드. `uv export --frozen --prune torch` 로 `uv.lock` 에서 torch·nvidia-\*/triton 을 dep graph 기준으로 제거한 `requirements.txt` 를 만들어 non-torch 의존성을 설치하고, `torch` 는 PyTorch 공식 CPU 인덱스에서 별도 설치한다 (CUDA 바이너리·nvidia-\* 이미지 미포함). `core-secure-layer` 는 editable path-dep 으로 설치된다. **무거운 모델 파일 (`layers/*/model/`, ~7GB) 은 이미지에 넣지 않고 compose 의 bind mount 로 런타임에 공급**되어 이미지 크기가 대폭 줄어든다. 비-root `appuser` 로 기동. |
| `Dockerfile.dockerignore` | BuildKit 의 Dockerfile 전용 ignore. 빌드 컨텍스트(monorepo 루트) 에서 `admin-backend/`, `admin-frontend/`, `docs/`, `.venv/`, `.git`, `.env`, `tests/`, `*.egg-info` 등을 제외. 그리고 `core-secure-layer/core_secure_layer/layers/*/model/` 도 제외해 빌드 컨텍스트 전송 크기를 **GB 단위로 줄인다**. vectordb / patterns / policies 는 chromadb sqlite 쓰기 잠금/권한 문제 회피를 위해 이미지에 포함 유지. |
| `docker-compose.yml` | `context: ..` 로 monorepo 루트를 빌드 컨텍스트로 잡고, `platform: linux/amd64` 고정. `env_file: .env`, `extra_hosts: host.docker.internal:host-gateway`, `start_period: 300s` (모델 로드 유예). **`volumes` 섹션에서 `../core-secure-layer/core_secure_layer/layers/l{2..5}/model` 를 `:ro` 로 bind mount** 해 이미지에서 제외된 모델을 공급한다. L6 `kanana-safeguard-8b` 는 아직 호스트에 없으므로 마운트하지 않으며, 모델이 준비되면 같은 패턴으로 한 줄 추가. |

### 아키텍처 / 런타임 특성

- **빌드 컨텍스트**: `gateway-backend/` 단독이 아니라 `agentic-ai-guardrail/`
  (monorepo 루트). `core-secure-layer/` 의 Python 소스 / vectordb / patterns
  / policies 를 함께 포함해야 editable path-dep (`../core-secure-layer`) 이
  컨테이너 안에서 `/app/core-secure-layer` 로 resolve 된다. 단 **무거운
  `layers/*/model/` 은 `.dockerignore` 로 빌드 컨텍스트와 이미지 양쪽에서
  모두 제외**되며 런타임에 bind mount 로 공급된다. 이로써 빌드 컨텍스트
  전송량이 GB 단위로 줄고 이미지 용량도 ~7GB 감소한다.
- **플랫폼**: 맥북 Apple Silicon 에서 빌드해도 `linux/amd64` 이미지가 나오도록
  compose 에 플랫폼을 고정. 개발 서버(x86) 에서는 native 빌드가 수행된다.
- **CPU / GPU**: 빌드 단계에서 `torch` 를 PyTorch 공식 CPU 인덱스
  (`https://download.pytorch.org/whl/cpu`) 에서만 설치하고, `uv export
  --prune torch` 로 `uv.lock` 의 nvidia-\*/triton 런타임 의존성을 dep graph
  기준으로 제거한다. 결과적으로 이미지에 CUDA 바이너리가 포함되지 않는다.
  `pyproject.toml` / `uv.lock` 은 수정하지 않아 로컬 macOS 개발 환경과 완전히
  분리되어 있다 (배포 전용 오버라이드는 Dockerfile 안에만 존재). 런타임에는
  transformers / sentence-transformers 가 device 자동 선택으로 CPU 추론.
- **모델 공급 방식**: 이미지는 `core-secure-layer` 의 Python 패키지만 품고,
  각 레이어의 모델 바이너리(`layers/l{2..5}/model/`)는 `docker-compose.yml`
  의 `volumes:` 섹션이 **호스트의 `../core-secure-layer/...` 경로를 `:ro`
  로 bind mount** 해서 `/app/core-secure-layer/.../model/` 에 투명하게
  overlay 한다. editable install 의 `.pth` 는 여전히 `/app/core-secure-layer`
  트리를 가리키고, 서브디렉터리 overlay 만 들어가므로 import 경로에는 영향이
  없다. 결과: 로컬 측정 기준 이미지 `13.4GB → 5.64GB`, 빌드 컨텍스트 전송
  `7.77GB → 4.66MB`.
- **모델 로드 시점**: `app/services/layer_registry.py` 가 import 될 때 L1~L6
  싱글턴이 즉시 인스턴스화된다 → uvicorn 이 `"Application startup complete"`
  를 찍는 시점에는 이미 모델 로드가 끝난 상태. 초기 로드는 1~3분 소요.
  이때 `app.services.layer_diagnostics` 가 "레이어 로드 상태 요약" 을
  INFO / WARNING 으로 한 번 찍고(위 _레이어 진단_ 참고), `/v1/layers/status`
  에서도 같은 결과를 조회할 수 있다.
- **`/health` access log 억제**: 도커 healthcheck 가 수초마다 때리는
  `'"GET /health HTTP/1.1" 200 OK'` 라인은 `uvicorn.access` 로거에
  부착된 `_HealthAccessLogFilter` 가 걸러낸다. `--no-access-log` 로
  전체 access log 를 끄지 않고 `/health` 경로만 억제하므로,
  `POST /v1/chat/completions` 같은 실제 트래픽은 평소대로 access log
  에 남는다. 앱 자체 request 미들웨어(`log_request`) 도 이미
  `/health` 와 `/openapi.json` 을 건너뛰도록 설정돼 있어 두 경로는
  양쪽에서 모두 조용하다.

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
curl -fsS http://localhost:54088/health
#  -> {"status":"ok"}
curl -fsS http://localhost:54088/v1/models/default
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

- **`core-secure-layer` 디렉터리 _전체_ 를 볼륨 마운트하지 말 것.** editable
  install 의 `.pth` 가 `/app/core-secure-layer` 절대경로를 가리키고 있어,
  전체를 호스트 경로로 덮으면 vectordb / patterns / policies 리소스가
  사라지고 `ModuleNotFoundError` 혹은 모델 로드 실패가 발생한다.
  compose 가 쓰는 **`layers/*/model` 서브디렉터리 단위 overlay 는 권장
  방식** — editable 트리는 유지되고 무거운 모델 파일만 호스트에서 공급된다.
- **호스트 사전조건**: `docker compose up` 전에 **호스트(로컬·dev 서버
  모두)에 `../core-secure-layer/core_secure_layer/layers/l{2,3,4,5}/model/`
  경로가 반드시 존재**해야 한다. 모노레포를 clone 만 한 직후라면 모델 다운
  스크립트를 먼저 돌려 모델을 배치할 것. bind mount 원본이 없으면 compose
  가 즉시 실패한다.
- **L6 kanana-safeguard-8b 는 아직 미배포**: 현재 `docker-compose.yml` 에
  L6 마운트 라인이 빠져 있다. 이 상태에서는 L6 가 `loaded=False` / `effective
  =False` 로 표시되고 L6 검사는 PASS 처리된다(fail-open). 모델이 호스트에
  준비되면 compose 에 한 줄 추가(`../core-secure-layer/.../l6/model:...:ro`).
- **`.env` 는 이미지에 들어가지 않는다.** `Dockerfile.dockerignore` 에서
  명시적으로 제외하고 compose 의 `env_file` 로 런타임에 주입한다. 새 키가
  필요하면 `.env.example` 에 먼저 추가.
- **로컬 macOS 에서 실제 이미지 빌드는 비권장**: `linux/amd64` QEMU 에뮬레이션
  으로 시간이 오래 걸린다. 다만 이번 bind mount 전환으로 **빌드 컨텍스트
  전송이 GB → MB 단위로 줄어** 과거 대비 크게 빨라졌다. 구문 검증은
  `docker compose config` (단, `.env` 값이 표준 출력으로 노출되므로
  `--no-interpolate` 사용 권장) + `docker buildx build --check` 로 충분하며,
  실 배포용 이미지는 개발 서버 native 에서 굽는 것을 권장.
- **첫 기동이 5분 이상 걸리면 `start_period` 확장**: 디스크 I/O 가 느린
  환경에서는 `docker-compose.yml` 의 `start_period: 300s` 를 `600s` 로 늘려
  healthcheck 가 unhealthy 로 떨어지는 것을 방지한다.

### 트러블슈팅

| 증상 | 진단 포인트 |
|---|---|
| 기동 로그에 `core_secure_layer.layers.l*` import 오류 | editable 설치가 깨진 상태. `Dockerfile.dockerignore` 가 `core-secure-layer/` 의 **Python 소스** 까지 제외하지는 않는지 재확인. 제외해야 하는 건 `layers/*/model/` 뿐이다. |
| `GET /v1/layers/status` 에서 L2~L5 중 일부가 `loaded=false` | bind mount 원본 경로가 호스트에 없거나 비어 있음. `ls ../core-secure-layer/core_secure_layer/layers/l4/model` 로 호스트 모델 유무 확인. 또는 `docker exec gateway-backend ls /app/core-secure-layer/core_secure_layer/layers/l4/model` 로 mount 가 실제로 반영됐는지 점검. `docker exec gateway-backend mount \| grep core-secure-layer` 로 4줄의 `virtiofs ro` 항목이 보여야 정상. |
| `GET /v1/layers/status` 에서 L2~L5 는 `loaded=true` 인데 `effective=false` | 모델은 있으나 규칙/컬렉션/LLM 이 비어 조용히 PASS 되는 상태. `signals` 필드를 확인(예: L4 `nli_rules_count`, `policy_collection_count`, `llm_attached`). 기동 로그에서도 `docker compose logs gateway-backend \| grep "로드 실패했습니다"` 로 동일하게 관찰된다. |
| `모델 로드 실패` 워닝만 나오고 요청은 동작 | fail-open 설계 동작. 해당 레이어만 비활성. `/v1/layers/status` 의 `detail` 필드와 위 항목(bind mount 원본 확인)을 우선 점검. |
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
