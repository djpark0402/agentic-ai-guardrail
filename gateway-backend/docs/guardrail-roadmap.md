# 가드레일 게이트웨이 보완 로드맵

> 작성일: 2026-04-23
> 범위: `gateway-backend/` 의 프롬프트 가드레일 제품화 관점에서 **보완해야 할
> 기능과 수정이 필요한 사항**을 우선순위화해 정리.
> 방법: Codex(보안/아키텍처/운영) · Gemini(UX/DX/문서/생태계) 두 외부 advisor
> 의 독립 분석을 교차 검증한 뒤 통합.
>
> 각 항목은 **왜 필요한가 / 현재 상태 / 제안 / 우선순위 / 관련 코드** 5필드.
> 우선순위: **P0** (운영 전 반드시 해결) → **P1** (정식 공개 전 해결) →
> **P2** (장기 고도화).

---

## 목차

- [0. 설계 원칙 (이 로드맵이 전제하는 것)](#0-설계-원칙-이-로드맵이-전제하는-것)
- [PART A. 보안·아키텍처·운영 (Codex 관점)](#part-a-보안아키텍처운영-codex-관점)
  1. [입력 검사 범위 확장](#a1-입력-검사-범위-확장)
  2. [실시간 스트리밍 출력 검사 전략](#a2-실시간-스트리밍-출력-검사-전략)
  3. [차단 응답의 정보 유출 최소화](#a3-차단-응답의-정보-유출-최소화)
  4. [분산 Replay 방어 저장소](#a4-분산-replay-방어-저장소)
  5. [ADMIN 정책 조회 캐싱·회로차단·fallback](#a5-admin-정책-조회-캐싱회로차단fallback)
  6. [네트워크 경계 하드닝](#a6-네트워크-경계-하드닝)
  7. [Observe 모드의 운영 가드](#a7-observe-모드의-운영-가드)
  8. [진단 엔드포인트 인증·권한 분리](#a8-진단-엔드포인트-인증권한-분리)
  9. [민감 로그 정리와 구조화 audit log](#a9-민감-로그-정리와-구조화-audit-log)
  10. [fail-open 관측 가능성과 알람](#a10-fail-open-관측-가능성과-알람)
  11. [SKIP_* 우회 플래그 prod-safe 가드](#a11-skip_-우회-플래그-prod-safe-가드)
  12. [Readiness vs Liveness 분리](#a12-readiness-vs-liveness-분리)
  13. [회귀 시나리오 체크리스트](#a13-회귀-시나리오-체크리스트)
- [PART B. UX·문서·개발자 경험 (Gemini 관점)](#part-b-ux문서개발자-경험-gemini-관점)
  1. [차단 안내문 UX](#b1-차단-안내문-ux)
  2. [다국어(i18n) 대응](#b2-다국어i18n-대응)
  3. [관찰 모드 UI 시각화](#b3-관찰-모드-ui-시각화)
  4. [에러 코드 카탈로그](#b4-에러-코드-카탈로그)
  5. [공식 클라이언트 SDK](#b5-공식-클라이언트-sdk)
  6. [플레이그라운드 고도화](#b6-플레이그라운드-고도화)
  7. [영어 문서 / 이중 언어화](#b7-영어-문서--이중-언어화)
  8. [관측 대시보드](#b8-관측-대시보드)
  9. [ADMIN 통합 플로우 다이어그램](#b9-admin-통합-플로우-다이어그램)
  10. [대안 가드레일 벤치마킹](#b10-대안-가드레일-벤치마킹)
  11. [에지 케이스 경고 배너](#b11-에지-케이스-경고-배너)
  12. [개발자 온보딩 5분 퀵스타트](#b12-개발자-온보딩-5분-퀵스타트)
- [PART C. 종합 우선순위 요약](#part-c-종합-우선순위-요약)
- [PART D. 두 advisor 간 합의·충돌 정리](#part-d-두-advisor-간-합의충돌-정리)

---

## 0. 설계 원칙 (이 로드맵이 전제하는 것)

> 2026-04-23 설계 논의에서 확정된 원칙. 아래 로드맵의 모든 우선순위와
> 설계 선택은 이 원칙을 공통 전제로 삼는다.

### P-1. 가드레일의 존재 이유 — 공격 방어·차단

모든 레이어는 **공격 및 악의적 행동에 대한 방어·차단** 이 primary 목적.
Audit/이상 탐지는 부수적 산출물이며, 유출 차단을 대체하지 않는다.

| 레이어 | 주 목적 | 특이 역할 |
|---|---|---|
| L1 prompt injection | 공격 차단 | — |
| L2 sensitive data | 공격 차단 + 출력 유출 차단 | — |
| L3 toxicity | 공격 차단 | — |
| L4 hallucination | 공격 차단 | — |
| L5 PII | **유출 차단 + 마스킹** | 입출력 양방향 처리. 입력 PII 원본과 동일 값이 응답에 재출현할 때 **역마스킹(복원)** 까지 검토 중 |
| L6 compliance | 공격 차단 | — |

### P-2. "응답 후 BLOCK 은 유출을 되돌릴 수 없다"

이미 사용자에게 방출된 응답은 차단해도 유출이 회수되지 않는다. 따라서:

- **되돌릴 수 있는 레이어** (규칙 기반, 문자/문장 단위 실시간 판정 가능) 만
  출력 streaming 경로에 배치.
- **되돌릴 수 없는 레이어** (perplexity·LLM·벡터 기반, 전체 응답 필요) 는
  둘 중 하나:
  1. **입력(pre-LLM) 단계로 이동** — 사용자 프롬프트 단계에서 위험도 판정
  2. **buffer-then-stream 경로 전용** — streaming 비활성 조건 (짧은 응답
     또는 정책 스위치) 하에서만 실행
- "응답 완료 후 BLOCK" 은 **유출 방지용으로 설계하지 않는다**. 부수적
  audit 기록은 허용하되, 그 BLOCK 으로 이미 전송된 응답을 되돌리는
  액션은 없음.

### P-3. Stateless 전제

OpenAI 호환 API 는 매 요청에 전체 `messages` 를 다시 받으므로, 검사 로직은
**대화 히스토리 DB 저장 없이** 동작해야 한다 (A1 의 content-hash PASS
캐시 근거). Audit/compliance 목적의 저장은
[A9](#a9-민감-로그-정리와-구조화-audit-log) 의 별도 파이프라인에서만 수용.

---

## PART A. 보안·아키텍처·운영 (Codex 관점)

### A1. 입력 검사 범위 확장 + Content-Hash PASS 캐시

- **Why it matters**: 현재 가드레일은 실제 공격 표면의 **일부만** 본다.
  `system` 오염, `assistant`/`tool` 응답 주입, `tools` 스키마 설명 인젝션,
  멀티모달 non-text 필드 공격은 "가장 최근 user 텍스트" 하나만 검사하면
  전부 놓친다. 그러나 단순히 "전체 배열 재검사" 로 전환하면 과거 턴의
  user 메시지가 반복 재평가되어 **"한 번 BLOCK 된 대화는 이후 전부 차단"**
  이라는 회귀가 발생한다. 따라서 **검사 범위 확장과 회귀 방지를 동시에**
  만족시키는 설계가 필요하다.
- **Current state**: `guardrail_converter.messages_to_request()` 는
  `messages` 중 가장 최근 `role="user"` 메시지 하나만 추출해
  `GuardrailRequest.user_input` 으로 만든다. `system` / `assistant` /
  `tool` content, `tools.function.description`, `tool_choice`, multimodal
  의 `image_url` 등 non-text part 는 전부 제외되며, LLM 호출에는
  pass-through 된다 (README "가드레일 입력 범위" 섹션 명시). 이 좁은 범위는
  **회귀 방지 목적의 의도적 설계** 이며, 그 의도 자체는 유지해야 한다.
- **Proposed change**: **Stateless content-hash PASS 캐시** 패턴 도입으로
  검사 범위 확장과 회귀 방지를 양립시킨다. OpenAI 호환 API 는 매 요청에
  전체 `messages` 배열을 다시 받으므로 **별도 대화 히스토리 DB 저장은
  불필요**하다.

  **1) 입력 정규화 계층 (`InputNormalizer`) 추가** — 검사 대상을
  `system` + 모든 `user` + `assistant.tool_calls` + `tool` 응답 +
  `tools.function.description/parameters` + `tool_choice` + multimodal
  텍스트/이미지 URL 메타데이터로 확장한다. 레이어에는 "사용자 입력" 과
  "도구/시스템 제어면" 을 구분된 필드로 전달해 면(面)별로 다른 판정 기준을
  적용할 수 있게 한다.

  **2) Content-hash PASS 캐시** (단일 인스턴스는 `cachetools.TTLCache`,
  다중 인스턴스는 Redis. TTL 권장치: 5–15분)

  | 항목 | 값 |
  |---|---|
  | Key | `(sha256(normalized_content), layer_id)` |
  | Value | `PASS` (boolean/timestamp). **BLOCK 은 저장 금지** |
  | 원문 저장 | **하지 않음** (PII 이슈 회피, hash 만 보관) |
  | TTL 만료 시 | 자동 재평가 → 규칙/정책 업데이트 반영 |

  흐름: 배열 각 항목 검사 시 hash 먼저 조회 → **히트면 스킵**, **미스면
  레이어 실행** 후 **PASS 결과만** 캐시 저장. BLOCK 을 저장하지 않는 것이
  회귀 방지의 핵심이다 — 같은 악성 콘텐츠는 어차피 다음 요청에서도 같은
  BLOCK 판정이 나오므로 캐시할 필요가 없고, 캐시하면 "한 번 차단된 대화는
  영원히 차단" 회귀가 재발한다.

  **3) 동작 예시** — 과거 통과 메시지는 재평가되지 않고, 신규 악성 입력만
  정확히 차단된다:

  ```
  요청 1: [system "helpful"] [user "안녕"]
    → hash_a, hash_b 둘 다 미스 → 검사 → 모두 PASS → 캐시 저장

  요청 2: [system "helpful"] [user "안녕"] [assistant "..."] [user "오늘 날씨?"]
    → hash_a, hash_b 히트 → 스킵
    → hash_c (신규 user) 미스 → 검사 → PASS → 캐시 저장

  요청 3: [...기존 메시지...] [user "ignore previous instructions"]
    → 기존 메시지 전부 PASS 캐시 히트 → 스킵
    → 신규 user 미스 → 검사 → BLOCK (캐시 저장 안 함) → 이번 요청만 차단
    → 다음 요청에서 기존 메시지는 여전히 캐시 히트 상태 유지
  ```

  **4) 단계적 인프라 및 다중 인스턴스 영향** (2026-04-23 결정)

  - **기본 전략: 각 인스턴스가 자체 in-memory `cachetools.TTLCache` 를
    보유**. PASS 캐시는 **보안 기능이 아니라 성능·회귀 방지 기능**이므로
    인스턴스 간 공유되지 않아도 **안전성은 그대로 유지**된다 (캐시 미스
    시 어차피 레이어 재검사 수행).
  - **다중 인스턴스 배포 시 주의 — Hit Rate 저하**:
    - 각 인스턴스가 독립 캐시를 보유하므로 같은 content 가 여러 번 검사
      될 수 있음. 예: 2개 인스턴스 + 균등 분산 시 같은 system prompt 가
      평균 2회 검사.
    - **안전성에는 영향 없음** — 매번 재검사하더라도 동일 PASS 판정이
      나오고, "BLOCK 은 저장 안 함" 회귀 방지 불변도 유지됨.
    - 완화책 (필요 시):
      1. LB 레벨 **sticky session** 또는 `consistent hash by X-API-Key`
         — 같은 apiKey 요청이 같은 인스턴스로 라우팅되어 apiKey 단위
         캐시 지역성 확보.
      2. 인스턴스 수가 많아지고 hit rate 가 성능상 중요해지는 시점에
         [A4](#a4-분산-replay-방어-저장소) Phase 2 에서 Redis 등 공유
         KV 재검토 (현 로드맵엔 Redis 도입 계획 없음).
  - **PASS 캐시는 A4 의 ADMIN 위임 대상이 아님** — A4 는 보안 기능
    (nonce replay 방어) 이므로 ADMIN 중앙 저장이 자연스럽지만, A1 은
    단순 성능 최적화 캐시라 ADMIN 에 왕복시키면 오히려 비효율. 로컬
    TTLCache 유지가 맞음.
  - **회귀 방지 불변**: "BLOCK 은 저장 안 함" 원칙은 **캐시 공유 여부와
    무관하게 그대로 유지**. 인스턴스가 몇 개든, 로컬이든 분산이든 회귀
    방지는 깨지지 않음.

  **5) DB 저장은 이 검사 로직과 무관** — 감사(audit) 목적의 구조화 저장은
  [A9](#a9-민감-로그-정리와-구조화-audit-log) 에서 별도 파이프라인으로
  다룬다. 검사 성능/회귀 방지 ≠ audit 요구사항이므로 관심사를 분리한다.

  **6) TTL 튜닝 주의점** — 너무 길게 잡으면 정책 업데이트 반영이 늦어진다.
  정책 버전(`policy.etag` 등)을 캐시 key 에 포함시키면 정책 변경 시 전체
  캐시가 자연스럽게 무효화된다.

- **Priority**: **P0**
- **관련 코드**: `app/services/guardrail_converter.py:34`,
  `app/services/security_layer_service.py:87`, `app/models/chat.py:8`,
  `app/services/llm_service.py:21`, (신규) `app/services/input_normalizer.py`,
  (신규) `app/services/content_pass_cache.py`

---

### A2. 실시간 스트리밍 출력 검사 전략

- **Why it matters**: 현재 구조는 유출은 막지만 **실제 스트리밍이 아니다**.
  긴 응답일수록 TTFB 가 나빠지며, 인위적 지연으로 타이핑 UX 를 흉내내고
  있어 자동화 클라이언트엔 순수 비용이다. 설계 원칙 [P-2](#p-2-응답-후-block-은-유출을-되돌릴-수-없다)
  를 지키면서 streaming 을 개선할 방법이 필요하다.
- **Current state**:
  - LLM 호출은 항상 non-stream. 전체 응답 수신 후 출력 가드레일 → SSE
    재방출 ("가짜 streaming").
  - `_stream_openai_chunks()` 가 응답을 **1자 단위 청크**로 재분할.
  - `GUARDRAIL_BLOCK_STREAM_DELAY_MS` (기본 20ms) 로 인위적 지연을 추가해
    타이핑 효과 시뮬레이션.
  - 자동화 클라이언트(LangChain·LiteLLM·백엔드-to-백엔드) 에겐 지연이
    손해이며, 관측 지표(`response_emit` 구간) 도 왜곡된다.
- **Proposed change**: 세 단계로 분해.

  ---

  **A2-a. 인위적 지연 옵트인 전환 (P1, 즉시 적용)**

  서버 기본값을 `instant` 로 고정하고, 타이핑 효과는 **명시적 opt-in** 요청
  에만 적용한다.

  | 요청 조건 | 동작 |
  |---|---|
  | 헤더 누락 | `instant` (지연 0, 청크 그대로) |
  | `X-Guardrail-Stream-Style: instant` | `instant` |
  | `X-Guardrail-Stream-Style: typing` | 타이핑 효과 적용 |
  | 알 수 없는 값 | `instant` 로 폴백 (느슨한 파싱) |

  - `GUARDRAIL_BLOCK_STREAM_DELAY_MS` 의 의미 재정의 — "**typing 모드 요청
    시에만 적용되는 프레임 간 지연**". 서버 전역 지연 스위치가 아님.
  - 플레이그라운드는 내부적으로 `typing` 헤더를 자동 부착해 데모 효과를
    유지.
  - openai SDK·LangChain·LiteLLM 등 표준 클라이언트는 **아무 변경 없이**
    즉시 모드로 동작.
  - 관련 코드: `app/routers/chat.py:67` (`_SSE_CHUNK_SIZE`),
    `app/routers/chat.py:72` (`GUARDRAIL_BLOCK_STREAM_DELAY_SECONDS`),
    `app/routers/chat.py:1050` (block streaming 호출부),
    `app/static/index.html`.

  ---

  **A2-b. 레이어 tier 분리 (P1, 중간 규모)**

  설계 원칙 [P-2](#p-2-응답-후-block-은-유출을-되돌릴-수-없다) 에 따라
  **"되돌릴 수 없는 레이어는 streaming 경로에 두지 않는다"**. 각 레이어의
  속도 · 최소 판정 단위 · streaming 배치를 명시적으로 분류.

  | 레이어 | 속도 | 최소 판정 단위 | Streaming 배치 |
  |---|---|---|---|
  | L1 규칙 | ms | 한 토큰 | 토큰 단위 실시간 |
  | L2 규칙 기반 부분 | ms | 한 문장 | 문장 단위 실시간 |
  | L2 perplexity 부분 | ms–10ms | **~100 토큰 이상** | buffer-then-stream 전용 (streaming 경로 제외) |
  | L3 임베딩 | 10–50ms | 한 문장+ | 문장 경계마다 윈도 검사 |
  | L4 벡터+LLM | 100ms~ | 전체 응답 | **streaming 경로 제외** — pre-LLM 입력 판정 또는 buffer-then-stream |
  | L5 PII | ms | 한 세그먼트 | 실시간 **redaction (마스킹)** — P-1 의 예외 역할 |
  | L6 LLM safeguard | 수백ms~ | 전체 응답 | **streaming 경로 제외** — pre-LLM 또는 buffer-then-stream |

  **Perplexity 신빙성 조건** — 일반적으로 최소 100 토큰 이상에서 안정적.
  한국어 기준 한 문장은 15–40 토큰 수준이라 문장 단위 perplexity 는
  noise-dominated. 짧은 응답은 현재 buffer-then-stream 경로가 오히려
  적합하며, streaming 경로에선 sliding window + multi-feature ensemble
  로 보강해야 한다.

  **L5 PII 의 예외 역할** ([P-1](#p-1-가드레일의-존재-이유--공격-방어차단)
  참조) — 차단이 아닌 **마스킹**이 주 목적이므로 redaction 형태의 실시간
  처리가 가능. 입력에 등장한 PII 원본 ↔ placeholder 매핑을 세션/턴 단위
  in-memory 테이블에 저장하고, 출력에 동일 값이 재출현하면 **원복(unmask)**
  까지 검토 중. 이 기능은 A2-b 에 종속되지 않는 별도 개선 주제로 추후
  정리 대상.

  **Streaming 활성화 조건** — tenant 정책이 fast-tier 만 enabled 이거나,
  사용자가 명시적으로 streaming 을 요청한 경우만 fast-tier 기반 streaming
  경로 사용. 그 외 기본은 buffer-then-stream (현재 동작 유지).

  ---

  **A2-c. Holdback buffer 기반 진짜 streaming (P1~P2, 큼)**

  - Provider (Solar/OpenAI/Ollama) streaming API 를 `llm_service` 에 추가.
  - Fast-tier 레이어가 요구하는 **최소 판정 토큰 수** 를 버퍼 크기 기준으로
    사용. 버퍼 = `max(실시간 레이어의 최소 판정 단위)`. Perplexity 는 A2-b
    에서 이미 streaming 경로 밖으로 배치했으므로 버퍼 크기 제약은 L3 문장
    경계 수준으로 충분.
  - 버퍼가 채워지면 누적 검사 → 안전 구간만 방출, 의심이면 추가 누적.
  - 실시간 BLOCK 발생 시 이후 청크 중단 + generic 종료 이벤트. A2-b 에서
    fast-tier 만으로 판정하므로 "되돌릴 수 없는 레이어에 의한 사후 BLOCK"
    문제가 구조적으로 발생하지 않음.
  - **A2-b 선행 필수**. Provider streaming 전환은 별도 tracking.

- **Priority**: A2-a **P1 (즉시)**, A2-b **P1**, A2-c **P1~P2**
  (provider streaming 도입 시점에 동기)
- **관련 코드**: `app/services/llm_service.py:141`,
  `app/routers/chat.py:194`, `app/routers/chat.py:930`,
  `app/routers/chat.py:67`, `app/routers/chat.py:72`,
  `app/static/index.html`

---

### A3. 차단 응답의 정보 유출 최소화

- **Why it matters**: 공격자는 차단 메시지를 **프로빙 채널**로 쓴다.
  어떤 레이어가 어떤 이유로 막았는지 알려주면 우회 프롬프트를 빠르게
  수렴시킬 수 있다. 다만 완전 통일 메시지("차단되었습니다")는 정상 사용자
  UX 를 해치므로, **공격 힌트는 제거하되 행동 변경 가이드는 남기는**
  균형점이 필요하다. Gemini 관점의 **B1(차단 안내문 UX)** 와 동일 근원.
- **Current state**: `_build_block_content()` 가 사용자 응답에 레이어
  번호(`L2(입력 보안)`) 와 레이어가 돌려준 원본 `reason` 문자열을 그대로
  노출. 관찰 모드에서는 `guardrail_reports` 에 `reason`, `severity`,
  `confidence`, `tags` 까지 전부 실린다.
- **Proposed change**: **3개 coarse taxonomy 카테고리** 로 매핑하고
  레이어 번호·원본 reason·severity·confidence·tags 는 전부 사용자 노출에서
  제거. 상세 정보는 operator-only audit 로그(A9) 로 분리.

  **① 카테고리 매핑 (3개 확정, 2026-04-23 논의)**

  | 사용자 노출 카테고리 | 매핑 레이어 | 사용자 안내문 (예시) |
  |---|---|---|
  | **정책 위반** | L1, L3, L6 (입력), L2 공격성 패턴 | "요청이 정책에 의해 차단되었습니다. 다른 표현으로 시도해 주세요." |
  | **개인정보 보호** | L5 (차단 모드), L2 sensitive 입력 | "개인정보가 포함된 요청은 처리할 수 없습니다. 민감 정보를 제외하고 다시 질문해 주세요." |
  | **응답 제한** | L4, L6 (출력), L2 sensitive 출력 | "요청하신 내용에 답변드릴 수 없습니다." |

  L5 PII 가 **마스킹(redaction) 모드** 로 동작하는 경우는 차단이 아니므로
  카테고리 매핑에서 제외 — 마스킹된 응답을 정상 전달하며, 필요 시 별도
  경고 필드로 클라이언트에 알림.

  **② 노출 범위**

  | 정보 | 사용자 | Operator (audit) |
  |---|---|---|
  | 차단됐다는 사실 | ✅ | ✅ |
  | 카테고리 (3개 중 하나) | ✅ | ✅ |
  | 레이어 번호 (L1~L6) | ❌ | ✅ |
  | 원본 `reason` 문자열 | ❌ | ✅ |
  | `severity` / `confidence` | ❌ | ✅ |
  | `tags` 배열 | ❌ | ✅ |

  **③ 관찰 모드 `guardrail_reports` 분리**

  - `guardrail_reports.public`: 카테고리 레벨 요약 (플레이그라운드/데모
    시각화에 사용).
  - `guardrail_reports.operator`: 전체 필드. operator 인증이 있는 경우만
    응답에 포함. 인증 없으면 미첨부.

  **④ 안내문 템플릿 외부화**

  - 카테고리별 문구를 리소스 파일(`app/i18n/block_messages.{ko,en}.json`
    등) 로 분리.
  - B2 (i18n) 와 함께 구현.

- **Priority**: **P1 (데모/개발 단계) → 외부 공개·실서비스 전환 시 P0 로
  상향** (2026-04-23 조정).
  - 현재는 **신뢰된 환경 내 데모·개발 단계**이며, 레이어 번호와 원본
    reason 을 투명하게 노출하는 것이 **개발자·QA 의 디버깅 자산**이자
    공격 시나리오 재현에 유리하다.
  - 공격자 프로빙 우려는 신뢰 범위 밖 사용자에게 API 가 노출될 때 실재화
    되므로, 그 시점(외부 공개/실서비스/공개 SaaS/멀티테넌시 도입 중 하나)
    이 이 항목의 **P0 재상향 트리거**다.
- **관련 코드**: `app/routers/chat.py:365`, `app/routers/chat.py:399`,
  `app/models/guardrail.py:17`

---

### A4. 분산 Replay 방어 저장소 — ADMIN 위임 경로

- **Why it matters**: Replay 방어는 인스턴스 간 **공유되지 않으면 무력화**
  된다. 로드밸런서 뒤에서 같은 nonce 를 다른 인스턴스로 보내면 통과한다.
  단, 현재는 **단일 인스턴스** 배포(`docker-compose.yml`) 이므로 이
  취약점은 아직 실현되지 않고 있다.
- **Current state**:
  - `NonceStore` 는 프로세스 메모리의 `dict + threading.Lock`
    (`app/services/request_verifier.py:120`). DI 로 프로세스 싱글턴.
  - **ADMIN backend 도 동일한 nonce/timestamp 검증을 수행 중** —
    `/api/v1/gateway/verify` 호출 시 ADMIN 쪽에서도 replay 체크. 즉
    현재는 게이트웨이/ADMIN 두 단계 검증이 **중복**으로 이뤄지고 있다.
  - 코드 주석에 "프로덕션에선 Redis 등 공유 저장소로 교체" 가 명시돼
    있으나, **Redis 도입은 현재 로드맵에 없음** (2026-04-23 저자 결정).
- **Proposed change**: **Phase 기반 접근** — Redis 도입 없이 단계적 해결.

  **Phase 0 — 현재 (단일 인스턴스 유지)**

  - `docker-compose.yml` 에 `deploy: replicas: 1` 명시적 락.
  - README / `docs/` 에 **"수평 확장 미지원, nonce 저장소는 프로세스
    메모리"** 경고 배너 추가.
  - 컨테이너 재시작 시 `skew_sec` 동안 replay 창 발생 가능 — **현 단계
    에선 수용** (SQLite 등 재시작 회복성 보강 불필요, 2026-04-23 결정).

  **Phase 1 — 수평 확장 도입 시점 (ADMIN 위임 채택)**

  게이트웨이 로컬 `NonceStore` 를 제거하고 **nonce 검증을 ADMIN 단일
  주체로 통합**. 채택 근거:

  1. ADMIN 이 이미 nonce/timestamp 검증을 동등하게 수행 중 → 현재 게이트웨이
     검증은 **중복 방어**. 이를 제거하면 책임 경계가 명확해짐.
  2. ADMIN 은 중앙 집중형이라 **자연스러운 공유 지점**. 별도 Redis/KV 없이도
     여러 게이트웨이 인스턴스가 동일 저장소를 참조하는 효과.
  3. 게이트웨이가 **완전 stateless** 가 됨 → 수평 확장 시 추가 인프라 없이
     `replicas` 만 올리면 됨.

  구체 구현 계약:
  - `POST /api/v1/gateway/verify` 응답에 "nonce 소비 결과" 를 명시적으로
    포함하도록 ADMIN 측 계약 확장:
    - 정상: 기존 정책 응답 그대로.
    - Replay 의심: HTTP 409 또는 응답 바디에 `"replay": true` 필드.
  - ADMIN 은 `INSERT ... ON CONFLICT DO NOTHING RETURNING` 같은 원자
    연산으로 nonce 저장 + 중복 판정 (ADMIN 의 기존 DB 재사용).
  - 게이트웨이는 기존 `HeaderVerificationError` 경로를 그대로 재사용 —
    라우터 레벨 응답 형태 변화 없음.
  - **ADMIN 부하 증가** 는 [A5 (ADMIN 정책 조회 캐싱·회로차단)](#a5-admin-정책-조회-캐싱회로차단fallback)
    와 함께 해결. Policy 는 캐싱 가능하지만 **nonce 소비는 캐싱 불가 —
    반드시 매 요청 호출해야 함**. 이 구분을 ADMIN 계약과 A5 설계에 반영.

  **대안 검토 (기각된 옵션)**

  - **Sticky session (LB consistent hash by X-API-Key)**: LB 설정만으로
    해결 가능하지만, ADMIN 이 이미 검증 중인 현 구조에서는 Option ③ (ADMIN
    위임) 쪽이 중복 제거 효과가 있어 우선. Phase 1 이후 ADMIN 부하가 과해
    지면 sticky session 을 **보조 완화책**으로 추가 고려 가능.

  **Phase 2 — 대규모/고부하 시점**

  - Redis 또는 분산 KV 도입 재검토. 그 시점엔 필요성이 명확해짐.

- **Priority**: **P1 (단일 인스턴스 현재 단계) → P0 재상향 트리거**:
  (a) `replicas ≥ 2` 도입, (b) autoscaling / k8s Deployment 전환,
  (c) 멀티 리전 / 멀티 클러스터. 이 중 하나라도 계획되는 시점.
- **관련 코드**: `app/services/request_verifier.py:120`,
  `app/services/request_verifier.py:157`, `app/dependencies.py:19`,
  `app/routers/chat.py:964`, `app/services/policy_service.py:79`
  (ADMIN `/verify` 확장 대상), admin-backend (`/api/v1/gateway/verify`
  핸들러)

---

### A5. ADMIN 정책 조회 — 회복성(A5-a) + 효율화·물리 분리(A5-b)

- **Why it matters**: 현재 `/api/v1/gateway/verify` 하나가 **① 요청 검증
  (nonce/timestamp/signature/bodyHash)** 과 **② 권한 확인 = 정책 조회
  (apiKey 의 활성 레이어/임계값)** 을 동시에 처리한다. 이 둘은 캐싱 특성이
  정반대다:

  | 관심사 | 캐싱 가능? | 호출 빈도 | 장애 영향도 |
  |---|---|---|---|
  | 요청 검증 (per-request) | **불가** (nonce 는 단일 소비) | 트래픽 = 1:1 | Replay 방어 본체 |
  | 정책 조회 (lookup) | **가능** (apiKey 당 드물게 변경) | 분당 ~1회로 충분 | 장애 시 stale fallback 가능 |

  즉 **캐싱 불가한 관심사가 캐싱 가능한 관심사를 같이 끌고 다니는 구조**
  이기 때문에, 게이트웨이는 정책이 안 바뀌어도 매 요청 ADMIN 을 때리고,
  ADMIN 장애 시 정책은 캐시하면 살 수 있는데도 전체 요청이 실패한다.

- **Current state**: 모든 요청이 `/api/v1/gateway/verify` 를 호출.
  - timeout 5초 상수 hard-coded (`policy_service.py:22`)
  - 캐시/재시도/회로차단기/stale fallback 없음
  - 실패 시 `httpx.HTTPError` 전파 → 요청 전체 실패 (`policy_service.py:135`)
  - ADMIN 에는 `apiKey/timestamp/nonce/bodyHash/signature` 만 전달 (원본
    body 미전송)
  - `verify_and_fetch_policy()` 한 메소드가 **두 관심사를 동시에 반환**
    (`policy_service.py:79`)

---

#### A5-a. 회복성 강화 (경로 무관 공통 개선)

물리적 분리 전/후 모두 적용 가능한 5개 공통 개선. A5-b 와 독립 진행 가능.

- **Proposed change**:
  1. **Connect / read timeout 분리** — 현재 5초 단일 값 → `connect ≤ 500ms`,
     `read ≤ 2s` 로 분리. 커넥션 풀 고갈 상황에서 빠른 실패 유도.
  2. **짧은 retry budget** — idempotent 경로(GET 정책 조회)에 한해
     `100ms × 2회` 지수 백오프. 요청 검증(POST, nonce 소비)은 재시도 금지
     — 중복 소비 위험.
  3. **회로차단기 (pybreaker 등)** — 연결 실패·타임아웃 급증 시 동기 폭주
     차단. half-open 상태로 자동 회복.
  4. **`stale-if-error` fallback** — 마지막 검증된 정책(A5-b 이후엔 폴링
     캐시) 이 있으면 제한적으로 사용. 없으면 fail-safe 503 또는 "최소 안전
     정책"(전 레이어 BLOCK). 정책 선택은 `ADMIN_FALLBACK_MODE` 환경변수.
  5. **Health degradation 메트릭** — 회로차단 발동 / stale 적중률 /
     ADMIN 레이턴시 분포를 `/metrics` 로 노출. [A10 fail-open 관측](#a10-fail-open-관측-가능성과-알람) 과 연동.
- **Priority**: **P1**. 물리 분리(A5-b) 가 지연되어도 이 5개는 현 단일
  엔드포인트 구조에서도 바로 효과가 나온다.

---

#### A5-b. 물리적 엔드포인트 분리 + 정책 폴링 캐시

ADMIN 팀 계약 변경 포함. **[A4 Phase 1 (ADMIN 위임 nonce 소비)](#a4-분산-replay-방어-저장소--admin-위임-경로)** 과 동기화.

- **Proposed change — ADMIN 계약**:

  | 신규 엔드포인트 | 메소드 | 입력 | 출력 | 캐싱 |
  |---|---|---|---|---|
  | `/api/v1/gateway/verify` | POST | `apiKey/timestamp/nonce/bodyHash/signature` | `{ok, replay?}` | **금지** (nonce 소비) |
  | `/api/v1/gateway/policy` | GET | `apiKey` (or operator token) | `{policy, version, etag}` | **가능** (`ETag` / `Last-Modified` 지원) |

  - 기존 `verify_and_fetch_policy()` 를 **두 메소드로 분해**:
    `verify_request()` + `fetch_policy()`. 호출 계약과 실패 모드가 분리됨.
  - `/verify` 는 **원자 연산만** (nonce INSERT ON CONFLICT + 응답 200/409).
  - `/policy` 는 **read-only**. HTTP 캐시 헤더 완전 지원 → 304 Not Modified
    재활용.

- **Proposed change — 게이트웨이 동작**:
  1. **정책 조회 = 능동 polling** — 게이트웨이가 **60초 주기**로 ADMIN
     `/policy` 호출. `If-None-Match` / `If-Modified-Since` 포함한 Conditional
     GET → 변경 없으면 304, 본체 transfer 없음. 안정된 정책은 자주 변경되지
     않는다는 전제에서 60초로 충분.
  2. **±10–20% jitter** — 다중 인스턴스의 thundering herd 방지. polling
     시점을 분산시켜 ADMIN 집중 부하 회피.
  3. **로컬 TTL 캐시** — apiKey → policy 매핑. 폴링 결과로 atomically 갱신.
     요청 핫패스는 **로컬 dict lookup 만**, ADMIN 호출 제거.
  4. **push / webhook 은 P2 로 보류** — 현재 단계에선 능동 polling 으로
     충분. ADMIN 이 정책 변경 이벤트를 push 하는 구조는 장기 고도화.
  5. **N 인스턴스 부하 증가 걱정에 대한 답**: Conditional GET 으로 본체는
     대부분 전송되지 않고, ADMIN DB 조회는 policy 변경 여부만 확인하는
     경량 질의가 된다. `N × (60초당 1회 304 응답)` 수준이므로 인스턴스
     수 증가에 선형 증가하지만 본체 payload 가 없어 실질 부하는 미미.
     대규모 시점엔 push 구조로 전환.

- **Proposed change — ADMIN 팀에 전달할 "Why + What"**:

  > **Why** — 현재 `/verify` 단일 엔드포인트가 두 가지 관심사 (per-request
  > 보안 검증 vs. apiKey 정책 조회) 를 같이 반환해서, 게이트웨이는 정책이
  > 바뀌지 않아도 매 요청 ADMIN 을 호출합니다. apiKey 의 레이어 활성
  > 정책은 분 단위로 변하지 않으므로 **물리적으로 분리**해 정책만 HTTP
  > 캐싱 가능한 형태로 내려받고 싶습니다. 이렇게 하면 (1) ADMIN 부하가
  > 정책 변경 시점에만 집중되고, (2) 장애 격리가 생기며 (policy 저장소
  > 장애가 인증 경로를 멈추지 않음), (3) 정책의 지연 갱신(lazy refresh)
  > 도 단순해집니다.
  >
  > **What**:
  > 1. `GET /api/v1/gateway/policy?apiKey=...` 신규 추가. 응답에 `ETag`,
  >    `Last-Modified` 헤더 포함. `If-None-Match` → 304 처리.
  > 2. 기존 `POST /api/v1/gateway/verify` 는 nonce 소비와 signature 검증
  >    전용으로 슬림화. 정책 필드 제거 (또는 당분간 deprecated 필드로
  >    유지, Phase 2 에 제거).
  > 3. ETag 는 apiKey 별 정책 document 의 hash 권장. 변경 시에만 갱신.

- **회피된 대안**:
  - **응답 필드만 분리 (단일 엔드포인트 유지)**: 지금 초안 단계에선
    편의성이 있지만 **캐싱 불가 관심사가 그대로 끌고 다니는 문제가 해결
    안 됨**. `/verify` 응답을 HTTP 캐싱할 수 없으므로 ETag/304 활용도
    불가. 물리 분리로 갑니다.
  - **Redis / 공유 KV 도입**: [A4 의사결정](#의사결정-6--a4-분산-replay-방어-redis-없이-admin-위임-채택)과 동일 — 현 단계에선
    과잉 인프라.

- **Priority**: **P2**. A5-a 회복성이 P1 에서 체감 효과가 크고, 물리 분리는
  ADMIN 팀 계약 변경이 필요한 **크로스팀 변경**이라 timing 을 맞춰야 함.
  **P1 재상향 트리거**: ADMIN 실측 QPS 가 현재의 2배 이상으로 증가하거나,
  [A4 Phase 1 ADMIN 위임](#a4-분산-replay-방어-저장소--admin-위임-경로) 과
  함께 묶어 진행하기로 결정될 때.

- **관련 코드**: `app/services/policy_service.py:22` (timeout 상수),
  `app/services/policy_service.py:79` (`verify_and_fetch_policy` 분해 대상),
  `app/services/policy_service.py:132` (`httpx.post` timeout 적용 지점),
  `app/routers/chat.py:991`, `app/main.py:345` (의존성 주입 지점)

---

### A6. 네트워크 경계 하드닝 — 무분별 요청 / 악의적 남용 방어

- **Why it matters — 게이트웨이가 실제로 맞닥뜨릴 4가지 위협**:
  1. **경제적 DoS** — `/v1/chat/completions` 는 요청 1건당 **업스트림 LLM
     토큰 비용**이 직접 발생한다. 서버 CPU 가 터지기 전에 **Upstage/OpenAI
     과금**이 먼저 터진다. 공격자가 적은 RPS 로도 긴 context 를 흘려
     보내면 비용만 빠르게 고갈시킬 수 있음.
  2. **리소스 고갈** — body bomb(거대 JSON), slow loris(느린 연결 유지),
     파이프라인 장시간 점유로 **워커/메모리/업스트림 연결 pool** 을 고갈.
  3. **유효 key 남용 / 탈취** — 현재 인증은 `X-API-Key` + HMAC 서명
     (`X-Timestamp` / `X-Nonce` / `X-Signature`) 네 종뿐이다. 이는 "이
     key 소유자가 정당하게 서명했다"만 증명할 뿐, **key 보유자 본인이
     악의적으로 퍼붓는 경우**나 **key 가 유출돼 공격자 손에 들어간 경우**는
     전혀 막지 못한다. HMAC 는 *위변조 방지*이지 *남용 방지*가 아니다.
  4. **가드레일 우회 brute force** — 같은 key 가 단시간에 프롬프트를
     조금씩 바꿔가며 반복 BLOCK 을 유발, 우회 패턴을 탐색. 일반 API 와 달리
     **가드레일 서비스 특유의 남용 패턴**으로, 단순 RPS 제한으로는 식별이
     어렵다.
- **Current state**:
  - 인증: `X-API-Key` + HMAC 서명 4종 헤더. ADMIN 이 `/verify` 로 key 유효성
    + nonce + timestamp 만 검증. **"유효한 key 가 남용되는지"는 검증 경로에
    없다**.
  - `CORSMiddleware(allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])`
    — 모든 origin 허용.
  - 레이트리밋 없음. API key 당 / IP 당 / tenant 당 **어떤 한도도 없다**.
  - 요청 body 크기 상한 없음. `max_tokens` / `messages` 총 길이 상한 없음.
  - concurrency cap 없음. request-level timeout 없음.
  - LLM 토큰 예산(일/월) 개념이 없어 **비용 기반 남용 탐지 불가**.
  - **요지**: 현재 게이트웨이는 "헤더 서명이 맞는 요청" 이면 무제한으로
    업스트림 LLM 에 그대로 흘린다. 악의적 요청을 막을 장치가 사실상 없음.
- **Proposed change — 계층별 방어**:

  현재 5개를 동일 선상에서 "P0 일괄"로 두지 말고, **공격자가 도달하는 순서
  대로 점점 더 정교한 방어선**을 둔다. 값싸게 버릴 것은 앞에서, 비싼 판단은
  뒤에서 한다.

  **L1. Cheap reject — LLM 호출이 일어나기 전에 버린다** *(P0)*
  1. **Body 크기 상한** (ASGI middleware) — 요청 body bytes, JSON depth,
     배열 길이, `messages` 총 토큰 수 상한. 이걸로 body bomb 과 token
     flood 를 *과금 전*에 차단.
  2. **Request read timeout** — 느린 업로드 / slow loris 방어. uvicorn /
     FastAPI 양쪽에 명시.
  3. **Per API-key rate limit** (slowapi + Redis 또는 동등물) — 초당 /
     분당 RPS 한도. 남용 signal 의 1차 차단선.
  4. **Per source IP rate limit** — API key 전에 적용되는 보조 방어.
     NAT/프록시로 노이즈가 있지만, 미인증 flooding 과 key brute-force
     시도를 걸러냄.
  5. **CORS allowlist** — 브라우저 클라이언트가 실제로 필요한 origin 만
     허용. 현재 데모 단계는 서버-서버가 주이므로 **CORS 자체를 닫는
     것**도 유력한 선택지.

  **L2. Economic guard — LLM 토큰 비용을 진짜로 막는다** *(P1)*
  6. **Per-key 일/월 토큰 예산** — RPS 만으로는 "적은 요청 × 긴 context"
     형태의 비용 공격을 못 막는다. 토큰 사용량 누적을 키별로 집계,
     예산 초과 시 429 + ADMIN 알람. **A6 의 핵심 방어선.**
  7. **Request 당 상한** — `max_tokens` / `messages` 총 토큰 상한을
     정책으로 강제. 정책은 ADMIN 이 key 별로 달리 내려줄 수 있어야 함
     (A5-b `/policy` 와 연계).
  8. **Per-key / per-tenant concurrency cap** — 동시 in-flight 요청 수
     상한. 한 key 가 워커와 업스트림 연결 pool 을 독점하는 상황 방지.

  **L3. Abuse detection — 가드레일 서비스 특유의 남용 신호** *(P1)*
  9. **BLOCK 반복 탐지** — 같은 key 가 짧은 시간창 안에 BLOCK 을 **N회
     이상** 연속으로 유발하면 단기 suspend + ADMIN 알람. 가드레일 우회
     brute-force 의 가장 강한 signal.
  10. **요청량 급변 감지** — 키 baseline 대비 M× 이상 급증 시 step-up
      또는 shedding. A10 (fail-open 메트릭) 인프라와 공유 가능.

  **L4. Edge — 앱 밖에서 처리할 것** *(P2)*
  11. **TLS 종료 / WAF / 국가·IP blocklist / DDoS 흡수** — 앞단 프록시
      (nginx / envoy / CDN) 책임으로 **분리**. 앱 안에 넣어 "이중 방어"
      하지 않는다. 중복·오버엔지니어링이 되고, P0 범위만 비대해진다.

- **HMAC 와 남용 방어의 경계 명시**: HMAC 4종 헤더는 **transport 무결성
  보장**이지 **남용 방어 기능이 아니다**. 남용 방어는 L1–L3 가 담당하며,
  HMAC 검증을 통과한 뒤에 적용된다. 문서와 에러 코드(B4)에도 이 경계를
  명시해 "서명이 맞는데 왜 429?" 같은 혼동을 방지.
- **Priority**:
  - **P0** — L1 전부 (Body/timeout/key RPS/IP RPS/CORS)
  - **P1** — L2 (토큰 예산, per-request 상한, concurrency cap) + L3 (BLOCK
    반복 탐지, 급변 감지)
  - **P2** — L4 (앞단 프록시 체계)
- **관련 코드**: `app/main.py:191`, `app/main.py:202`,
  `app/routers/chat.py:924`, `app/routers/chat.py:689` (`skip_header_verification`
  경로 — L1 rate limit 은 이 우회 플래그 아래에서도 반드시 적용되어야 함).
- **ADMIN 연계 (A5-b 와 동기화)**: 토큰 예산 한도·concurrency cap·BLOCK
  반복 임계값 등은 **key 별 정책**이므로 `/policy` 응답 스키마에 포함시킨다.
  A5-b 계약 변경 proposal 에 L2/L3 파라미터 필드를 함께 제안.

---

### A7. Observe 모드의 운영 가드 — APP_ENV=dev 게이트 (구현 완료)

- **Why it matters**: BLOCK 이 나와도 **원본 LLM 응답을 계속 사용자에게
  돌려주는** 모드는 운영 실수 한 번으로 보안 통제를 무효화한다. 관찰 모드
  자체는 데모·디버깅 자산으로 가치가 크므로 기능을 없애는 대신 **프로덕션
  활성화를 기술적으로 불가능하게** 만든다.
- **Current state (2026-04-24 기준)**:
  - 관찰 모드 기능은 유지 (`_run_observe_mode_pipeline` / `guardrail_reports`
    응답 필드 / Swagger 예시 전부 그대로). 레이어별 판정을 시각화하는 데모
    자산으로 B3 (관찰 모드 UI 시각화) 와 계속 엮여 있음.
  - `Settings` 에 `app_env: Literal["dev", "prod"] = "prod"` 필드 + 기동 시
    `model_validator(mode="after") _observe_mode_requires_dev` 추가. `app_env
    != "dev"` 상태에서 `continue_on_layer_failure=True` 면 **`Settings()`
    생성 시점에 `ValidationError`** 로 프로세스가 기동하지 않는다.
  - 기본값은 `"prod"` (safe-by-default) — `.env` 에 `APP_ENV` 를 명시하지
    않으면 자동으로 잠긴다. `Literal` 덕에 `"staging"` 같은 오타도 기동 시
    거부된다.
  - README 경고문은 "권고" 에서 "기술적으로 차단됨" 으로 격상. Swagger /
    `ChatResponse.guardrail_reports` docstring 에도 `APP_ENV=dev` 조건을
    병기.
- **Proposed change — 범위 축소 및 구현 상태**:
  1. **`APP_ENV=prod` 기동 실패** — **구현 완료**
     (`app/config.py:72` `_observe_mode_requires_dev`). 요청 경로 변경 없이
     config 한 곳에서 강제.
  2. **2-step approval lease (ADMIN signed approval)** — **범위 축소·보류**.
     현재 데모 단계에서는 복잡도 대비 이득 부족. P2 재상향 트리거를 명시:
     (a) 공개 SaaS 전환, (b) 멀티테넌시 도입, (c) 고객에게 "디버그 모드
     토글" 을 API 로 노출. 그 전까지 (1) 만으로 충분.
  3. **운영자 전용 수집 채널** — 유지. 단, 관찰 모드 자체가 dev 전용이므로
     `guardrail_reports` 가 사용자 응답에 섞여 나가는 구조는 이미 실질적
     분리 상태. B3 (관찰 모드 UI 시각화) 와 동기 구현.
- **HMAC 와의 경계**: `X-API-Key` + HMAC 4종 헤더는 *요청 검증*. `APP_ENV`
  가드는 *기동 계약* — 프로세스가 시작될 수 있느냐의 문제. 두 검증은
  서로 독립적이며 HMAC 가 아무리 완벽해도 `APP_ENV=prod` 에서는 관찰 모드
  자체가 켜질 수 없다. `skip_header_verification` 과 함께 쓰이는 데모
  시나리오는 양 플래그 모두 `APP_ENV=dev` 에서만 의미가 있어 A11 (`SKIP_*`
  prod-safe 가드) 과 같은 방향으로 수렴.
- **Priority**: **P0 — (1) 구현 완료**. (2) 2-step lease 는 위 트리거
  충족 시 재검토 (사실상 P2 로 이동). (3) 운영자 전용 채널은 B3 와 동기.
- **관련 코드**: `app/config.py:57` (`app_env`), `app/config.py:72`
  (`_observe_mode_requires_dev`), `app/routers/chat.py:1012` (observe 진입),
  `app/routers/chat.py:475` (`_run_observe_mode_pipeline`),
  `tests/unit/test_config.py` (dev 허용 / prod 거부 / 미설정 거부 / 오타 거부
  테스트).

---

### A8. 진단 엔드포인트 인증·권한 분리

- **Why it matters**: 레이어별 `effective / signals / model_paths` 는
  **공격자에게 우회 힌트**다. 공개로 둘 이유가 거의 없다.
- **Current state**: `/v1/layers/status` 는 인증 없이 호출 가능하며
  `model_loaded`, `effective`, `signals`, `model_paths`, `detail` 을 그대로
  반환. `/health` 도 readiness 분리 없이 공개.
- **Proposed change**:
  1. `/health/live`: 최소 생존 신호만 (공개 가능).
  2. `/health/ready`: 내부 오케스트레이터용 (내부망 ACL).
  3. 상세 진단(`/v1/layers/status`, 추후 `/admin/...`) 은 admin key +
     mTLS + 내부망 ACL 중 하나 이상으로 보호.
  4. 외부 공개가 꼭 필요하면 `signals/model_paths/detail` 제거, coarse
     상태만 남김.
- **Priority**: **P0**
- **관련 코드**: `app/routers/layers.py:95`,
  `app/services/layer_diagnostics.py:320`, `app/main.py:284`

---

### A9. 민감 로그 정리와 구조화 audit log

- **Why it matters**: 보안 게이트웨이는 **차단보다 로그에서 먼저 새는**
  경우가 많다. API key·프롬프트 본문·ADMIN 응답 원문이 INFO 로그에 남으면
  내부자·로그 수집기·장기 보관소가 모두 유출면이 된다.
- **Current state**:
  - `policy_service.py:122-126`: 게이트웨이 `X-API-Key` 값과 verify
    payload 전체, ADMIN 응답 body 를 **INFO** 로 기록 (주석에 "운영
    환경에서는 제거/DEBUG 하향" 명시되어 있지만 미조치).
  - `chat.py`: 요청 수신 시 메시지 content 를 요약해 INFO 로그.
  - 구조화 audit log 저장 경로 없음.
- **Proposed change**:
  1. 운영 기본값: raw prompt / raw completion / raw admin payload / full
     API key 를 **로그에 남기지 않음**. API key 는 `prefix_hash` 형태만.
     본문은 length·hash·분류 결과만.
  2. 보안 이벤트 전용 **audit log 스키마** 도입:
     `request_id`, `tenant`, `decision` (pass/block/observe), `blocked_stage`,
     `public_reason_code`, `layer_results`, `policy_version`, `operator_view`.
  3. 원문 샘플이 꼭 필요하면 별도 암호화 저장소 + 짧은 TTL + 엄격한
     권한 (operator role) 으로 분리.
- **Priority**: **P0**
- **관련 코드**: `app/services/policy_service.py:114`,
  `app/routers/chat.py:116`, `app/routers/chat.py:955`

---

### A10. fail-open 관측 가능성과 알람

- **Why it matters**: fail-open 자체보다 **"조용한 fail-open"** 이 더
  위험하다. 레이어가 빠져도 요청은 성공하므로 계측·알람이 없으면 운영자는
  보호 손실을 모른 채 지나간다.
- **Current state**: 레이어 미매핑·`NotImplementedError` 는 PASS.
  운영자 가시 신호는 기동 로그 + `/v1/layers/status` 뿐. Prometheus/OTel
  메트릭·트레이스·알람 훅 없음.
- **Proposed change**:
  1. 필수 메트릭:
     - `guardrail_fail_open_total{layer,reason}`
     - `guardrail_layer_effective{layer}`
     - `guardrail_block_total{stage,layer}`
     - `admin_verify_latency` / `admin_verify_error_total`
     - `skip_flag_enabled` / `observe_mode_enabled` (gauge, 켜지면 1)
  2. OTel span: `header_verify → policy_fetch → input_guardrail → llm_call
     → output_guardrail → response_emit` 을 하나의 trace 로 연결.
  3. 알람: `effective=false` 지속, fail-open 급증, admin circuit open,
     observe mode/skip flag 활성화 시 즉시 알람.
- **Priority**: **P1**
- **관련 코드**: `app/services/security_layer_service.py:199`,
  `app/services/layer_diagnostics.py:444`, `app/routers/chat.py:105`

---

### A11. SKIP_* 우회 플래그 prod-safe 가드

- **Why it matters**: 보안 우회 플래그는 **"로컬 전용" 문서화만으로는
  부족**하다. prod 환경에 값 하나가 잘못 들어가면 헤더 검증 또는 정책 조회
  전체가 꺼진다.
- **Current state**: `skip_header_verification` / `skip_policy_fetch` 가
  `Settings` 에 그대로 노출되고 라우터에서 조건문만으로 즉시 우회.
  프로덕션 차단 로직/기동 보호장치 없음.
- **Proposed change**:
  1. `APP_ENV=prod` 에서 둘 중 하나라도 `true` 면 **startup failure**.
  2. 빌드 프로필 분리 (dev/staging/prod 별 허용 플래그 집합).
  3. 기동 시 "unsafe config detected" 경고 메트릭 + `/health/ready` 에
     unsafe 상태 반영.
  4. 서명된 개발용 override token 없이는 활성화 불가 (옵션).
- **Priority**: **P0**
- **관련 코드**: `app/config.py:46`, `app/routers/chat.py:672`,
  `app/routers/chat.py:991`

---

### A12. Readiness vs Liveness 분리

- **Why it matters**: 대형 모델 로드가 길거나 실패하면 오케스트레이터는
  **"살아있지만 미준비"** 와 **"죽음"** 을 구분해야 한다. 구분이 없으면
  무한 재시작 또는 조용한 보호 손실 발생.
- **Current state**: `layer_registry.py` 는 모듈 import 시 L1~L6 싱글턴을
  즉시 인스턴스화 (~7GB, 1~3분 소요). `/health` 는 항상 `{"status":"ok"}`
  만 반환. Readiness 판단에 레이어 로드/effective 상태 미반영.
- **Proposed change**:
  1. `/health/live`: 프로세스 이벤트 루프 생존만.
  2. `/health/ready`: "최소 필수 레이어 + 정책 조회 경로 + nonce 저장소
     + admin circuit" 준비 여부.
  3. 레이어 로드를 lazy/background warmup 으로 전환 (첫 요청 전 warmup
     완료되도록 기동 훅 추가).
  4. 필수 레이어가 `effective=false` 면 `ready=false` 또는 `degraded`
     로 표면화.
- **Priority**: **P1**
- **관련 코드**: `app/services/layer_registry.py:14`, `app/main.py:80`,
  `app/main.py:284`, `app/routers/layers.py:101`

---

### A13. 회귀 시나리오 체크리스트

- **Why it matters**: 이 게이트웨이는 보안·가용성·호환성 요구가 동시에
  걸려 있어 **수정 후 회귀가 기능 버그보다 위험**하다.
- **Current state**: 단위 테스트는 chat router / policy fetch / nonce
  verifier / layer converter / layer diagnostics 주변에 집중. 분산 replay,
  prod-safe 플래그, 진짜 streaming, 진단 엔드포인트 권한화 관련 통합
  테스트 부재.
- **Proposed change**: 아래 표를 최소 회귀 세트로 고정하고 단위 + 통합 +
  다중 인스턴스 시뮬레이션 레이어로 나눠 자동화.

  | 회귀 시나리오 | 기대 결과 | 우선순위 |
  |---|---|---|
  | `system` 메시지에 jailbreak 지시 삽입 | 입력 BLOCK 또는 위험 점수 상승 | P0 |
  | 이전 `assistant`/`tool` 응답에 주입 페이로드 포함 | 멀티턴 누적 기준 차단 | P0 |
  | `tools.function.description` / `tool_choice` 에 인젝션 포함 | 정의 영역도 검사되어 BLOCK | P0 |
  | multimodal `image_url` / non-text part 포함 요청 | 텍스트 외 필드 정책 적용 또는 명시적 거부 | P0 |
  | 두 인스턴스에 동일 nonce 재전송 | 한 번만 통과, 나머지는 replay 실패 | P0 |
  | ADMIN 일시 장애 + 캐시 보유 | stale 정책 또는 fail-safe 정책으로 일관 처리 | P0 |
  | ADMIN 장애 + 캐시 미보유 | 보안 약화 없이 503 또는 최소 안전 정책 | P0 |
  | 차단 응답 외부 노출 검증 | 레이어 번호/원본 reason/tags 비노출 | P0 |
  | `/v1/layers/status` 무인증 호출 | 401/403 또는 내부망 전용 차단 | P0 |
  | `SKIP_*` 또는 observe 모드가 prod 설정으로 기동 | startup failure | P0 |
  | observe 승인 lease 없이 활성화 시도 | 활성화 거부 | P0 |
  | streaming 출력 검사 중 중간 청크에서 BLOCK | 안전 경계까지 방출 후 종료/마스킹 | P1 |
  | 필수 레이어 로드 실패 | `/health/live`=200, `/health/ready`=실패 또는 degraded | P1 |
  | fail-open 발생 | 메트릭 증가, 트레이스 태깅, 알람 훅 호출 | P1 |

- **Priority**: **P2** (체크리스트 자체는 P2. 개별 시나리오는 위의 P0/P1
  우선순위를 따른다)
- **관련 코드**: `app/routers/chat.py:924`,
  `app/services/policy_service.py:79`, `app/services/request_verifier.py:120`,
  `app/routers/layers.py:95`, `tests/unit/`

---

## PART B. UX·문서·개발자 경험 (Gemini 관점)

### B1. 차단 안내문 UX

- **현재 상태**: `L2(입력 보안)` 등 내부 레이어 번호와 원본 `reason`
  문자열을 사용자 메시지에 그대로 노출. 스트리밍에서도 문자 단위로 흘려
  보낸다.
- **사용자가 겪는 불편**: 일반 사용자는 "L2" 가 무엇인지 알 수 없고,
  기술적 사유 노출은 공격자에게 우회 힌트를 제공한다 (→ **A3 과 동일
  근원**).
- **제안**: [A3](#a3-차단-응답의-정보-유출-최소화) 에서 확정한 **3개
  coarse taxonomy** (정책 위반 / 개인정보 보호 / 응답 제한) 를 그대로
  사용자 측에 적용. B1 은 A3 의 UX 구현 표면.
  1. 내부 레이어 번호·원본 `reason` 을 숨기고 3개 카테고리 중 하나로
     매핑된 안내문만 노출.
  2. `reason` 은 **개발자용(상세, operator-only audit log)** 과
     **사용자용(요약, coarse taxonomy)** 으로 분리.
  3. "다른 표현으로 시도" 외에 카테고리별 구체 행동 가이드 (예: "민감
     정보를 제외하고 다시 질문해 주세요").
- **우선순위**: **P1 (데모/개발 단계) → 외부 공개 시 P0** — A3 와 동기
  조정. 데모 단계에서는 차단 사유의 투명한 노출이 개발/QA 의 디버깅 자산
  이므로 현 시점에는 블로커가 아님.
- **참조 에셋**: `app/services/security_layer_service.py`,
  `app/routers/chat.py` (`_build_block_content`),
  [A3 카테고리 매핑 테이블](#a3-차단-응답의-정보-유출-최소화)

---

### B2. 다국어(i18n) 대응

- **현재 상태**: 안내문·로그·`/docs` 설명이 한국어 하드코딩.
- **사용자가 겪는 불편**: 글로벌 사용자에게 한글 차단 안내가 노출되어
  가독성·신뢰도가 급락.
- **제안**:
  1. `Accept-Language` 헤더에 따라 `ko` / `en` 메시지 동적 선택.
  2. `config.py` 에 `DEFAULT_LANGUAGE` + 언어별 메시지 맵 (또는 gettext
     / babel 채택).
  3. 차단 안내문/카테고리 라벨/에러 메시지를 분리된 리소스 파일로 외부화.
- **우선순위**: **P1**
- **참조 에셋**: `app/config.py`, `app/services/security_layer_service.py`,
  `app/routers/chat.py`

---

### B3. 관찰 모드 UI 시각화

- **현재 상태**: `guardrail_reports` 블록이 JSON 으로만 응답에 실린다.
- **사용자가 겪는 불편**: 플레이그라운드에서 어떤 레이어가 감지했는지,
  `severity` / `confidence` 가 어떤지 직관적으로 파악 불가.
- **제안**:
  1. 플레이그라운드 우측/하단에 **Guardrail Insights** 패널 추가.
  2. L1~L6 레이어별 통과/차단 상태를 타임라인 또는 신호등 UI 로 시각화.
  3. `severity` 에 따른 컬러 코딩 (Red/Yellow/Green).
  4. A3 가 외부 공개 스키마와 operator 스키마를 나눈다면, 플레이그라운드
     에서는 **operator view** 를 허용 (demo/debug 용).
- **우선순위**: **P1**
- **참조 에셋**: `app/static/index.html`, `app/models/guardrail.py`

---

### B4. 에러 코드 카탈로그

- **현재 상태**: `header_verification_failed` 외 상세 에러 코드 체계 부재.
  401/502 등 HTTP 레벨 코드만 있고 원인 구분이 없다.
- **사용자가 겪는 불편**: 통합 시 401/403/502 원인 (키 만료 vs 서명 불일치
  vs 모델 로드 중) 을 알 수 없어 디버깅 시간 급증.
- **제안**:
  1. `GW-ERR-001` (Signature Mismatch), `GW-ERR-002` (Timestamp Skew)
     등 고유 에러 코드 체계.
  2. `/docs` 에 **Error Catalog** 섹션 추가 (코드·HTTP status·원인·해결
     방법 테이블).
  3. A9 의 구조화 audit log 와 같은 에러 코드 사용 → 운영/고객지원 양쪽
     에서 동일 어휘.
- **우선순위**: **P0**
- **참조 에셋**: `app/errors.py`, `docs/architecture-overview.md`

---

### B5. 공식 클라이언트 SDK

- **현재 상태**: 4종 HMAC 헤더를 사용자가 직접 생성해야 함. SDK 미제공.
- **사용자가 겪는 불편**: 서명 로직 구현 시 timestamp/nonce/body hash
  처리에서 잦은 실수. OpenAI SDK 와의 직관적 병행 사용 어려움.
- **제안**:
  1. 공식 **Python SDK** (`pip install agentic-guardrail-client`) +
     **TypeScript SDK** 배포.
  2. OpenAI SDK 를 래핑하는 미들웨어/어댑터 제공: `base_url` + `api_key`
     + `secret` 만 넣으면 서명 헤더 자동 생성.
  3. LangChain / LiteLLM 사용자용 어댑터도 병행.
- **우선순위**: **P0**
- **참조 에셋**: `app/services/request_verifier.py`, `README.md`

---

### B6. 플레이그라운드 고도화

- **현재 상태**: 정적 HTML 수준의 기본 기능. 정책 시뮬레이션 불가, 서명
  자동 생성 UI 유무 불명확.
- **사용자가 겪는 불편**: 특정 레이어만 끄고 테스트하거나 현재 정책을
  확인하며 실험하기 어렵다.
- **제안**:
  1. 현재 활성 정책(L1~L6) 상태를 화면 상단에 표시 (`/v1/layers/status`
     연동, A8 의 coarse 스키마 기준).
  2. "서명 자동 생성" 체크박스 → 수동 헤더 입력 없이 테스트.
  3. BLOCK 시 raw JSON 과 렌더링된 안내문을 비교 뷰로 노출.
  4. **차단 모드 / 관찰 모드 토글** — 단, **프로덕션 빌드에서는 관찰 모드
     토글 비활성화** (A7 과 일관).
- **우선순위**: **P1**
- **참조 에셋**: `app/static/index.html`, `app/routers/layers.py`

---

### B7. 영어 문서 / 이중 언어화

- **현재 상태**: README·docs 가 한국어 위주. Swagger 타이틀/설명도 한글.
- **사용자가 겪는 불편**: 해외 오픈소스 커뮤니티·글로벌 팀 검토 시 진입
  장벽.
- **제안**:
  1. `README.en.md` 작성 (핵심 섹션부터 우선).
  2. `/docs` 의 `summary` / `description` 을 영어 병기 또는 언어 토글.
  3. OpenAPI `info.description` 은 최소한 영어 버전도 함께.
- **우선순위**: **P1** (외부 공개 시점에는 P0 로 상향)
- **참조 에셋**: `README.md`, `app/main.py` (FastAPI metadata)

---

### B8. 관측 대시보드

- **현재 상태**: 개별 요청 로그만 존재. 집계·통계·히트맵 없음.
- **사용자가 겪는 불편**: 어떤 레이어가 가장 많이 차단되는지, 특정 시간대
  공격 집중 여부를 알 수 없음.
- **제안**:
  1. A10 의 메트릭을 Grafana 대시보드로 시각화 (BLOCK 히트맵, 레이어별
     p50/p95 레이턴시, fail-open 발생률).
  2. `/v1/stats/layers` (운영자 전용) 엔드포인트 추가 — 시간별 BLOCK
     카운트 / 레이어별 히트율.
  3. A9 의 audit log 를 대시보드 원천으로 사용.
- **우선순위**: **P2**
- **참조 에셋**: `app/services/layer_diagnostics.py`, A10 메트릭 스키마

---

### B9. ADMIN 통합 플로우 다이어그램

- **현재 상태**: 게이트웨이 ↔ admin-backend 위임 구조가 텍스트 위주.
- **사용자가 겪는 불편**: API Key 발급처 / 서명 검증 주체 / 정책 조회
  타이밍 혼동으로 아키텍처 이해에 혼선.
- **제안**: 다음을 담은 **시퀀스 다이어그램 + 상태 다이어그램**:
  - Key 발급(Admin UI) → Gateway Call → Admin `/verify` 위임 → Policy
    Fetch → L1~L6 → LLM → Output Check → User
  - NonceStore / 캐시 / 회로차단기 경로
- **우선순위**: **P1**
- **참조 에셋**: `docs/architecture-overview.md`

---

### B10. 대안 가드레일 벤치마킹

- **현재 상태**: NeMo Guardrails / Guardrails AI / Lakera Guard / Azure AI
  Content Safety / OpenAI Moderation / Llama Guard 와의 비교 우위 설명
  부족.
- **사용자가 겪는 불편**: "왜 이 제품을 쓰는가" 설득 논리 없음.
- **제안**:
  1. **Feature Matrix** (6 레이어 × 경쟁 제품 기능 지원 표).
  2. 차별점 강조: 한국어 특화 가드레일 (L5 PII 한국어 컨텍스트, L3
     Toxicity 한국어 사전), OpenAI SDK 완전 호환, 초경량/저지연 레이어
     구성, 사내망 배포 (on-prem).
  3. `docs/benchmark.md` 신설.
- **우선순위**: **P2**
- **참조 에셋**: `docs/project-analysis.md`

---

### B11. 에지 케이스 경고 배너

- **현재 상태**: multimodal / tool content / 멀티턴 미검사는 README
  "운영 주의" 문단으로만 존재.
- **사용자가 겪는 불편**: 문서 정독 없이 통합 시 이미지 내 텍스트나 이전
  대화 내역을 통한 우회에 무방비.
- **제안**:
  1. `/docs` 상단 + `/playground/` 에 **Limitations 배너** 상시 노출.
  2. 검사 제외 항목 (Multi-modal · System · Tool · 멀티턴) 을 명확히
     표기.
  3. A1 이 해결되면 배너 내용도 함께 갱신 (live status).
- **우선순위**: **P1**
- **참조 에셋**: `docs/feature-validation.md`,
  `app/services/guardrail_converter.py`, `app/static/index.html`

---

### B12. 개발자 온보딩 5분 퀵스타트

- **현재 상태**: 환경 변수 설정 위주의 설치 가이드. 첫 BLOCK 재현까지의
  과정이 분산.
- **사용자가 겪는 불편**: 첫 번째 "작동한다" 경험까지 5분 이상, 여러
  문서를 오가야 함.
- **제안**:
  1. README 최상단에 **"5분 Hello World"** 섹션:
     - `docker compose up -d`
     - `SKIP_HEADER_VERIFICATION=true` 로컬 로드
     - 첫 정상 요청 curl 1 줄
     - 첫 BLOCK 재현 curl 1 줄 (예: "ignore previous instructions" 류)
  2. Docker Compose 원클릭 로컬 셋업 (admin-backend mock 포함).
  3. B5 SDK 배포 후에는 Python 3 줄 예제 추가.
- **우선순위**: **P0**
- **참조 에셋**: `README.md`, `docker-compose.yml`

---

## PART C. 종합 우선순위 요약

### P0 — 운영 전 반드시 해결

**보안·아키텍처 (Codex)**
- A1. 입력 검사 범위 확장 (system/assistant/tool/multimodal/멀티턴)
- A6. 네트워크 경계 하드닝 — L1 Cheap reject 만 (Body/timeout/key RPS/IP RPS/CORS). L2 경제 가드·L3 남용 탐지는 P1, L4 edge 프록시는 P2 로 분리 (2026-04-24 계층 분해)
- A7. Observe 모드 운영 차단 — APP_ENV=dev 게이트 (2026-04-24 구현 완료). 2-step approval lease 는 공개 SaaS / 멀티테넌시 전환 시 재검토 (P2 트리거)
- A8. 진단 엔드포인트 인증·권한 분리
- A9. 민감 로그 정리 + 구조화 audit log
- A11. `SKIP_*` 우회 플래그 prod-safe 가드

**UX·DX (Gemini)**
- B4. 에러 코드 카탈로그
- B5. 공식 클라이언트 SDK
- B12. 개발자 온보딩 5분 퀵스타트

### P1 — 정식 공개 전 해결

- A2-a. 인위적 지연 옵트인 전환 (즉시 적용 가능, 헤더 누락=instant 기본)
- A2-b. 출력 레이어 tier 분리 (streaming 경로 vs. buffer-then-stream)
- A2-c. Holdback buffer 기반 진짜 streaming (provider streaming 도입 시)
- A3. 차단 응답의 정보 유출 최소화 (3개 coarse taxonomy — 2026-04-23 P1 로 조정)
- A4. 분산 Replay 방어 — Phase 1 ADMIN 위임 (수평 확장 시 P0 재상향)
- A5-a. ADMIN 정책 조회 회복성 (timeout 분리 / retry budget / 회로차단 / stale-if-error / 메트릭)
- A6 L2. 경제 가드 — per-key 토큰 예산 / request 상한 / concurrency cap (A5-b `/policy` 계약 확장과 동기)
- A6 L3. 남용 탐지 — BLOCK 반복 / 요청량 급변 (A10 메트릭 인프라 공유)
- A10. fail-open 관측 가능성과 알람
- A12. Readiness vs Liveness 분리
- B1. 차단 안내문 UX (A3 과 동기 구현)
- B2. 다국어(i18n) 대응
- B3. 관찰 모드 UI 시각화
- B6. 플레이그라운드 고도화
- B7. 영어 문서 (외부 공개 시점엔 P0)
- B9. ADMIN 통합 플로우 다이어그램
- B11. 에지 케이스 경고 배너

### P2 — 장기 고도화

- A5-b. ADMIN 정책 조회 물리 분리 + 폴링 캐시 (ADMIN 계약 변경, A4 Phase 1 과 동기화)
- A6 L4. 앞단 프록시 체계 — TLS 종료 / WAF / 국가·IP blocklist / DDoS 흡수 (nginx·envoy·CDN 책임으로 분리)
- A13. 회귀 시나리오 체크리스트 자동화
- B8. 관측 대시보드
- B10. 대안 가드레일 벤치마킹

---

## PART D. 두 advisor 간 합의·충돌 정리

### 강한 합의 지점

| 합의 항목 | Codex | Gemini | 공통 결론 |
|---|---|---|---|
| 차단 응답 정보 유출 최소화 | A3 (P1, 2026-04-23 조정) | B1 (P1, A3 동기) | **3개 coarse taxonomy** (정책 위반 / 개인정보 보호 / 응답 제한) 매핑. 데모/개발 단계에선 투명성이 디버깅 자산이므로 P1. **외부 공개·실서비스 전환 시 P0 재상향** |
| 관측 가능성 | A10 fail-open 메트릭 (P1) | B8 관측 대시보드 (P2) | 먼저 **메트릭 인프라(A10)** 구축 후 대시보드(B8) 에 태우는 순서 |
| 에지 케이스 투명성 | A1 검사 범위 확장 (P0) | B11 경고 배너 (P1) | A1 해결 전까지 B11 배너는 **의무**. A1 완료 후 배너 내용 갱신 |
| 운영 모드 가드 | A7 Observe lease (P0) | B6 플레이그라운드 토글 (P1) | 플레이그라운드 토글은 **프로덕션 빌드에서 비활성화** 되도록 B6 설계에 제약 추가 |

### 충돌 또는 주의 지점

| 충돌 항목 | Codex 입장 | Gemini 입장 | 최종 판단 |
|---|---|---|---|
| **관찰 모드 `guardrail_reports` 공개 범위** | A3: 레이어별 reason/tags 는 기본 비공개 | B3: 플레이그라운드에서 타임라인 시각화(레이어 상세 노출) | 외부 API 응답은 coarse 스키마만. 플레이그라운드·Swagger 시도 UI 는 operator-auth 뒤에서 **풀 스키마 허용**. 즉 A3 가 B3 를 제약 |
| **`/v1/layers/status` 노출 여부** | A8: 인증 필요, `signals`/`model_paths` 공개 금지 | B6: 플레이그라운드에 "현재 활성 정책" 표시 | 공개용 coarse (`all_effective` boolean) 와 operator 전용 상세로 **분리**. B6 의 표시는 coarse 스키마로 충분 |
| **i18n vs. 차단 메시지 보안** | A3: 사용자 노출 문구 최소화 | B2: 친절한 가이드 제공 | **coarse taxonomy 키**만 i18n 번역. Operator reason 은 영문 고정(로그·audit 일관성) |

### 최종 실행 방향

1. **Phase 0 (운영 오픈 게이트)** — P0 전체를 "운영 오픈 블로커" 로 고정.
   특히 **A3 + B1 + A4 + A11** 은 코드가 아닌 **설계 계약** 이므로 먼저
   스펙을 수립한 뒤 구현 착수.
2. **Phase 1 (정식 공개 준비)** — P1 묶음. A2(진짜 스트리밍) 은 LLM
   provider streaming 지원이 선행돼야 하므로 별도 tracking.
3. **Phase 2 (장기 고도화)** — P2 묶음은 Phase 1 안정화 후 반기 단위
   로드맵.

---

## 참고 산출물

- Codex artifact: `.omc/artifacts/ask/codex-agentic-ai-guardrail-gateway-backend-fastapi-openai-v1-chat--2026-04-23T00-58-37-841Z.md`
- Gemini artifact: `.omc/artifacts/ask/gemini-agentic-ai-guardrail-gateway-backend-openai-v1-chat-completi-2026-04-23T00-54-26-639Z.md`
- 현재 구현 상태 스냅샷: `docs/project-analysis.md`
- 아키텍처 개요: `docs/architecture-overview.md`

---

## 논의 이력

이 문서는 살아있는(living) 로드맵이며, 설계 논의에서 의사결정이 바뀐
부분은 이 섹션에 이력을 남겨 추적한다.

### 2026-04-23 — 초안 생성 후 A1·A2 재구조화

**컨텍스트**: Codex(보안/아키텍처) · Gemini(UX/DX) advisor 초안을 통합한
뒤, P0/P1 항목을 저자와 순차적으로 재검토하며 설계 원칙을 확정하는 과정.

**의사결정 1 — A1 재정의 (입력 검사 범위 vs. 회귀 방지 양립)**

- 원 지적: "이전 프롬프트가 BLOCK 됐을 때 이후 정상 프롬프트도 회귀
  차단되는 문제를 피하려고 마지막 user 하나만 검사하는 설계였다."
- 결론: 검사 범위 확장과 회귀 방지는 **배타적이지 않다**. 해결책은
  **Stateless content-hash PASS 캐시** 패턴.
  - `messages` 배열 전체를 순회하되, `(sha256(content), layer_id)` 캐시를
    먼저 조회 → 히트면 스킵, 미스면 레이어 실행 후 **PASS 만 저장**.
  - **BLOCK 은 저장하지 않음** — "한 번 차단되면 영원히 차단" 회귀 재발
    방지.
  - 원문 저장 없이 hash 만 → PII 이슈 회피.
  - 별도 대화 히스토리 DB 불필요 (설계 원칙 P-3 참조).
- 검사 대상은 `user` 뿐 아니라 `system` / `assistant` / `tool` /
  `tools.description` / multimodal 메타데이터까지 확장.

**의사결정 2 — 설계 원칙 P-1 확정**

- 모든 레이어의 primary 목적은 **공격·악의적 행동 방어·차단**.
- 예외는 **L5 PII** — 마스킹 및 역마스킹(입력 PII ↔ 응답 재출현 값 매칭
  기반 복원) 이 주 역할. 이 역할은 A2 streaming 설계에서 L5 를 redaction
  가능 레이어로 분류하는 근거가 된다.

**의사결정 3 — 설계 원칙 P-2 확정**

- "이미 사용자에게 방출된 응답은 BLOCK 으로 되돌릴 수 없다" 를 전제.
- **되돌릴 수 없는 레이어** (L4 hallucination / L6 compliance / L2
  perplexity 부분) 는 출력 streaming 경로에 배치하지 않는다.
  1. pre-LLM 입력 판정으로 이동하거나,
  2. buffer-then-stream 경로 전용으로 배치.
- 응답 완료 후 BLOCK 을 "유출 방지용" 으로 설계하지 않는다.

**의사결정 4 — A2 를 3단계로 분해**

- A2-a (인위 지연 옵트인): 기본값 `instant`. 헤더 누락·알 수 없는 값도
  전부 `instant` 로 폴백. 타이핑 효과는 `X-Guardrail-Stream-Style: typing`
  명시 요청 시에만.
- A2-b (레이어 tier 분리): 레이어별 속도·최소 판정 토큰 수·streaming
  배치를 표로 명시. Perplexity 최소 100 토큰 보장 조건 문서화.
- A2-c (holdback buffer 진짜 streaming): provider streaming API 도입
  필요. A2-b 선행 필수.

**의사결정 5 — A3·B1 재조정 및 3개 coarse taxonomy 확정**

- **재분류 근거 (저자 판단)**: 이 프로젝트는 현재 **데모 단계**이며
  **신뢰할 수 있는 환경 내에서 동작**한다. 개발/QA 에게 "어떤 레이어가
  어떤 사유로 차단했는가" 를 투명하게 보여주는 것이 **디버깅 자산**이며,
  공격 시나리오 재현·정책 조정에도 유리하다. A1(검사 범위)·A2(스트리밍)
  와 달리 A3/B1 은 기술 스택의 안전성 문제가 아니라 **"누가 읽느냐"에
  따라 가치가 뒤집히는 노출 정책**이라, 환경이 바뀌기 전까지는 현재 상태
  유지가 합리적이다.
- **우선순위 상태**: A3 와 B1 모두 현재 단계에서 **P1 유지**, 외부 공개
  시점에 **P0 로 재상향**.
- **P0 재상향 트리거** — 아래 중 하나라도 충족되면 A3/B1 은 즉시 블로커:
  (a) 신뢰 범위 밖 실사용자에게 서비스 노출
  (b) 공개 SaaS / 공개 API 전환
  (c) 멀티테넌시 도입 (서로 다른 신뢰 경계의 클라이언트가 같은 게이트웨이
      를 공유)
- **Coarse taxonomy 3개 확정** (P1 구현 시 적용):
  1. **정책 위반** — L1 prompt injection, L3 toxicity, L6 compliance
     (입력), L2 공격성 패턴
  2. **개인정보 보호** — L5 (차단 모드), L2 sensitive 입력
  3. **응답 제한** — L4 hallucination, L6 (출력), L2 sensitive 출력
- 레이어 번호·원본 reason·severity·confidence·tags 는 P1 구현 시
  사용자 노출에서 제거, operator-only audit log (A9) 로 이동.
- L5 가 **마스킹(redaction)** 으로 동작할 때는 차단이 아니므로 위 3개
  카테고리 매핑에서 제외 — 별도 경고 필드로 클라이언트에 알림.

**의사결정 6 — A4 분산 Replay 방어, Redis 없이 ADMIN 위임 채택**

- **재분류 근거**: 현재 배포는 **단일 인스턴스**(`docker-compose.yml`)
  이며, ADMIN 이 이미 동일한 nonce/timestamp 검증을 **중복으로** 수행 중.
  즉 현 단계에선 replay 방어가 정상 동작하며, 다중 인스턴스 전환 시점이
  실제 블로커가 되는 순간이다 (A3 와 동일한 트리거 기반 구조).
- **우선순위 조정**: A4 를 **P0 → P1** 로 재분류.
- **P0 재상향 트리거**: (a) `replicas ≥ 2`, (b) autoscaling / k8s
  Deployment, (c) 멀티 리전 / 멀티 클러스터 — 이 중 하나라도 도입 계획.
- **Phase 1 접근법 확정 (Redis 미도입)**: ADMIN backend 에 nonce 소비를
  위임. 근거:
  1. ADMIN 이 이미 nonce/timestamp 검증 중 — 게이트웨이 로컬 NonceStore 는
     중복 방어. 이를 제거하면 책임 경계가 명확해짐.
  2. ADMIN 은 중앙 집중형이라 자연스러운 공유 지점. 추가 인프라 없음.
  3. 게이트웨이가 완전 stateless 가 되어 수평 확장 시 Redis 등 없이
     `replicas` 만 올려 배포 가능.
- **대안 검토 결과**: Sticky session (LB consistent hash by X-API-Key) 도
  고려. 설정 간단하지만 ADMIN 이 이미 검증 중인 현 구조에선 **중복 제거
  효과가 있는 ADMIN 위임 쪽이 더 자연스러움**. Sticky session 은 Phase 1
  이후 ADMIN 부하가 과해지면 **보조 완화책**으로 추가 고려 가능.
- **A1 PASS 캐시는 공유 대상 아님**: 보안이 아닌 성능·회귀 방지 기능이
  므로 각 인스턴스가 로컬 TTLCache 유지해도 안전성 불변. 다중 인스턴스
  배포 시 hit rate 저하 가능성은 **A1 섹션의 "4) 단계적 인프라 및 다중
  인스턴스 영향" 항목에 명시적 노티 추가**. 완화책으로 sticky session 또는
  consistent hashing LB 를 권장.
- **Phase 0 SQLite 재시작 회복성 보강은 생략** — 현 단계에선 필요성
  낮음 (재시작 직후 `skew_sec` 동안의 짧은 replay 창은 수용).

**의사결정 7 — A5 분해: 회복성(A5-a) P1 + 물리적 엔드포인트 분리(A5-b) P2**

- **문제 진단**: 기존 A5 제안은 `/verify` 한 엔드포인트 위에 TTL 캐시를
  얹는 형태였으나, 같은 엔드포인트가 **캐싱 불가한 관심사 (nonce 소비 =
  요청 검증)** 와 **캐싱 가능한 관심사 (apiKey 정책 조회)** 를 동시에
  반환하는 구조적 결함이 실제 원인. 매 요청 ADMIN 호출이 필연이 됨.
- **분리 방향 확정**: **물리적 엔드포인트 분리** 로 결정.
  - `POST /verify` — 요청 검증 전용 (nonce 소비, 캐싱 금지).
  - `GET /policy` — 정책 조회 전용 (ETag / `If-None-Match` / 304 지원).
  - 응답 필드만 분리하는 경량 안은 기각 — `/verify` 전체가 여전히 캐싱
    불가 경로에 묶여 있어 ETag / HTTP 캐시를 활용할 수 없음. 그리고 물리
    분리가 **지연 갱신(lazy/deferred policy refresh) 유지에도 유리**하다는
    점이 결정타.
- **A5-a (P1, 회복성 5개)**: Connect/read timeout 분리, idempotent 재시도
  budget, pybreaker 회로차단기, `stale-if-error` fallback, health
  degradation 메트릭. 물리 분리 전/후 모두 적용 가능해 독립 진행.
- **A5-b (P2, 효율화)**: ADMIN 계약 변경 + 게이트웨이 60초 polling +
  Conditional GET + jitter. **A4 Phase 1 (ADMIN 위임 nonce 소비) 과 함께
  묶어 진행하면 cross-team 협의 비용 최소화** — P1 재상향 트리거에 이
  동시 진행 시점 포함.
- **60초 polling 간격 확정**: 안정된 정책은 분 단위로 변하지 않는다는
  전제. Jitter ±10–20% 로 thundering herd 방지.
- **N 인스턴스 부하 증가 우려 해소**: Conditional GET → 대부분 304,
  본체 전송 없음. ADMIN DB 는 policy 변경 여부만 확인하는 경량 질의.
  선형 증가는 있으나 실질 부하 미미. 대규모 전환 시 push / webhook 구조
  (P2 보류) 재검토.
- **ADMIN 팀 계약 변경 proposal** 은 A5-b 섹션 본문에 "Why + What" 형태로
  그대로 담아 **ADMIN 팀에게 전달 가능한 문서** 로 사용.

### 2026-04-24 — A6 네트워크 경계 하드닝 재구조화

**컨텍스트**: 저자 질문 — *"지금은 API Key 를 통해 클라이언트 검증만 하고
있어서 실제 악의적 요청을 막긴 어렵죠?"* 에서 출발. 현재 인증 체계
(`X-API-Key` + HMAC 4종 헤더) 의 **실질 능력 범위**를 재점검한 결과,
위변조 방지(transport 무결성) 와 남용 방지(abuse prevention) 가 **서로
다른 문제**이며, 현재 게이트웨이에는 후자를 담당할 장치가 사실상 없음을
확인.

**의사결정 8 — A6 를 계층(L1~L4) 으로 분해, 단일 P0 에서 P0/P1/P2 로 재분배**

- **문제 진단**: 기존 A6 는 "CORS / rate limit / body size / timeout /
  concurrency / 이중 방어" 5개를 동일 선상의 **단일 P0** 로 묶고 있었다.
  그 결과 (a) 앱 레벨과 앞단 프록시 책임이 섞여 범위가 비대해지고,
  (b) LLM 게이트웨이 특유의 두 가지 방어선 — **경제적 DoS(토큰 비용)**
  와 **가드레일 우회 brute-force** — 이 빠져 있었다. 단순 RPS 제한만으로는
  "적은 요청 × 긴 context" 형태의 비용 공격과 "프롬프트 변형 반복" 형태의
  우회 시도를 **구조적으로** 못 막는다.
- **HMAC 의 경계 재확인**: `X-API-Key` + HMAC 서명은 *"이 key 소유자가
  정당하게 서명했다"* 만 증명한다. **유효한 key 의 남용**(key 보유자 본인
  또는 탈취한 공격자) 은 검증 경로 어디에서도 잡히지 않는다. HMAC 는
  위변조 방지이지 남용 방지가 아니라는 경계를 A6 본문과 B4 에러 코드에
  명시적으로 박아 혼동 방지.
- **계층 재구조화 확정**:
  - **L1 Cheap reject (P0)** — LLM 호출이 일어나기 전에 버림. Body 크기
    상한, read timeout, per-key RPS, per-IP RPS, CORS allowlist.
  - **L2 Economic guard (P1)** — 업스트림 LLM 토큰 비용 방어. Per-key
    일/월 토큰 예산, request 당 토큰 상한, concurrency cap. **A6 의 실질
    핵심.** A5-b `/policy` 계약에 이 파라미터를 함께 싣는다.
  - **L3 Abuse detection (P1)** — 가드레일 서비스 특유 신호. BLOCK 반복
    탐지(우회 brute-force 차단), 요청량 급변 감지. A10 메트릭 인프라와
    공유.
  - **L4 Edge (P2)** — TLS 종료 / WAF / 국가·IP blocklist / DDoS 흡수.
    앞단 프록시(nginx·envoy·CDN) 책임으로 **분리**. 앱 안에 넣어 "이중
    방어" 하지 않음 — 중복·오버엔지니어링 회피.
- **L2 가 "P1 이면 늦지 않나?" 에 대한 답**: 맞다. 하지만 L2 는 **키별
  정책 시스템(A5-b `/policy`)** 과 계약적으로 엮여 있어 ADMIN 계약 변경이
  선행돼야 한다. 대신 P0 의 L1 per-key RPS + body/토큰 상한이 **급한
  출혈은 막는다**. L2 는 정식 공개 전 반드시 닫는다.
- **우회 플래그와의 상호작용**: `skip_header_verification=true` 경로에서도
  L1 rate limit 은 **반드시 적용**되어야 한다 — 데모 우회 플래그가 남용
  방어를 함께 우회하면 안 됨을 A11 (`SKIP_*` 가드) 과 일관되게 강제.
- **ADMIN 계약 연계**: 토큰 예산 한도, concurrency cap, BLOCK 반복 임계값
  등 **key 별 정책**은 `/policy` 응답에 실어 ADMIN 에서 제어. A5-b 계약
  변경 proposal 에 L2/L3 파라미터 필드 추가를 함께 요청.

### 2026-04-24 — A7 Observe 모드 운영 가드 구현

**컨텍스트**: 저자 질문 — *"레이어를 생략하는 모드가 있었나요? 있으면
제거해주세요."* 에서 출발. 확인 결과 **레이어 생략 모드는 없고**, 대신
`CONTINUE_ON_LAYER_FAILURE` 로 켜지는 **관찰 모드**(레이어를 끝까지 실행하되
BLOCK 판정을 *강제하지 않고* 원본 응답을 사용자에게 그대로 전달)가 존재.
모드를 삭제하면 PII 데모 덱·B3 (관찰 모드 UI 시각화)·B6 (플레이그라운드
고도화) 등 데모 자산이 줄줄이 손상되므로, 저자는 **기능 유지 + 프로덕션
활성화 금지 (dev 전용)** 방향을 선택.

**의사결정 9 — APP_ENV=dev 게이트로 범위 축소, 2-step lease 는 보류**

- **HMAC 와 APP_ENV 의 관심사 분리**: `X-API-Key` + HMAC 4종 헤더는 *요청
  검증* — 위변조 방지. `APP_ENV` 게이트는 *기동 계약* — 프로세스가 시작될
  수 있느냐의 문제. 두 검증은 서로 독립. HMAC 가 아무리 완벽해도
  `APP_ENV=prod` 에서는 관찰 모드 자체가 켜질 수 없다.
- **구현 위치 — config 한 곳**: `Settings` 에 `app_env: Literal["dev", "prod"]
  = "prod"` + `@model_validator(mode="after") _observe_mode_requires_dev`.
  요청 경로(`app/routers/chat.py`) 에는 추가 분기가 전혀 없어 **검증
  중복·엇갈림 리스크 0**. 잘못된 조합은 `Settings()` 생성 시점에
  `ValidationError` 로 프로세스가 기동 실패.
- **기본값 `"prod"` (safe-by-default)**: `.env` 에 `APP_ENV` 를 명시하지
  않으면 자동으로 잠긴다. 명시적 opt-in 만 활성화.
- **`Literal["dev", "prod"]` 로 오타 거부**: `"staging"`, `"development"`
  같은 유사 값은 기동 시 즉시 거부. 새 환경이 필요하면 코드 추가가 강제됨.
- **2-step approval lease 는 보류**: 원래 A7 제안(ADMIN signed approval
  lease + tenant/route/시간창 검증) 은 현재 데모 단계 대비 과도한 복잡도.
  P2 재상향 트리거를 명시: (a) 공개 SaaS 전환, (b) 멀티테넌시 도입, (c)
  고객에게 "디버그 모드 토글" 을 API 로 노출. 그 전까지 `APP_ENV=dev` 게이트
  하나로 충분.
- **데모 자산은 보존**: `_run_observe_mode_pipeline`, `guardrail_reports`
  응답 필드, Swagger 예시, PII 데모 덱 스토리 전부 그대로. dev 에서만
  동작하는 자산이라는 명시만 추가.
- **A11 과 방향 일치**: `skip_header_verification` 등 `SKIP_*` 플래그도
  dev 전용이 되어야 한다는 A11 방향과 같은 계약 — 데모 우회 플래그는 전부
  `APP_ENV=dev` 에 묶어 운영 사고를 기술적으로 차단하는 일관된 패턴.
- **문서 동기화**: README 의 관찰 모드 경고문을 "권고 금지" → "기술적
  차단" 으로 격상. `/docs` Swagger description, `ChatResponse.guardrail_reports`
  docstring 에도 `APP_ENV=dev` 조건 병기.

**보류 주제**

- **L5 PII 역마스킹(복원) 상세 설계** — 입력 PII 원본 ↔ 응답 재출현 값
  매칭 방식, 세션/턴 단위 매핑 저장소, 복원 범위(정확 일치만 vs. 부분
  일치) 등. 별도 주제로 후속 논의.
- **레이어별 실제 구현(core-secure-layer)** 의 "최소 판정 토큰 수" 실측치
  확정. A2-b 표의 숫자는 일반 경험칙 기준이며, 실제 L2·L3·L4 구현체의
  requirement 를 측정해 갱신 필요.
- **L2 내부 분할 여부** — L2 의 "공격성 패턴" 과 "sensitive data" 를 별도
  서브레이어로 분리할지. 현재는 논리적으로만 구분하고 하나의 L2 가
  처리한다고 가정.
- **ADMIN `/verify` 계약 확장 상세** — Phase 1 구현 시점에 HTTP 409 vs
  응답 바디 `"replay": true` 필드 중 선택, ADMIN 쪽 nonce 테이블 스키마,
  TTL cleanup 전략. ADMIN 팀과의 계약 협의 대상.
