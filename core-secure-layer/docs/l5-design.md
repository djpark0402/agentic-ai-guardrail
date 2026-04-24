# L5: PII Detection (Regex + Model-Adapter NER)

## 1. 목적

사용자 입력에서 개인식별정보(PII)와 민감 정보를 탐지하여 차단한다. 2단계 필터링으로 **Regex 패턴 → NER 모델** 순서로 검사하며, 앞 단계에서 탐지되면 즉시 차단한다. NER 단계는 모델마다 라벨 스키마와 판정 규칙이 다르므로 **모델 폴더 내 `pii_labels.json`** 으로 자기완결형으로 정의한다.

## 판정 원칙

> **미탐(false negative)은 허용, 오탐(false positive)은 절대 불허.**
>
> PII를 못 잡아서 통과시키는 것은 허용한다.
> 정상 문장을 PII로 오인하여 차단하는 것은 절대 안 된다.

## 2. 판정 기준 — 2단계 필터링

검사 순서: **Regex 패턴 → NER 모델**. 앞 단계에서 탐지되면 즉시 차단하고 후속 단계는 스킵한다. 비용이 낮은 순서로 배치하여 성능을 최적화한다.

### 2.1 Regex 패턴 (1단계)

기본 정규식 + 외부 주입 정규식으로 구조화된 민감 정보를 탐지. API 키, 주민등록번호 등 정형화된 PII를 빠르게 걸러낸다.

**기본 패턴:**

| 종류 | 패턴 | 예시 |
|------|------|------|
| 주민등록번호 | `\d{6}-[1-4]\d{6}` | `900101-1234567` |
| 전화번호 | `\d{2,3}-\d{3,4}-\d{4}` | `010-1234-5678`, `02-123-4567` |
| 이메일 | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | `user@example.com` |
| API 키 (OpenAI) | `sk-[a-zA-Z0-9]{20,}` | `sk-abcdef1234567890abcd` |
| AWS 키 | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| Bearer 토큰 | `Bearer\s+[a-zA-Z0-9._\-]+` | `Bearer eyJhbGciOi...` |

**외부 주입:** `extra_patterns` 파라미터로 추가 정규식 리스트 주입.

### 2.2 NER 모델 (2단계)

1단계를 통과한 입력에 대해 로컬 NER 모델로 개체명 인식을 수행한다. **판정 로직은 모델 폴더 내 `pii_labels.json` 에서 정의**하며, L5Layer 코드는 JSON 스펙을 해석해 차단/허용을 결정한다.

#### `pii_labels.json` 스펙

모델 폴더(`model/<모델명>/pii_labels.json`)에 다음 필드를 기술한다:

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `label_map` | `dict[str, str]` | O | 모델 원본 라벨(B-/I- 접두사 제거 후) → 정규화된 PII 타입명. 예: `{"이름": "person", "PS": "person"}` |
| `block_singletons` | `list[str]` | O | 단일 감지만으로 차단할 PII 타입명 목록. 예: `["phone_number", "resident_id"]` |
| `block_combinations` | `list[list[str]]` | O | 조합 차단 규칙. 각 내부 리스트의 모든 타입이 동시에 감지되면 차단. 예: `[["person", "location"]]`. 조합을 쓰지 않으면 `[]` |
| `min_score` | `float` | X (기본 `0.0`) | 엔티티 신뢰도 임계값. 이 값 미만은 무시 |
| `aggregation_strategy` | `str` | X (기본 `"simple"`) | `transformers.pipeline("ner", aggregation_strategy=...)` 에 그대로 전달. 서브워드 병합 정책 |

**JSON 예시 1 — PII 특화 모델 (`ner-ko`):**
```json
{
  "label_map": {
    "이름": "person",
    "전화번호": "phone_number",
    "휴대전화번호": "mobile_number",
    "주민등록번호": "resident_id",
    "계좌번호": "account_number",
    "카드번호": "card_number",
    "여권번호": "passport_number",
    "운전면허번호": "driver_license",
    "전자메일": "email",
    "로그인ID": "login_id",
    "상세주소": "address",
    "우편번호": "zip_code",
    "가맹점명": "merchant",
    "결제금액": "payment_amount",
    "신용점수": "credit_score"
  },
  "block_singletons": [
    "person", "phone_number", "mobile_number", "resident_id",
    "account_number", "card_number", "passport_number",
    "driver_license", "email", "login_id", "address",
    "zip_code", "merchant", "payment_amount", "credit_score"
  ],
  "block_combinations": [],
  "min_score": 0.0,
  "aggregation_strategy": "simple"
}
```
→ 특화 모델이라 "감지된 엔티티 = PII" 이므로 전부 singleton 차단. 현재 동작과 동일.

**JSON 예시 2 — 범용 NER 모델 (가상):**
```json
{
  "label_map": {
    "PS": "person",
    "LC": "location",
    "DT": "date",
    "OG": "organization"
  },
  "block_singletons": [],
  "block_combinations": [
    ["person", "location"],
    ["person", "date"]
  ],
  "min_score": 0.85,
  "aggregation_strategy": "simple"
}
```
→ "홍길동" 단독은 허용, "홍길동이 서울 산다" 는 차단.

#### 판정 알고리즘 (코드 측)
1. NER 파이프라인 추론 → 엔티티 리스트 획득
2. `min_score` 미만 엔티티 제거
3. 각 엔티티의 `entity` 필드에서 B-/I- 접두사 제거 → `label_map` 으로 정규화 타입 획득 (맵에 없으면 무시)
4. 정규화 타입 집합에 대해:
   - `block_singletons` 중 하나라도 포함되면 차단
   - `block_combinations` 중 하나라도 전부 포함되면 차단
   - 그 외엔 허용

### 2.3 `pii_labels.json` 부재 시 폴백 (관대 폴백)

모델 폴더에 `pii_labels.json` 이 **없으면**:
- `config.json` 의 `id2label` 을 자동 추출해 `label_map` 으로 사용 (B-/I- 접두사 제거, 값은 원본 라벨명 그대로)
- `block_singletons = <모든 라벨>`, `block_combinations = []`, `min_score = 0.0`, `aggregation_strategy = "simple"`
- 단, 생성자 `min_score` 가 주어졌다면 그 값이 `0.0` 대신 쓰인다 (§3 참조)
- 즉 "엔티티 하나라도 감지되면 차단" — 현재 동작과 동일
- 로드 시점에 `logger.warning("pii_labels.json 없음, 폴백 동작 — 범용 NER 모델은 오탐 위험이 큼: %s", path)` 로 1회 경고

> ⚠️ **주의**: 이 폴백은 PII 특화 모델을 전제로 한다. 범용 NER(PER/LOC/ORG 등) 모델을 `pii_labels.json` 없이 드롭인하면 정상 대화의 인명·지명도 차단되어 오탐이 폭증한다. 범용 모델은 반드시 `pii_labels.json` 을 함께 작성할 것.

## 3. 초기화

```python
layer = L5Layer(
    model_name="ner-ko",                     # NER 모델 폴더명
    extra_patterns=[r"PROJ-\d{6}"],          # 추가 차단 정규식
    min_score=0.85,                          # JSON 의 min_score 를 override (선택)
)
```

| 파라미터 | 타입 | 기본값 | 설명 |
|----------|------|--------|------|
| `model_name` | `str` | `"ner-ko"` | NER 모델 폴더명 (`model/` 하위) |
| `extra_patterns` | `list[str]` | `[]` | 추가 차단 정규식 리스트 |
| `min_score` | `float \| None` | `None` | NER 엔티티 신뢰도 임계값. `None` 이면 `pii_labels.json` 의 값을 사용하고, 값이 주어지면 JSON 스펙을 override. 폴백 경로에서도 동일하게 적용 |

판정 규칙(`label_map`, `block_singletons`, `block_combinations`, `aggregation_strategy`)은 `model/<model_name>/pii_labels.json` 에서 읽으므로 생성자로 주입하지 않는다. 다만 `min_score` 만은 **프로젝트별 임계값 튜닝 용도로 생성자 주입을 허용** 한다 — 공유 모델 폴더를 여러 프로젝트가 다른 감도로 쓰는 시나리오를 커버한다.

## 4. 디렉토리 구조

```
l5/
├── l5.py
└── model/
    └── ner-ko/
        ├── config.json
        ├── model.safetensors
        ├── tokenizer.json
        ├── tokenizer_config.json
        └── pii_labels.json      ← 추가
```

## 5. 입력/출력

### 입력: `GuardrailRequest`

| 필드 | 사용 여부 | 용도 |
|------|-----------|------|
| `user_input` | O | PII 탐지 대상 |
| `session_id` | X | 사용 안 함 |
| `metadata` | X | 사용 안 함 |

### 출력: `LayerResult`

**허용 시:**
```python
LayerResult(
    name="L5",
    allowed=True,
    confidence=1.0,
    severity=Severity.NONE,
)
```

**차단 시 (Regex):**
```python
LayerResult(
    name="L5",
    allowed=False,
    reason="PII detected: phone_number at position 5",
    confidence=0.0,
    severity=Severity.HIGH,
    tags=["pii", "phone_number"],
)
```

**차단 시 (NER singleton):**
```python
LayerResult(
    name="L5",
    allowed=False,
    reason="PII detected: person at position 3",
    confidence=0.0,
    severity=Severity.HIGH,
    tags=["pii", "ner", "person"],
)
```

**차단 시 (NER combination):**
```python
LayerResult(
    name="L5",
    allowed=False,
    reason="PII detected: person+location",
    confidence=0.0,
    severity=Severity.HIGH,
    tags=["pii", "ner", "person", "location"],
)
```

- `reason`: singleton 은 `"PII detected: {type} at position {N}"`, combination 은 `"PII detected: {type1}+{type2}+..."`
- `severity`: `HIGH`
- `confidence`: 차단=`0.0`, 허용=`1.0`
- `tags`: `["pii", ...]` (NER 은 `["pii", "ner", ...]`)
- 원문은 `reason` 에 포함하지 않음 (PII 로그 유출 방지)

## 6. 엣지 케이스

| 케이스 | 판정 | 이유 |
|--------|------|------|
| 빈 문자열 `""` | 허용 | 탐지 대상 없음 |
| 일반 문장 `"오늘 날씨가 좋다"` | 허용 | PII 없음 |
| `"010-1234-5678"` | 차단 (1단계) | 전화번호 Regex |
| `"user@gmail.com"` | 차단 (1단계) | 이메일 Regex |
| `"900101-1234567"` | 차단 (1단계) | 주민등록번호 Regex |
| `"sk-abc123..."` | 차단 (1단계) | API 키 Regex |
| PII 특화 모델 + `"홍길동"` | 차단 (2단계) | `person` ∈ `block_singletons` |
| 범용 모델 + `"홍길동"` 단독 | 허용 | `person` ∉ `block_singletons`, 조합 미충족 |
| 범용 모델 + `"홍길동이 서울에 산다"` | 차단 (2단계) | `[person, location]` 조합 매칭 |
| NER 모델 미로드 | 허용 | fail-open (1단계만 동작) |
| `pii_labels.json` 미존재 | 경고 로그 + 폴백 동작 | §2.3 참조 |
| 외부 주입 패턴 매칭 | 차단 (1단계) | `extra_patterns` |
| 모델 추론 중 예외 | 허용 | fail-open |
| `min_score` 미만 엔티티 | 무시 | 낮은 신뢰도 오탐 방지 |

## 7. 보안 고려

- **fail-open**: NER 모델 미로드, 추론 예외 시 허용. 1단계(Regex)는 모델 없이도 동작
- **fail-open 의 범위**: `pii_labels.json` JSON 파싱 실패 시에도 폴백이 아닌 **NER 비활성화(fail-open)** 으로 처리 — 잘못된 JSON 으로 의도치 않은 차단 규칙이 돌아가는 위험 회피
- **Regex 안전성**: 외부 주입 정규식의 ReDoS 방지를 위해 타임아웃 또는 패턴 길이 제한 고려
- **PII 원문 비노출**: `reason` 에 탐지 타입+위치만 포함, 원문은 노출하지 않음
- **관대 폴백의 리스크**: §2.3 경고 참조 — 범용 NER 드롭인은 오탐 유발, 반드시 `pii_labels.json` 동반 작성

## 8. 의존성

- **선행 레이어**: L1~L4
- **외부 라이브러리**: `transformers` (NER), `torch`
- **LangChain**: 사용 안 함

## 9. 향후 확장

- PII 마스킹(anonymization) 옵션 — 차단 대신 `***` 치환 통과
- `pii_labels.json` 스키마 검증 (pydantic 모델)
- Regex 패턴도 모델 폴더 밖 외부 설정으로 분리
- 차단 단어 화이트리스트 (예: "비밀번호 변경" 같은 문맥은 허용)
- NER 결과를 `LayerContext.annotations` 에 기록

## 10. 모델 추가 가이드

새 NER 모델을 L5 에 추가하려면:

1. `l5/model/<새모델명>/` 폴더 생성, HuggingFace 포맷(`config.json`, `model.safetensors`, `tokenizer.json`, `tokenizer_config.json`) 배치
2. 해당 모델의 라벨 스키마를 확인 (`config.json` 의 `id2label` 또는 모델 카드)
3. 라벨별로 PII 성격을 판단해 `pii_labels.json` 작성:
   - 정형 PII 라벨(전화번호, 주민번호 등) → `block_singletons` 에 추가
   - 조합이어야 의미 있는 라벨(인명+지명 등) → `block_combinations` 에 추가
   - 오탐 위험이 높은 라벨(기관명 등) → 양쪽 모두에서 제외
4. `min_score` 는 모델 성능에 따라 조정 (기본 `0.0`, 오탐이 많으면 `0.8` 이상으로)
5. `L5Layer(model_name="<새모델명>")` 로 초기화해 통합 테스트
