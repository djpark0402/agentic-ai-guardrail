# L5: PII Detection & Anonymization (NER)

## 1. 목적

사용자 입력에서 개인식별정보(PII)와 민감 정보를 탐지하여 차단한다. 2단계 필터링으로 정규식 패턴 → NER 모델 순서로 검사하며, 앞 단계에서 탐지되면 즉시 차단한다.

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

1단계를 통과한 입력에 대해 로컬 NER 모델로 개체명 인식을 수행.

**탐지 대상 엔티티:**
- `PERSON` (인명)
- `LOCATION` (주소/위치)
- `ORGANIZATION` (기관명) — 오탐 위험이 높으므로 단독으로는 차단하지 않음
- `DATE_OF_BIRTH` (생년월일)
- 기타 PII 엔티티 (모델에 따라)

**NER 차단 기준:**
- `PERSON` + `LOCATION` 또는 `PERSON` + `DATE_OF_BIRTH` 조합이 동시에 감지되면 차단 (단일 엔티티만으로는 오탐 가능)
- 단, `PERSON` 단독 감지는 허용 (일반 대화에서 이름 언급은 정상)

## 3. 초기화

```python
layer = L5Layer(
    model_name="ner-ko",                     # NER 모델 선택
    extra_patterns=[r"PROJ-\d{6}"],           # 추가 차단 정규식
)
```

| 파라미터 | 타입 | 기본값 | 설명 |
|----------|------|--------|------|
| `model_name` | `str` | `"ner-ko"` | NER 모델 폴더명 (`model/` 하위) |
| `extra_patterns` | `list[str]` | `[]` | 추가 차단 정규식 리스트 |

## 4. 디렉토리 구조

```
l5/
├── l5.py
└── model/
    └── ner-ko/         # 기본 한국어 NER 모델
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
    reason='PII detected: phone_number at position 5',
    confidence=0.0,
    severity=Severity.HIGH,
    tags=["pii", "phone_number"],
)
```

**차단 시 (NER):**
```python
LayerResult(
    name="L5",
    allowed=False,
    reason='PII detected: person+location at position 3',
    confidence=0.0,
    severity=Severity.HIGH,
    tags=["pii", "ner", "person"],
)
```

- `reason`: `'PII detected: {pii_type} at position {N}'`
- `severity`: `HIGH`
- `confidence`: 차단=`0.0`, 허용=`1.0`
- `tags`: `["pii", "{pii_type}"]` (NER의 경우 `["pii", "ner", "{entity_type}"]`)

## 6. 엣지 케이스

| 케이스 | 판정 | 이유 |
|--------|------|------|
| 빈 문자열 `""` | 허용 | 탐지 대상 없음 |
| 일반 문장 `"오늘 날씨가 좋다"` | 허용 | PII 없음 |
| `"010-1234-5678"` | 차단 (1단계) | 전화번호 Regex 매칭 |
| `"user@gmail.com"` | 차단 (1단계) | 이메일 Regex 매칭 |
| `"900101-1234567"` | 차단 (1단계) | 주민등록번호 Regex 매칭 |
| `"sk-abc123..."` | 차단 (1단계) | API 키 Regex 매칭 |
| `"홍길동이 서울에 산다"` | 차단 (2단계) | NER: PERSON + LOCATION 조합 |
| `"홍길동이 좋아한다"` | 허용 | NER: PERSON 단독 → 오탐 방지 |
| NER 모델 미로드 | 허용 | fail-open (1단계 Regex만 동작) |
| 외부 주입 패턴 매칭 | 차단 (1단계) | extra_patterns에 포함된 정규식 |
| 예외 발생 | 허용 | fail-open |

## 7. 보안 고려

- **fail-open**: NER 모델 미로드, 예외 시 허용. 1단계(Regex)는 모델 없이도 동작
- **Regex 안전성**: 외부 주입 정규식의 ReDoS 방지를 위해 타임아웃 또는 패턴 길이 제한 고려
- **PII 원문 비노출**: reason에 탐지 타입+위치만 포함, 원문은 노출하지 않음 (로그 유출 방지)

## 8. 의존성

- **선행 레이어**: L1~L4
- **외부 라이브러리**: `transformers` (NER 모델), `torch`
- **LangChain**: 사용 안 함

## 9. 향후 확장

- PII 마스킹(anonymization) 옵션 — 차단 대신 `***`로 치환하여 통과
- 한국어 특화 NER 모델 추가 (KoELECTRA 등)
- 커스텀 엔티티 타입 지원
- NER 결과를 LayerContext annotations에 기록
- 정규식 패턴 외부 설정 파일(JSON) 지원
- 차단 단어 화이트리스트 (예: "비밀번호 변경" 같은 문맥은 허용)
