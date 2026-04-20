# L2: Perplexity / Anomaly Detection (혼란도 탐지)

## 1. 목적

사용자 입력이 자연스러운 문장인지 판별한다. 허용되지 않은 문자셋 사용(1차), 알려진 의심 패턴/시크릿 노출(2차), 비정상적 문자 분포(3차), 비정상적으로 높은 혼란도(4차) 를 순차 검사하여, 난독화되거나 의미 없는 입력, 공격성 명령·코드, 시크릿/자격증명, 무의미/무작위 텍스트를 차단한다.

## 판정 원칙

> **미탐(false negative)은 허용, 오탐(false positive)은 절대 불허.**
>
> 이상한 문장을 못 잡아서 통과시키는 것은 허용한다.
> 정상 문장을 차단하는 것은 절대 안 된다.

이 원칙은 모든 단계의 최우선 필터다. 각 단계 내부에서 예외 발생 시 해당 단계를 skip 하고 다음 단계로 진행하거나 허용한다.

**예외 조항 (L2 한정 오탐 수용)**: 2차 regex 패턴 목록에는 "위험 명령어·코드 인젝션" 과 "API 키·시크릿 노출" 에 대한 정규식이 포함된다. 이 패턴들은 정상 개발/운영 문서에서도 등장할 여지가 있어 이론적으로 오탐을 발생시킬 수 있다. 본 레이어는 설계자의 명시적 결정으로 이 패턴 전체를 그대로 수용한다. 튜닝 없이 **원본 정규식 그대로 적용** 하며, 오탐 관찰 시 별도 작업으로 정제한다.

## 2. 판정 기준

입력은 네 단계로 순차 검사한다. 앞 단계에서 차단되면 뒤 단계는 실행하지 않는다.

```
1차 charset whitelist → 2차 regex pattern → 3차 shannon entropy → 4차 PPL
```

### 2.1 1차 필터링 — 문자셋 허용 목록 (Character Whitelist)

입력 문자열의 모든 문자가 허용 문자셋에 속하는지 검사한다. 허용되지 않은 문자가 **하나라도** 있으면 즉시 차단하고 이후 단계는 스킵한다.

**허용 문자셋:**
- 한국어: 가-힣, ㄱ-ㅎ, ㅏ-ㅣ
- 영어: A-Z, a-z
- 숫자: 0-9
- 공백/줄바꿈: 스페이스, 탭, 개행
- 기본 구두점: `. , ! ? : ; ' " - ( ) [ ] { }`
- 수학/기호: `@ # $ % ^ & * + - = ~ / \ | < > _`

### 2.2 2차 필터링 — Regex 패턴 탐지 (신규)

1차를 통과한 입력에 대해 미리 정의된 정규식 패턴 리스트를 순회한다. **첫 매치에서 즉시 차단**. 패턴 리스트는 아래 3계열을 합친 모듈 상수다.

**(A) 텍스트 구조 이상**
```
(.)\1{9,}                                   → "동일 문자 10회 이상 반복"
[ㄱ-ㅎㅏ-ㅣ]{5,}                              → "자음/모음만 5자 이상 나열"
[\x00-\x08\x0b\x0c\x0e-\x1f]{2,}            → "제어 문자 다수 포함"
(?:[^\s]{50,})                              → "공백 없는 50자 이상 연속"
```

참고: 자모 정규식은 초기 원안 `(?:[ㄱ-ㅎㅏ-ㅣ]\s*){5,}` 에서 `\s*` 반복자 부분을 제거했다. 원안은 공백으로 구분된 정상 자모 나열(예: 한국어 타자 강의에서 등장 가능한 `"ㄱㄴㄷㄹ ㅏㅓㅗㅜ"`) 을 오탐하여 기존 허용 테스트에 회귀를 일으켰다.

**(B) 위험 명령어 / 코드 인젝션**
```
(?i)rm\s+-rf                                → "rm -rf"
(?i)DROP\s+TABLE                            → "DROP TABLE"
(?i)os\.system\s*\(                         → "os.system"
(?i)exec\s*\(|eval\s*\(                     → "exec/eval"
(?i)subprocess\.|Popen\s*\(                 → "subprocess"
(?i)SELECT\s+.+FROM|INSERT\s+INTO|UPDATE\s+.+SET|DELETE\s+FROM
                                            → "SQL 명령"
(?i)<script[\s>]|javascript:                → "스크립트 인젝션"
(?i)\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}|%[0-9a-f]{2}.*%[0-9a-f]{2}
                                            → "인코딩 페이로드"
```

참고: 초기 원안에 있던 `(?i)document\.cookie` / `(?i)nmap\s+-[a-zA-Z]` 2개 패턴은 단독 위협성이 낮고 다른 패턴과 문맥 중복이 있어 현재 구현에서는 제외했다. 필요 시 후속 작업에서 복원 검토.

**(C) API 키 / 시크릿**
```
(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[=:]\s*\S+
                                            → "API 키 노출"
sk-ant-api03-[a-zA-Z0-9_-]{20,}             → "Anthropic API Key"
sk-[a-zA-Z0-9]{20,}                         → "OpenAI API Key"
AKIA[0-9A-Z]{16}                            → "AWS Access Key"
ghp_[a-zA-Z0-9]{36}                         → "GitHub PAT"
github_pat_[a-zA-Z0-9_]{20,}                → "GitHub Fine-grained"
xox[bpsa]-[a-zA-Z0-9-]{10,}                 → "Slack Token"
-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----    → "Private Key"
eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}   → "JWT"
(?i)(password|passwd|pwd)\s*[=:]\s*\S+      → "비밀번호 노출"
```

**검사 함수:**
```python
def _check_regex(text, patterns=_DEFAULT_PATTERNS) -> tuple[bool, str]:
    for pattern, desc in patterns:
        if re.search(pattern, text):
            return True, f"의심 패턴 탐지: {desc}"
    return False, "의심 패턴 없음"
```

### 2.3 3차 필터링 — Shannon Entropy (신규)

2차를 통과한 입력의 문자 분포 엔트로피를 계산하여 하한/상한 범위 밖이면 차단.

```python
def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counter.values()
    )

def _check_entropy(text, low=1.5, high=5.5) -> tuple[bool, str, float]:
    ent = _shannon_entropy(text)
    if ent < low:
        return True, f"엔트로피 {ent:.2f} < 하한 {low} (너무 단조로움)", ent
    if ent > high:
        return True, f"엔트로피 {ent:.2f} > 상한 {high} (너무 무작위)", ent
    return False, f"엔트로피 {ent:.2f} 정상 범위", ent
```

- 하한 `1.5` 미만: `"aaaaa..."` 같은 단조로운 입력
- 상한 `5.5` 초과: 난수·무작위 문자열
- 임계값은 `entropy_low`, `entropy_high` 파라미터로 조정 가능 (기본값 1.5 / 5.5)

### 2.4 4차 필터링 — Perplexity 기반 이상 탐지

3차를 통과한 입력에 대해 로컬 GPT-2 모델로 Perplexity(PPL) 를 계산한다. PPL 이 설정된 임계값을 초과하면 차단.

**모델:**
- 로컬 폴더에서 로드 (`model_name` 파라미터로 `model/` 하위 지정)
- GPT-2 계열
- `transformers.AutoModelForCausalLM` + `AutoTokenizer` 로 로드
- MPS/CUDA/CPU 자동 감지

**PPL 계산:**
```python
inputs = tokenizer(text, return_tensors="pt", truncation=True)
with torch.no_grad():
    outputs = model(**inputs, labels=inputs["input_ids"])
ppl = torch.exp(outputs.loss).item()
```

**임계값:**
- `ppl_threshold` 파라미터로 주입 (기본값 600.0)
- `PPL > ppl_threshold` → 차단

## 3. 입력/출력

### 입력: `GuardrailRequest`

| 필드 | 사용 여부 | 용도 |
|------|-----------|------|
| `user_input` | O | 모든 단계의 검사 대상 |
| `session_id` | X | 사용 안 함 |
| `metadata` | X | 사용 안 함 |

### 레이어 초기화

```python
layer = L2Layer(
    model_name="gpt2",       # 모델 폴더명 (model/ 하위)
    ppl_threshold=600.0,     # 4차 PPL 임계값
    entropy_low=1.5,         # 3차 엔트로피 하한
    entropy_high=5.5,        # 3차 엔트로피 상한
)
```

### 출력: `LayerResult`

**허용 시:**
```python
LayerResult(
    name="L2",
    allowed=True,
    confidence=1.0,
    severity=Severity.NONE,
)
```

**1차 차단 (문자셋 위반):**
```python
LayerResult(
    name="L2",
    allowed=False,
    reason="disallowed character detected at position 5: 'α'",
    severity=Severity.MEDIUM,
    tags=["charset", "disallowed_character"],
)
```

**2차 차단 (Regex 의심 패턴):**
```python
LayerResult(
    name="L2",
    allowed=False,
    reason="의심 패턴 탐지: API 키 노출",
    severity=Severity.MEDIUM,
    tags=["anomaly", "regex"],
)
```

**3차 차단 (엔트로피):**
```python
LayerResult(
    name="L2",
    allowed=False,
    reason="엔트로피 6.12 > 상한 5.5 (너무 무작위)",
    severity=Severity.MEDIUM,
    tags=["anomaly", "entropy"],
)
```

**4차 차단 (PPL 초과):**
```python
LayerResult(
    name="L2",
    allowed=False,
    reason="high perplexity: 1523.4 (threshold: 600.0)",
    severity=Severity.MEDIUM,
    tags=["perplexity", "anomaly"],
)
```

- severity 는 모든 단계 `MEDIUM` 유지
- 2/3차 reason 메시지 한국어 (원본 설명 보존). 1/4차는 기존 영어 메시지 유지

## 4. 엣지 케이스

| 케이스 | 판정 | 단계 |
|--------|------|------|
| 빈 문자열 `""` | 허용 | 전 단계 스킵 |
| 공백만 `"   "` | 허용 | 전 단계 스킵 |
| `"오늘 날씨가 좋다"` | 허용 | 4단계 모두 통과 |
| `"안녕 😀"` | 차단 (1차) | 이모지 |
| `"aaaaaaaaaa"` (10자 동일) | 차단 (2차) | `(.)\1{9,}` 매치 |
| `"ㅋㅋㅋㅋㅋㅋㅋㅋㅋㅋ"` | 차단 (2차) | 동일 문자 10회 — **의도된 오탐 수용** |
| `"ㄱㄴㄷㄹㅁ"` | 차단 (2차) | 자모음 5자+ |
| `"rm -rf /"` | 차단 (2차) | rm -rf |
| `"DROP TABLE users"` | 차단 (2차) | DROP TABLE |
| `"sk-ant-api03-abcdefghij1234567890"` | 차단 (2차) | Anthropic API Key |
| `"eyJhbGciOiJ.eyJzdWIiOiI"` | 차단 (2차) | JWT |
| `"password=hunter2"` | 차단 (2차) | 비밀번호 노출 |
| `"<script>alert(1)</script>"` | 차단 (2차) | 스크립트 인젝션 |
| `"SELECT * FROM users"` | 차단 (2차) | SQL 명령 — **의도된 오탐 수용** |
| `"a" * 100` | 차단 (2차) | 동일 문자 100회 (2차가 먼저 매치, 엔트로피까지 안 감) |
| 완전 난수 (base64-like) 긴 문자열 | 차단 (3차) | 엔트로피 > 5.5 — 단, 2차 regex 에 먼저 걸릴 수도 있음 |
| 짧은 단조 입력 `"a"` | 허용 | 1자 → 엔트로피 0.0 이지만 전체 문자 분포상 의미 없음. 현재는 `< 1.5` 에 걸려 차단 가능성 있음 |
| `"asjkdf lkajsd fkj"` | 차단 (4차) | 문자셋/regex/entropy 통과 후 PPL 매우 높음 |
| 모델 로드 실패 | 4차 단계만 허용 | 1~3차는 정상 동작 |
| 예외 발생 | 허용 | fail-open |

**짧은 입력에 대한 엔트로피 동작**: 현 스펙은 원본 코드 그대로 `entropy_min_length` 같은 길이 가드 없이 모든 입력에 적용된다. `"ab"` (2자) 같은 매우 짧은 입력도 엔트로피 계산 대상이며 결과적으로 `< 1.5` 에 걸려 차단될 수 있다. 이는 원본 코드의 동작을 그대로 유지한 결과이며, 오탐으로 관찰되면 후속 튜닝 대상.

## 5. 보안 고려

- **fail-open**: 모델 로드 실패 / PPL 계산 예외 / 단계별 예외 시 해당 단계 skip 또는 허용. 오탐 방지 우선
- **정규식 리스트 관리**: `_DEFAULT_PATTERNS` 는 모듈 상수로 유지. 추가/제거는 코드 수정으로만 (런타임 주입 경로 없음)
- **판정 원칙 예외 수용**: 2차 regex 에 포함된 `<script>`, `SELECT ... FROM`, `password=...`, 한국어 `ㅋ` 반복 등은 정상 문맥에서도 등장할 수 있으며 이번 설계에서는 **원본 정규식을 튜닝 없이** 그대로 수용한다. 오탐 발생 시 별도 작업으로 정제
- **토큰 길이 제한**: GPT-2 truncation 적용
- **메모리**: 모델 인스턴스 캐싱 (요청당 재로드 없음)

## 6. 의존성

- **선행 레이어**: L1 (인코딩 탐지 및 정규화)
- **Python 표준 라이브러리**: `re`, `math`, `collections.Counter`, `pathlib`, `logging`
- **외부 라이브러리**: `transformers`, `torch` (4차 PPL 용)
- **LangChain**: 사용 안 함

## 7. 향후 확장

- 다국어 문자셋 지원 (중국어, 일본어, 아랍어 등)
- 이모지 허용 옵션
- 언어별 모델 분기 (KoGPT2 / GPT-2)
- Regex 패턴 동적 로딩 (JSON / 원격)
- 엔트로피 최소 길이 가드 (짧은 입력 오탐 방지)
- Regex 오탐 샘플 수집 및 패턴 정제
- 시크릿 탐지 결과의 별도 severity 분화 (HIGH)
- 패턴별 세분화된 tag (pattern_id 슬러그)
- 동적 임계값 (입력 길이/도메인에 따른 조절)
- 모델 핫스왑 (재시작 없이 모델 교체)
