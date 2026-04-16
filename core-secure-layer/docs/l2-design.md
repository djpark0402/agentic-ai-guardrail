# L2: Perplexity / Anomaly Detection (혼란도 탐지)

## 1. 목적

사용자 입력이 자연스러운 문장인지 판별한다. 허용되지 않은 문자셋 사용(1차)과 비정상적으로 높은 혼란도(2차)를 순차 검사하여, 난독화되거나 의미 없는 입력을 차단한다.

## 판정 원칙

> **미탐(false negative)은 허용, 오탐(false positive)은 절대 불허.**
>
> 이상한 문장을 못 잡아서 통과시키는 것은 허용한다.
> 정상 문장을 차단하는 것은 절대 안 된다.

## 2. 판정 기준

### 2.1 1차 필터링 — 문자셋 허용 목록 (Character Whitelist)

입력 문자열의 모든 문자가 허용 문자셋에 속하는지 검사한다. 허용되지 않은 문자가 **하나라도** 있으면 즉시 차단하고 2차 필터링은 스킵한다.

**허용 문자셋:**
- 한국어: 가-힣, ㄱ-ㅎ, ㅏ-ㅣ
- 영어: A-Z, a-z
- 숫자: 0-9
- 공백/줄바꿈: 스페이스, 탭, 개행
- 기본 구두점: `. , ! ? : ; ' " - ( ) [ ] { }`
- 수학/기호: `@ # $ % ^ & * + - = ~ / \ | < > _`

**차단 예시:**
- 아랍어, 중국어, 일본어 등 비허용 스크립트
- 제어 문자 (ASCII 0~31 중 탭/개행 제외)
- 이모지
- 특수 유니코드 (영폭 문자, 결합 문자 등)

**오탐 검토:**
- 일반 한국어/영어 문장 → 허용 ✅
- 프로그래밍 코드 (`if x > 0:`) → 허용 ✅ (기호 포함)
- 이모지가 포함된 문장 → 차단 ⚠️ (다국어/이모지 대응은 향후 확장)

### 2.2 2차 필터링 — Perplexity 기반 이상 탐지

1차를 통과한 입력에 대해 로컬 GPT-2 모델로 Perplexity(PPL)를 계산한다. PPL이 설정된 임계값을 초과하면 차단.

**모델:**
- 로컬 폴더에서 로드 (`model_path` 파라미터로 주입)
- GPT-2 계열 (다운로드 또는 직접 학습한 모델)
- `transformers.AutoModelForCausalLM` + `AutoTokenizer`로 로드

**PPL 계산:**
```python
# 토큰화 → 모델 forward → cross-entropy loss → exp(loss) = PPL
inputs = tokenizer(text, return_tensors="pt")
with torch.no_grad():
    outputs = model(**inputs, labels=inputs["input_ids"])
ppl = torch.exp(outputs.loss).item()
```

**임계값:**
- `ppl_threshold` 파라미터로 초기화 시 주입 (기본값 제공)
- `PPL > ppl_threshold` → 차단
- 임계값은 모델/도메인에 따라 튜닝 필요

**오탐 검토:**
- 일반 문장 ("오늘 날씨가 좋다") → PPL 낮음 → 허용 ✅
- 전문 용어 ("Kubernetes pod autoscaling") → PPL 다소 높을 수 있음 → 임계값으로 조절
- 난독화된 입력 ("asjdf;lkaj sdkfj") → PPL 매우 높음 → 차단 ✅
- 프롬프트 인젝션 ("Ignore previous instructions") → PPL 보통~높음 → 임계값에 따라 결정

## 3. 입력/출력

### 입력: `GuardrailRequest`

| 필드 | 사용 여부 | 용도 |
|------|-----------|------|
| `user_input` | O | 문자셋 검사 + PPL 계산 대상 |
| `session_id` | X | 사용 안 함 |
| `metadata` | X | 사용 안 함 |

### 레이어 초기화

```python
layer = L2Layer(
    model_path="/path/to/gpt2",    # 로컬 모델 폴더
    ppl_threshold=600.0,            # PPL 임계값
)
```

- `model_path`: 모델/토크나이저가 저장된 로컬 디렉토리 경로
- `ppl_threshold`: PPL 차단 임계값 (float)

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

**1차 차단 시 (문자셋 위반):**
```python
LayerResult(
    name="L2",
    allowed=False,
    reason="disallowed character detected at position 5: 'α'",
    confidence=0.0,
    severity=Severity.MEDIUM,
    tags=["charset", "disallowed_character"],
)
```

**2차 차단 시 (PPL 초과):**
```python
LayerResult(
    name="L2",
    allowed=False,
    reason="high perplexity: 1523.4 (threshold: 600.0)",
    confidence=0.0,
    severity=Severity.MEDIUM,
    tags=["perplexity", "anomaly"],
)
```

- 1차: `severity=MEDIUM`, tags=`["charset", "disallowed_character"]`
- 2차: `severity=MEDIUM`, tags=`["perplexity", "anomaly"]`
- MEDIUM 사유: L1(HIGH)보다 낮은 확신도. PPL은 확률적 판단

## 4. 엣지 케이스

| 케이스 | 판정 | 이유 |
|--------|------|------|
| 빈 문자열 `""` | 허용 | 문자셋 위반 없음, PPL 계산 불필요 |
| 공백만 `"   "` | 허용 | 허용 문자셋, PPL 계산 시 모델에 따라 다름 → fail-open |
| 일반 한국어 `"오늘 날씨가 좋다"` | 허용 | 문자셋 OK, PPL 낮음 |
| 일반 영어 `"Hello world"` | 허용 | 문자셋 OK, PPL 낮음 |
| 이모지 포함 `"안녕 😀"` | 차단 (1차) | 이모지는 허용 문자셋 밖 |
| 아랍어 `"مرحبا"` | 차단 (1차) | 비허용 스크립트 |
| 난독화 `"asjkdf lkajsd fkj"` | 차단 (2차) | PPL 매우 높음 |
| 짧은 입력 `"hi"` | 허용 | PPL 계산 가능하지만 정상 범위 |
| 매우 긴 입력 (10,000자+) | 정상 동작 | 토큰 길이 제한으로 자를 수 있음 |
| 모델 로드 실패 | 허용 | fail-open |
| PPL 계산 중 예외 | 허용 | fail-open |

## 5. 보안 고려

- **fail-open**: 모델 로드 실패, PPL 계산 예외 시 허용. 오탐 방지 우선
- **모델 경로 검증**: 존재하지 않는 경로가 주어지면 초기화 시 경고, 2차 필터링은 비활성 (1차만 동작)
- **토큰 길이 제한**: 모델의 max_length를 초과하는 입력은 잘라서 처리 (truncation)
- **GPU/CPU**: torch 사용 시 디바이스 자동 감지 (cuda 사용 가능하면 cuda, 아니면 cpu)
- **메모리**: 모델을 레이어 인스턴스에 캐싱하여 요청마다 재로드하지 않음

## 6. 의존성

- **선행 레이어**: L1 (인코딩 탐지)
- **외부 라이브러리**:
  - `transformers` — 모델/토크나이저 로드
  - `torch` — PPL 계산
- **LangChain**: 사용 안 함
- **pyproject.toml 변경 필요**: `transformers`, `torch` 의존성 추가

## 7. 향후 확장

- 다국어 문자셋 지원 (중국어, 일본어, 아랍어 등)
- 이모지 허용 옵션
- 언어별 모델 분기 (KoGPT2 / GPT-2)
- PPL 외 추가 이상 지표 (entropy, token 분포 등)
- 동적 임계값 (입력 길이/도메인에 따른 조절)
- 모델 핫스왑 (재시작 없이 모델 교체)
