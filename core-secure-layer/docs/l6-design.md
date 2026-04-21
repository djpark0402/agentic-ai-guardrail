# L6: Safety Model Guard (상용 안전성 모델)

## 1. 목적

Kanana-Safeguard-8B, Llama Guard 등 사전 학습된 안전성 판별 모델을 로컬에서 실행하여 입력의 안전성을 판별한다. 모델이 `unsafe`로 판정하면 차단한다.

## 판정 원칙

> **미탐(false negative)은 허용, 오탐(false positive)은 절대 불허.**
>
> 모델이 못 잡아서 통과시키는 것은 허용한다.
> 정상 문장을 위험하다고 오판하여 차단하는 것은 절대 안 된다.

## 2. 판정 기준

1. 사용자 입력을 로컬 safety 모델에 전달
2. 모델 출력에서 safe/unsafe 판정을 파싱
3. `unsafe` 판정 시 위험 카테고리와 함께 차단

### 공통 인터페이스

모델마다 출력 포맷이 다르지만(Kanana: `safe`/`unsafe\nS1`, Llama Guard: `safe`/`unsafe\nO1`), 전처리 단계에서 공통 형태로 변환한다.

```python
@dataclass
class SafetyResult:
    """모델 출력 파싱 결과."""
    is_safe: bool
    category: str | None = None  # "S1", "O1" 등
```

모델별 차이는 프롬프트 구성과 출력 파싱에서 흡수하며, `_check()` 로직은 `SafetyResult`만 다룬다.

## 3. 초기화

```python
layer = L6Layer(
    model_name="kanana-safeguard-8b",  # 모델 선택
)
```

| 파라미터 | 타입 | 기본값 | 설명 |
|----------|------|--------|------|
| `model_name` | `str` | `"kanana-safeguard-8b"` | 모델 폴더명 (`model/` 하위) |

### 디렉토리 구조

```
l6/
├── l6.py
└── model/
    ├── kanana-safeguard-8b/    # Kanana-Safeguard 모델
    └── llama-guard-3-8b/       # Llama Guard 모델
```

## 4. 런타임 흐름

```
user_input
    │
    ▼
[모델별 프롬프트 구성] → 입력 포맷팅
    │
    ▼
[로컬 모델 추론] → 모델 출력 텍스트
    │
    ▼
[출력 파싱] → SafetyResult(is_safe, category)
    │
    ▼
is_safe=True → 허용
is_safe=False → 차단 (category 포함)
```

### 모델별 프롬프트/파싱

**Kanana-Safeguard-8B:**
- 입력: 모델 자체 채팅 템플릿에 사용자 메시지 전달
- 출력: `"safe"` 또는 `"unsafe\nS1"` (S1=violence 등)

**Llama Guard 3:**
- 입력: 특정 프롬프트 포맷 (`<|begin_of_text|>...`)
- 출력: `"safe"` 또는 `"unsafe\nO1"` (O1=violence 등)

공통 파싱: 첫 줄이 `"safe"`이면 허용, `"unsafe"`이면 차단. 두 번째 줄이 있으면 카테고리로 추출.

## 5. 입력/출력

### 입력: `GuardrailRequest`

| 필드 | 사용 여부 | 용도 |
|------|-----------|------|
| `user_input` | O | 안전성 판별 대상 |
| `session_id` | X | 사용 안 함 |
| `metadata` | X | 사용 안 함 |

### 출력: `LayerResult`

**허용 시:**
```python
LayerResult(
    name="L6",
    allowed=True,
    confidence=1.0,
    severity=Severity.NONE,
)
```

**차단 시:**
```python
LayerResult(
    name="L6",
    allowed=False,
    reason='unsafe: S1 (violence)',
    confidence=0.0,
    severity=Severity.CRITICAL,
    tags=["safety_model", "S1"],
)
```

- `reason`: `'unsafe: {category}'` (카테고리 없으면 `'unsafe content detected'`)
- `severity`: `CRITICAL` (safety 모델 판정은 최고 심각도)
- `confidence`: 차단=`0.0`, 허용=`1.0`
- `tags`: `["safety_model", "{category}"]`

## 6. 엣지 케이스

| 케이스 | 판정 | 이유 |
|--------|------|------|
| 빈 문자열 `""` | 허용 | 추론 불필요 |
| 일반 문장 `"오늘 날씨가 좋다"` | 허용 | 모델이 safe 판정 |
| 위험 입력 | 차단 | 모델이 unsafe 판정 |
| 모델 미로드 | 허용 | fail-open |
| 모델 출력 파싱 실패 | 허용 | fail-open |
| 모델 추론 중 예외 | 허용 | fail-open |
| 카테고리 없이 `"unsafe"`만 | 차단 | reason: `'unsafe content detected'` |
| 예외 발생 | 허용 | fail-open |

## 7. 보안 고려

- **fail-open**: 모델 미로드, 추론 예외, 파싱 실패 시 허용. 오탐 방지 우선
- **모델 로딩**: `transformers.AutoModelForCausalLM` + `AutoTokenizer`로 로드. GPU 사용 가능 시 자동 감지
- **메모리**: 8B 모델은 GPU VRAM 16GB+ 필요. CPU fallback 지원하되 성능 저하 감안
- **추론 안전성**: `model.generate()`는 임의 입력에 대해 안전

## 8. 의존성

- **선행 레이어**: L1~L5
- **외부 라이브러리**: `transformers`, `torch`
- **LangChain**: 사용 안 함

## 9. 향후 확장

- 추가 safety 모델 지원 (ShieldGemma, Aegis 등)
- 모델별 프롬프트 템플릿 외부 설정 파일화
- 배치 추론 지원 (여러 입력 동시 판별)
- 모델 출력 confidence score 활용 (현재는 이진 판정만)
- 모델 캐싱/핫스왑
- quantization(GPTQ/AWQ) 모델 지원으로 메모리 절약
