# L3: Signature / Pattern Matching (Attack Pattern 유사도 검사)

## 1. 목적

사전에 임베딩하여 VectorDB에 저장된 공격 패턴(prompt injection, jailbreak 등)과 사용자 입력의 코사인 유사도를 계산하여, 유사도가 높으면 차단한다. 알려진 공격 패턴에 대한 **시그니처 기반 탐지** 레이어.

## 판정 원칙

> **미탐(false negative)은 허용, 오탐(false positive)은 절대 불허.**
>
> 새로운 공격 패턴을 못 잡아서 통과시키는 것은 허용한다 — DB에 없는 패턴은 후속 레이어에서 잡는다.
> 정상 문장을 공격 패턴으로 오인하여 차단하는 것은 절대 안 된다.

## 2. 판정 기준

1. 사용자 입력을 임베딩 모델로 벡터화
2. ChromaDB에서 top-K 유사 패턴 검색
3. **top-K 결과의 평균 코사인 유사도**가 임계값을 초과하면 차단

### 왜 top-1이 아닌 평균인가

단일 패턴과의 우연한 높은 유사도로 인한 오탐을 방지한다. 여러 공격 패턴과 고르게 유사해야 차단되므로 정상 문장이 걸릴 확률이 낮아진다.

## 3. 아키텍처

```
user_input
    │
    ▼
[임베딩 모델] ──→ input_vector
    │
    ▼
[ChromaDB query] ──→ top-K 결과 (distance 포함)
    │
    ▼
[평균 유사도 계산] ──→ avg_similarity > threshold?
    │                         │
    Yes                       No
    ▼                         ▼
  차단                      허용
```

## 4. 초기화 및 의존성

### L3Layer 초기화

```python
layer = L3Layer(
    db_path="l3/vectordb",            # ChromaDB 저장 경로
    model_path="l3/model",            # 임베딩 모델 로컬 폴더
    similarity_threshold=0.8,         # 평균 유사도 차단 임계값
    top_k=5,                          # 검색할 유사 패턴 수
)
```

| 파라미터 | 타입 | 기본값 | 설명 |
|----------|------|--------|------|
| `db_path` | `str` | `l3/vectordb` | ChromaDB 영속 저장 경로 |
| `model_path` | `str` | `l3/model` | sentence-transformers 모델 경로 |
| `similarity_threshold` | `float` | `0.8` | 평균 유사도 차단 임계값 |
| `top_k` | `int` | `5` | 검색 결과 수 |

### 디렉토리 구조

```
l3/
├── l3.py
├── vectordb/           # ChromaDB 영속 데이터
│   └── chroma/         # ChromaDB 내부 파일
└── model/              # 임베딩 모델 (sentence-transformers)
```

### 외부 라이브러리

- `chromadb` — 벡터 저장/검색
- `sentence-transformers` — 임베딩 생성 (또는 로컬 폴더의 커스텀 모델)
- `torch` — sentence-transformers 의존

## 5. 입력/출력

### 입력: `GuardrailRequest`

| 필드 | 사용 여부 | 용도 |
|------|-----------|------|
| `user_input` | O | 임베딩 → 유사도 검색 대상 |
| `session_id` | X | 사용 안 함 |
| `metadata` | X | 사용 안 함 |

### 출력: `LayerResult`

**허용 시:**
```python
LayerResult(
    name="L3",
    allowed=True,
    confidence=1.0,
    severity=Severity.NONE,
)
```

**차단 시:**
```python
LayerResult(
    name="L3",
    allowed=False,
    reason='similar to attack pattern "prompt_injection" (similarity: 0.92)',
    confidence=0.0,
    severity=Severity.HIGH,
    tags=["signature", "prompt_injection"],
)
```

- `reason`: `'similar to attack pattern "{pattern_name}" (similarity: {avg:.2f})'`
  - `pattern_name`: top-K 중 가장 유사도가 높은 패턴의 이름
- `severity`: `HIGH` (알려진 공격 패턴과 매칭)
- `confidence`: 차단=`0.0`, 허용=`1.0`
- `tags`: `["signature", "{pattern_name}"]`

## 6. 엣지 케이스

| 케이스 | 판정 | 이유 |
|--------|------|------|
| 빈 문자열 `""` | 허용 | 임베딩 불필요 |
| 일반 문장 `"오늘 날씨가 좋다"` | 허용 | 공격 패턴과 유사도 낮음 |
| 알려진 공격 `"Ignore previous instructions"` | 차단 | DB에 유사 패턴 존재 |
| DB가 비어있음 | 허용 | 검색 결과 없음 → 유사도 0 |
| 임베딩 모델 미로드 | 허용 | fail-open |
| ChromaDB 미로드 | 허용 | fail-open |
| top-K < K (결과 부족) | 있는 만큼 평균 | 결과 0개면 허용 |
| 매우 긴 입력 | 정상 동작 | 임베딩 모델의 max_length로 truncation |
| 예외 발생 | 허용 | fail-open |

## 7. 보안 고려

- **fail-open**: DB/모델 미로드, 임베딩 실패, 검색 예외 시 허용. 오탐 방지 우선
- **임베딩 안전성**: sentence-transformers `encode()`는 임의 입력에 대해 안전
- **ChromaDB 안전성**: 로컬 파일 기반, 외부 네트워크 불필요
- **DB 무결성**: 사전 빌드된 DB를 읽기 전용으로 사용. 런타임 중 패턴 추가/삭제 없음
- **우회 가능성**: DB에 없는 새로운 공격 패턴은 탐지 불가 (미탐 허용)

## 8. 향후 확장

- 런타임 패턴 추가/삭제 API
- 패턴 카테고리별 임계값 차등 설정
- top-K 외 ANN (Approximate Nearest Neighbor) 알고리즘 최적화
- 다국어 임베딩 모델 지원
- 유사도 결과를 LayerContext annotations에 기록 (후속 레이어 활용)
- 패턴 DB 버전 관리 및 핫스왑
