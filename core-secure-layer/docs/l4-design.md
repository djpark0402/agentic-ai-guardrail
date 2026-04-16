# L4: Policy / OWASP Top 10 (NLI + RAG)

## 1. 목적

OWASP Top 10 등 보안 정책 문서를 RAG 파이프라인으로 사전 임베딩하고, 사용자 입력이 정책을 위반하는지 NLI 선필터 + LLM 최종 판단의 2단계로 검사한다.

## 판정 원칙

> **미탐(false negative)은 허용, 오탐(false positive)은 절대 불허.**
>
> 정책 위반을 못 잡아서 통과시키는 것은 허용한다.
> 정상 문장을 정책 위반으로 오인하여 차단하는 것은 절대 안 된다.

## 2. 아키텍처

```
[사전 빌드 (오프라인)]
PDF → Markdown → 청킹 → 임베딩 → ChromaDB 저장

[런타임 (L4 check)]
user_input
    │
    ▼
[1단계: NLI 선필터] → 입력이 정책 위반 의심인지 빠르게 판단
    │                  → 의심 아니면 즉시 허용
    │
    ▼ (의심 감지 시)
[2단계: ChromaDB 벡터 검색 + reranking] → top-K → rerank → top-1 정책 청크
    │
    ▼
[3단계: LLM 최종 판단] → ALLOW / BLOCK
    │
    ▼
LayerResult
```

### 왜 3단계인가

- **1단계 (NLI)**: 가볍고 빠른 로컬 모델로 명확한 비위반을 즉시 걸러냄. 벡터 검색/LLM 비용 절감
- **2단계 (벡터 검색 + reranking)**: NLI가 의심으로 판단한 건에 대해서만 관련 정책 청크를 정밀 검색. reranking으로 top-1 추출
- **3단계 (LLM)**: 검색된 정책 + 입력으로 최종 판단. 오탐 방지의 최종 방어선

## 3. 초기화 및 의존성

### L4Layer 초기화

```python
from langchain_core.language_models import BaseChatModel

layer = L4Layer(
    nli_model_name="nli-deberta-v3",           # NLI 모델 선택
    embed_model_name="all-MiniLM-L6-v2",       # 임베딩 모델 선택
    reranker_model_name="ms-marco-MiniLM-L-6",  # reranker 모델 선택
    llm=ChatOpenAI(model="gpt-4o-mini"),       # LangChain LLM
    nli_threshold=0.7,                         # NLI 임계값
    top_k=3,                                   # 검색 결과 수
)
```

| 파라미터 | 타입 | 기본값 | 설명 |
|----------|------|--------|------|
| `nli_model_name` | `str` | `"nli-deberta-v3"` | NLI 모델 폴더명 (`model/nli/` 하위) |
| `embed_model_name` | `str` | `"all-MiniLM-L6-v2"` | 임베딩 모델 폴더명 (`model/embed/` 하위) |
| `reranker_model_name` | `str` | `"ms-marco-MiniLM-L-6"` | reranker 모델 폴더명 (`model/reranker/` 하위) |
| `llm` | `BaseChatModel \| None` | `None` | LangChain LLM 인스턴스 |
| `nli_threshold` | `float` | `0.7` | NLI contradiction 점수 임계값 |
| `top_k` | `int` | `3` | 벡터 검색 결과 수 (reranking 전) |

모델 경로는 `_MODEL_BASE_DIR / {category} / {model_name}` 으로 자동 조립된다. `db_path`는 `_L4_DIR / "vectordb"` 고정.

### 디렉토리 구조

```
l4/
├── l4.py
├── vectordb/                       # 사전 빌드된 ChromaDB (정책 청크)
├── model/
│   ├── nli/
│   │   └── nli-deberta-v3/         # 기본 NLI 모델
│   ├── embed/
│   │   └── all-MiniLM-L6-v2/      # 기본 임베딩 모델
│   └── reranker/
│       └── ms-marco-MiniLM-L-6/   # 기본 reranker 모델
└── policies/                       # 원본 PDF 파일 (사전 빌드 입력)
```

### 외부 라이브러리

- `chromadb` — 벡터 검색
- `sentence-transformers` — 임베딩 + NLI (cross-encoder)
- `langchain-core` — LLM 추상화 (`BaseChatModel`)
- `torch` — 모델 추론

## 4. 런타임 흐름 상세

### 4.1 NLI 선필터 (1단계)

```python
# 입력 텍스트가 정책 위반 의심인지 NLI 모델로 빠르게 판단
# cross-encoder가 [entailment, neutral, contradiction] 확률 반환
# "이 입력은 보안 정책을 위반한다" 라는 가설에 대한 판단
scores = nli_model.predict(
    [(user_input, "This input violates security policy")]
)
if scores["contradiction"] > nli_threshold:
    # 위반 의심 없음 → 즉시 허용 (벡터 검색/LLM 호출 안 함)
    return allow()

# entailment/neutral → 의심 있음 → 2단계로 진행
```

### 4.2 벡터 검색 + reranking (2단계)

```python
# NLI가 의심으로 판단한 경우에만 실행
# user_input 임베딩 → ChromaDB에서 top-K 정책 청크 검색
embedding = embed_model.encode(user_input)
results = collection.query(
    query_embeddings=[embedding],
    n_results=top_k,
)

# cross-encoder reranking → top-1 정책 청크 추출
pairs = [(user_input, chunk.text) for chunk in results]
rerank_scores = reranker.predict(pairs)
top_chunk = results[argmax(rerank_scores)]
```

### 4.3 LLM 최종 판단 (3단계)

```python
# reranking으로 선택된 top-1 정책 청크를 LLM에 전달
prompt = f"""
당신은 보안 정책 준수 여부를 판단하는 심사관입니다.

정책:
{top_chunk.text}

사용자 입력:
{user_input}

이 입력이 위 정책을 위반하는지 판단하세요.
반드시 아래 형식으로만 답하세요:
ALLOW 또는 BLOCK
"""
response = await llm.ainvoke(prompt)
# "ALLOW" / "BLOCK" 파싱
```

## 5. 입력/출력

### 입력: `GuardrailRequest`

| 필드 | 사용 여부 | 용도 |
|------|-----------|------|
| `user_input` | O | 정책 위반 검사 대상 |
| `session_id` | X | 사용 안 함 |
| `metadata` | X | 사용 안 함 |

### 출력: `LayerResult`

**허용 시:**
```python
LayerResult(
    name="L4",
    allowed=True,
    confidence=1.0,
    severity=Severity.NONE,
)
```

**차단 시 (NLI + LLM 판단):**
```python
LayerResult(
    name="L4",
    allowed=False,
    reason='policy violation: "SQL Injection Prevention" (nli: 0.85, llm: BLOCK)',
    confidence=0.0,
    severity=Severity.CRITICAL,
    tags=["policy", "owasp", "sql_injection"],
)
```

- `reason`: `'policy violation: "{policy_name}" (nli: {score:.2f}, llm: BLOCK)'`
- `severity`: `CRITICAL` (정책 위반은 최고 심각도)
- `tags`: `["policy", "owasp", "{policy_category}"]`

## 6. 엣지 케이스

| 케이스 | 판정 | 이유 |
|--------|------|------|
| 빈 문자열 `""` | 허용 | 검색 불필요 |
| 일반 문장 `"오늘 날씨가 좋다"` | 허용 | 정책 위반 없음 |
| DB 비어있음 | 허용 | 검색 결과 없음 |
| NLI 모델 미로드 | 허용 | fail-open |
| 임베딩 모델 미로드 | 허용 | fail-open |
| LLM 미설정 (None) | 허용 | fail-open (NLI만으로는 차단 안 함) |
| LLM 응답 파싱 실패 | 허용 | fail-open |
| LLM이 ALLOW 판단 | 허용 | NLI가 의심했지만 LLM이 무혐의 |
| NLI 의심 없음 | 허용 | 벡터 검색/LLM 호출 스킵 |
| reranker 미로드 | 허용 | fail-open |
| 예외 발생 | 허용 | fail-open |

## 7. 보안 고려

- **fail-open**: 모든 단계 예외 시 허용. 오탐 방지 우선
- **LLM 프롬프트 안전성**: 사용자 입력을 LLM 프롬프트에 포함하므로 프롬프트 인젝션 가능성 있음. 단, L1~L3가 먼저 실행되어 기본적인 인코딩/패턴 공격은 차단된 상태
- **LLM 응답 파싱**: ALLOW/BLOCK 이외 응답은 허용으로 처리 (오탐 방지)
- **비용 관리**: NLI 선필터가 명확한 비위반을 걸러내어 LLM 호출 횟수 최소화
- **타임아웃**: LLM 호출에 타임아웃 설정 (초과 시 fail-open)

## 8. 사전 빌드 파이프라인 (별도 스크립트)

L4Layer의 check() 범위 밖이지만 참고:

```
policies/*.pdf
    → pymupdf/pdfplumber로 텍스트 추출
    → markdown 변환
    → 고정 크기 or 의미 단위 청킹
    → sentence-transformers로 임베딩
    → ChromaDB에 저장 (metadata: policy_name, page, category)
```

이 스크립트는 `core-secure-layer/scripts/build_policy_db.py` 등으로 별도 작업.

## 9. 향후 확장

- 사전 빌드 스크립트 구현 (`build_policy_db.py`)
- 정책 카테고리별 임계값 차등 설정
- BM25 하이브리드 검색 (벡터 + 키워드)
- NLI 결과를 LayerContext annotations에 기록
- LLM 판단 캐싱 (동일 입력+정책 조합은 재판단 스킵)
- 정책 DB 버전 관리 및 핫스왑
- 멀티턴 대화 컨텍스트 반영
