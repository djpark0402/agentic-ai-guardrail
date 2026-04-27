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

1단계를 통과한 입력에 대해 로컬 NER 모델로 개체명 인식을 수행한다. **판정 로직은 모델 폴더 내 `pii_labels.json` 에서 정의**하며, L5Layer 코드는 JSON 스펙을 해석해 차단/허용을 결정한다. 모델 학습 방식에 따라 서로 다른 어댑터(§2.3) 가 모델을 로드·추론하지만, 판정 알고리즘과 JSON 스펙은 공통이다.

#### `pii_labels.json` 스펙

모델 폴더(`model/<모델명>/pii_labels.json`)에 다음 필드를 기술한다:

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `adapter` | `str` | X (기본 `"hf-pipeline"`) | NER 어댑터 선택. `"hf-pipeline"` (`transformers.pipeline("ner", ...)`, 자연 텍스트 입력), `"hf-charlevel"` (글자 리스트 + `[SP]` 토큰 입력, `is_split_into_words=True` 로 학습된 모델용), `"gliner"` (zero-shot NER, 추론 시 라벨 동적 전달) |
| `label_map` | `dict[str, str]` | O | 모델 원본 라벨(B-/I- 접두사 제거 후) → 정규화된 PII 타입명. 예: `{"이름": "person", "PS": "person"}` |
| `inference_labels` | `list[str]` | GLiNER 에서 O | GLiNER 어댑터 전용. 추론 시 `predict_entities(labels=...)` 로 전달할 엔티티 타입 문자열 목록. **문맥 기반 탐지가 필수적인 라벨 약 10개로 제한 권장** (모델 `max_types` 안에 들어가야 청크 분할 부작용을 피할 수 있음). 예: `["사람 이름", "주소", "기관명"]`. HF/charlevel 어댑터에서는 무시 |
| `block_singletons` | `list[str]` | O | 단일 감지만으로 차단할 PII 타입명 목록. 예: `["phone_number", "resident_id"]` |
| `block_combinations` | `list[list[str]]` | O | 조합 차단 규칙. 각 내부 리스트의 모든 타입이 동시에 감지되면 차단. 예: `[["person", "location"]]`. 조합을 쓰지 않으면 `[]` |
| `min_score` | `float` | X (기본 `0.0`) | 엔티티 신뢰도 임계값. 이 값 미만은 무시. GLiNER 어댑터에선 `category_thresholds` 의 fallback 으로 쓰임 |
| `aggregation_strategy` | `str` | X (기본 `"simple"`) | `hf-pipeline` 어댑터 전용. `transformers.pipeline("ner", aggregation_strategy=...)` 에 그대로 전달. `hf-charlevel`/`gliner` 에서는 무시 |
| `max_length` | `int` | X (기본 `256`) | `hf-charlevel` / `gliner` 슬라이딩 윈도우용. 모델의 입력 토큰 수 상한. 학습 시 사용한 값과 일치시켜야 한다 |
| `category_thresholds` | `dict[str, float]` | X | GLiNER 전용 — 정규화 PII 타입별 차등 임계값 (예: `{"person": 0.65, "credit_rating": 0.85}`). 라벨이 누락되면 `default_threshold` 적용 |
| `default_threshold` | `float` | X (기본 `0.75`) | GLiNER 전용 — `category_thresholds` 에 없는 라벨의 기본 cut |
| `pre_threshold` | `float` | X (기본 `0.4`) | GLiNER 전용 — 1차 단계 임계값. `predict_entities(threshold=pre_threshold)` 로 후보를 넓게 받고, 코드에서 `category_thresholds` 로 2차 cut |
| `words_splitter` | `str` | X | GLiNER 전용 — 모델의 `data_processor.words_splitter` 를 추론 시 교체 (예: `"mecab"`). 학습 데이터가 형태소 분할로 전처리됐는데 `gliner_config.json` 에는 `whitespace` 만 남아있는 경우 사용 |
| `text_window_max_len` | `int` | X (기본 `max_length` 사용) | GLiNER 전용 — 슬라이딩 윈도우의 토큰 수 상한 |
| `text_window_overlap` | `int` | X (기본 `64`) | GLiNER 전용 — 슬라이딩 윈도우의 겹침 토큰 수 (경계 엔티티 누락 방지) |

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
  "min_score": 0.7,
  "aggregation_strategy": "simple"
}
```
→ 특화 모델이라 "감지된 엔티티 = PII" 이므로 전부 singleton 차단. 기본 임계값은 CLAUDE.md "오탐 절대 불허" 원칙에 맞춰 `0.7` 로 설정하며, "감지된 모든 엔티티 즉시 차단" 이 필요한 프로젝트는 `L5Layer(model_name="ner-ko", min_score=0.0)` 으로 생성자에서 override 한다.

**JSON 예시 2 — 범용 NER 모델 (가상, HF):**
```json
{
  "adapter": "hf-pipeline",
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

**JSON 예시 3 — 글자 단위 학습 PII 모델 (`pii_model_v11`):**
```json
{
  "adapter": "hf-charlevel",
  "label_map": {
    "PS": "person",
    "PHONE": "phone_number",
    "EMAIL": "email",
    "RRN": "resident_id",
    "ADDR": "address"
  },
  "block_singletons": [
    "person", "phone_number", "email", "resident_id", "address"
  ],
  "block_combinations": [],
  "min_score": 0.7,
  "max_length": 256
}
```
→ 입력을 글자 리스트로 쪼개고 공백을 `[SP]` 로 치환한 뒤 `is_split_into_words=True` 로 추론. KoELECTRA-Base-v3 + KLUE-NER 스타일로 학습된 모델 (`pii_model_v11` 같은) 이 학습 분포 그대로 동작하도록 함.

**JSON 예시 4 — Zero-shot GLiNER 모델 (`gliner_korean_pii` 같은):**
```json
{
  "adapter": "gliner",
  "words_splitter": "mecab",
  "max_length": 256,
  "inference_labels": [
    "사람 이름", "기관명", "주소", "위치명", "직업명",
    "거래내역", "대출정보", "신용등급", "재산및소득정보", "IT시스템정보"
  ],
  "label_map": {
    "사람 이름": "person",
    "기관명": "organization",
    "주소": "address",
    "위치명": "location",
    "직업명": "job_title",
    "거래내역": "transaction",
    "대출정보": "loan",
    "신용등급": "credit_rating",
    "재산및소득정보": "income_property",
    "IT시스템정보": "it_system"
  },
  "category_thresholds": {
    "person": 0.65,
    "organization": 0.70,
    "address": 0.70,
    "location": 0.75,
    "job_title": 0.80,
    "transaction": 0.80,
    "loan": 0.80,
    "credit_rating": 0.85,
    "income_property": 0.80,
    "it_system": 0.80
  },
  "default_threshold": 0.75,
  "pre_threshold": 0.4,
  "block_singletons": [
    "person", "address", "location", "transaction", "loan",
    "credit_rating", "income_property", "it_system"
  ],
  "block_combinations": [],
  "min_score": 0.0,
  "text_window_max_len": 256,
  "text_window_overlap": 64
}
```
→ **inference_labels 은 문맥 기반 탐지가 필수적인 약 10개로 제한** (정형 PII 인 전화/이메일/주민번호 등은 Regex 1단계에서 처리). 학습 데이터가 MeCab 형태소 분할이면 `words_splitter: "mecab"`. 라벨별로 학습 강도가 다르므로 `category_thresholds` 로 차등 cut. 긴 텍스트는 `text_window_max_len` + `overlap` 슬라이딩 윈도우로 정확도 보존.

#### 판정 알고리즘 (어댑터 공통)
1. 어댑터의 `predict(text)` 호출 → 정규화된 엔티티 리스트 획득
   - 각 엔티티는 `{"entity": str, "word": str, "start": int, "score": float}` 형식 (§2.3 정규화 계약 참조)
2. `min_score` 미만 엔티티 제거
3. 각 엔티티의 `entity` 필드에서 B-/I- 접두사 제거 → `label_map` 으로 정규화 타입 획득 (맵에 없으면 무시)
4. 정규화 타입 집합에 대해:
   - `block_singletons` 중 하나라도 포함되면 차단
   - `block_combinations` 중 하나라도 전부 포함되면 차단
   - 그 외엔 허용

### 2.3 NER 어댑터

모델 학습 방식별 로딩·추론 차이를 어댑터 클래스로 캡슐화한다. L5Layer 코어 로직은 어댑터의 `predict(text)` 만 호출하며, 반환 포맷은 HF 스타일 `{entity, word, start, score}` 로 통일된다.

| 어댑터 | 선택 방법 | 로더 | 추론 | 출력 정규화 |
|---|---|---|---|---|
| `_HFPipelineAdapter` | `adapter = "hf-pipeline"` (기본) | `transformers.pipeline("ner", model=path, tokenizer=path, aggregation_strategy=...)` | `pipe(text)` | 원본 그대로 — `{entity_group, word, start, end, score}` 의 `entity_group` 을 `entity` 로 노출 |
| `_HFCharLevelAdapter` | `adapter = "hf-charlevel"` | `AutoTokenizer.from_pretrained(path) + add_tokens(["[SP]"])`, `AutoModelForTokenClassification.from_pretrained(path) + resize_token_embeddings(...)` | 텍스트 → 글자 리스트 + `[SP]` 치환 → 문장 단위 청크 분할 → 각 청크에 `model(**inputs)` 직접 호출 → `word_ids` 로 글자별 라벨 매핑 → BIO 디코딩 → 엔티티 스팬 | 글자 스팬을 `{entity, word, start, score}` 로 변환 |
| `_GLinerAdapter` | `adapter = "gliner"` | `gliner.GLiNER.from_pretrained(path)` + DeBERTa 호환 layer + (선택) `data_processor.words_splitter` 교체 | 텍스트 → 슬라이딩 윈도우 분할 → 각 윈도우에 `predict_entities(text, labels=inference_labels[:max_types], threshold=pre_threshold)` 호출 → 카테고리별 차등 cut 적용 → 후처리 오탐 필터 → 윈도우 결과 합치고 `(start, end)` span dedup | 정규화: `{entity, word, start, end, score}` |

#### 어댑터 공통 계약
- **생성자**: `(model_path: Path, spec: dict[str, Any])` — 로드는 이 시점에 수행하고, 실패 시 예외 발생
- **`predict(text: str) -> list[dict[str, Any]]`** — 위 정규화 포맷으로 엔티티 반환
- **예외 전파 금지** — L5Layer 가 `_check_ner` 에서 `try/except` 로 한 번만 fail-open 처리

#### `_HFCharLevelAdapter` 세부
- **글자 단위 입력**: `["[SP]" if ch == " " else ch for ch in text]`
- **`[SP]` 토큰 처리**: 토크나이저 vocab 에 `[SP]` 가 없으면 `add_tokens` 로 추가 후 모델 임베딩 테이블 확장
- **문장 단위 청크**: `_CHUNK_SIZE` 이하로 문장 부호(`. ! ? \n` 등) 기준 분할. 단일 문장이 한도를 넘으면 강제 분할
- **추론**: 각 청크를 `tokenizer(chars, is_split_into_words=True, truncation=True, max_length=...)` 로 토큰화 → `model(**inputs)` 직접 호출 → softmax → argmax → `word_ids` 로 글자 라벨 추출
- **공백 브릿지 후처리**: `[SP]` 위치 라벨이 `O` 인데 양쪽 라벨이 동일 엔티티 타입이면 `I-{type}` 으로 보정 (학습 시 [SP] 가 가끔 O로 예측되는 경향 보완)
- **BIO 디코딩**: 글자 라벨 시퀀스에서 `B-/I-` 연속 구간을 모아 엔티티 스팬 추출
- **출력 변환**: 각 엔티티에 `{"entity": type, "word": text[start:end], "start": start, "score": min_in_span}` 형식으로 정규화

#### `_GLinerAdapter` 세부 (`korean_pii.detection.HybridPIIDetector` 패턴 차용)
- **GLiNER 라벨 제한**: `inference_labels` 는 **문맥 필요 라벨 약 10개로 제한 권장**. 정형 PII 인 전화/이메일/주민번호 등은 Regex 1단계가 처리하므로 GLiNER 에 보내지 않는다. 모델의 `gliner_config.json` 의 `max_types` (보통 10) 를 초과하면 청크 분할로 폴백하지만, 청크 간 다중 매칭 노이즈 위험이 있어 권장은 단일 호출
- **DeBERTa-v3 tokenizer 호환 레이어**: `BaseGLiNER._load_tokenizer` 를 런타임 교체해 `PreTrainedTokenizerFast` 로 우회 로드 (`team-lucid/deberta-v3-base-korean` 같은 WordPiece 기반 tokenizer.json 모델 지원)
- **`words_splitter` override**: `pii_labels.json` 의 `words_splitter` 가 있으면 모델 로드 후 `data_processor.words_splitter` 를 그 splitter (예: `"mecab"`) 로 교체. 학습 데이터 전처리(MeCab 형태소 분할 등) 와 추론 단어 경계 일치
- **이중 단계 임계값**: 1차 GLiNER `predict_entities(threshold=pre_threshold)` 로 후보 폭넓게 수집(기본 0.4) → 2차 코드 단계에서 `category_thresholds.get(label, default_threshold)` 로 라벨별 cut. 라벨별 학습 강도 차이를 흡수하여 PERSON(0.65) 미탐 방지 + CREDIT_RATING(0.85) 오탐 방지를 동시에 달성
- **슬라이딩 윈도우 텍스트 청크**: 입력 텍스트를 `text_window_max_len` 토큰 + `text_window_overlap` 토큰 겹침으로 분할 후 각 윈도우 추론. 경계 엔티티 누락을 overlap 으로 보완. `model.config.max_len` (또는 `max_length`) 안에 들어가도록 보장
- **윈도우 결과 합치기**: 각 윈도우 엔티티들을 합친 뒤 `(start, end)` 동일 span 은 score 가 가장 높은 라벨 1개만 유지(span dedup)
- **후처리 오탐 필터**: 라벨별 한국어 특화 정규식 필터로 명백한 오탐 제거
  - `PERSON`: 1글자 / 숫자시작 / `~실/관/동/층/호` 끝 / `~에서` 등 조사 끝 / 직함(박사, 이사) / 조직접미사(주식회사) / 일반명사(기술/기관) → 거름. 또한 조사/어미가 뒤에 붙은 경우 `정하은이지` → `정하은` 으로 자동 trim
  - `ORGANIZATION`: 일반명사("회사/팀/조직"), 단독 은행명("우리/하나/국민"), 1글자 거름
  - `ADDRESS`: 단독 지명("서울"만) 거름 — 최소 2개 요소 필요
  - `JOB_TITLE`: 1글자 / 조사 붙음 / 괄호·따옴표 포함 거름
  - 공통: 특수문자/공백만 / 라벨별 최소 길이 (`PERSON ≥2`, `ADDRESS ≥5`, `ORGANIZATION ≥2`) 거름
- **출력 정규화**: 각 엔티티 `{"entity": label_map[label], "word": text[start:end], "start": start, "end": end, "score": score}` 로 변환

### 2.4 `pii_labels.json` 부재 시 폴백 (관대 폴백)

모델 폴더에 `pii_labels.json` 이 **없으면**:
- `config.json` 의 `id2label` 을 자동 추출해 `label_map` 으로 사용 (B-/I- 접두사 제거, 값은 원본 라벨명 그대로)
- `block_singletons = <모든 라벨>`, `block_combinations = []`, `min_score = 0.0`, `aggregation_strategy = "simple"`
- 단, 생성자 `min_score` 가 주어졌다면 그 값이 `0.0` 대신 쓰인다 (§3 참조)
- 즉 "엔티티 하나라도 감지되면 차단" — 현재 동작과 동일
- 로드 시점에 `logger.warning("pii_labels.json 없음, 폴백 동작 — 범용 NER 모델은 오탐 위험이 큼: %s", path)` 로 1회 경고

> ⚠️ **주의**: 이 폴백은 자연 텍스트 입력 + WordPiece subword 토큰화로 학습된 PII 특화 모델을 전제로 한다. 범용 NER(PER/LOC/ORG 등) 모델을 `pii_labels.json` 없이 드롭인하면 정상 대화의 인명·지명도 차단되어 오탐이 폭증한다. **글자 단위 + `[SP]` 로 학습된 모델 (예: `pii_model_v11`) 또는 GLiNER (zero-shot) 모델은 폴백 불가** — 어댑터가 `hf-pipeline` 로 동작해 학습 분포 밖 입력을 받게 되므로 정확도가 무너진다 (또는 GLiNER 의 경우 `inference_labels` 가 필수라 추론 자체 불가). 반드시 `pii_labels.json` 에 적절한 `adapter` 값을 명시할 것.

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
    ├── ner-ko/                    # 자연 텍스트 입력 (기본 어댑터)
    │   ├── config.json
    │   ├── model.safetensors
    │   ├── tokenizer.json
    │   ├── tokenizer_config.json
    │   └── pii_labels.json        ← adapter: "hf-pipeline" (생략 시 기본)
    ├── pii_model_v11/              # 글자 단위 + [SP] 학습
    │   ├── config.json
    │   ├── model.safetensors
    │   ├── tokenizer.json
    │   ├── tokenizer_config.json   # [SP] 가 added_tokens 에 등록돼 있음
    │   └── pii_labels.json        ← adapter: "hf-charlevel"
    └── <gliner-model>/             # GLiNER zero-shot
        ├── gliner_config.json      # max_types, words_splitter_type 등
        ├── model.safetensors
        ├── tokenizer.json
        ├── tokenizer_config.json
        └── pii_labels.json        ← adapter: "gliner" + inference_labels 필수
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
| `pii_labels.json` 미존재 | 경고 로그 + 폴백 동작 | §2.4 참조 |
| 외부 주입 패턴 매칭 | 차단 (1단계) | `extra_patterns` |
| 모델 추론 중 예외 | 허용 | fail-open |
| `min_score` 미만 엔티티 | 무시 | 낮은 신뢰도 오탐 방지 |

## 7. 보안 고려

- **fail-open**: NER 모델 미로드, 추론 예외 시 허용. 1단계(Regex)는 모델 없이도 동작
- **fail-open 의 범위**: `pii_labels.json` JSON 파싱 실패 시에도 폴백이 아닌 **NER 비활성화(fail-open)** 으로 처리 — 잘못된 JSON 으로 의도치 않은 차단 규칙이 돌아가는 위험 회피
- **Regex 안전성**: 외부 주입 정규식의 ReDoS 방지를 위해 타임아웃 또는 패턴 길이 제한 고려
- **PII 원문 비노출**: `reason` 에 탐지 타입+위치만 포함, 원문은 노출하지 않음
- **관대 폴백의 리스크**: §2.4 경고 참조 — 범용 NER 드롭인은 오탐 유발, 반드시 `pii_labels.json` 동반 작성. 글자 단위 학습 모델은 폴백 불가 (반드시 `adapter: "hf-charlevel"` 명시)
- **어댑터 필드 신뢰**: `pii_labels.json` 의 `adapter` 필드는 모델 폴더 배치자가 정하는 값으로 설계상 신뢰 대상. 잘못된 값이면 어댑터 로드가 예외로 실패해 fail-open

## 8. 의존성

- **선행 레이어**: L1~L4
- **외부 라이브러리**:
  - `transformers` + `torch` — HF (`hf-pipeline`, `hf-charlevel`) 어댑터용
  - `gliner` + `sentencepiece` + `python-mecab-ko` — GLiNER 어댑터용 (시스템 `mecab-ko` 라이브러리 필요, brew 등으로 설치)
- **LangChain**: 사용 안 함

## 9. 향후 확장

- PII 마스킹(anonymization) 옵션 — 차단 대신 `***` 치환 통과
- `pii_labels.json` 스키마 검증 (pydantic 모델)
- Regex 패턴도 모델 폴더 밖 외부 설정으로 분리
- 차단 단어 화이트리스트 (예: "비밀번호 변경" 같은 문맥은 허용)
- NER 결과를 `LayerContext.annotations` 에 기록

## 10. 모델 추가 가이드

새 NER 모델을 L5 에 추가하려면 모델의 학습 방식에 따라 세 경로 중 하나를 따른다.

### 10.1 자연 텍스트 입력 모델 (`adapter: "hf-pipeline"`, 기본)

WordPiece subword 토큰화로 자연 텍스트를 그대로 입력받아 학습된 일반 HF 토큰 분류 모델 (예: `ner-ko`).

1. `l5/model/<새모델명>/` 폴더 생성, HuggingFace 포맷(`config.json`, `model.safetensors`, `tokenizer.json`, `tokenizer_config.json`) 배치
2. 해당 모델의 라벨 스키마를 확인 (`config.json` 의 `id2label` 또는 모델 카드)
3. 라벨별로 PII 성격을 판단해 `pii_labels.json` 작성:
   - 정형 PII 라벨(전화번호, 주민번호 등) → `block_singletons` 에 추가
   - 조합이어야 의미 있는 라벨(인명+지명 등) → `block_combinations` 에 추가
   - 오탐 위험이 높은 라벨(기관명 등) → 양쪽 모두에서 제외
4. `min_score` 는 "오탐 절대 불허" 원칙에 맞춰 **기본 `0.7` 이상** 권장. JSON 필드를 생략하면 코드 기본값 `0.0` 이 적용되지만 실제 배포 모델에서는 반드시 명시할 것. 프로젝트별로 감도가 다르면 `L5Layer(..., min_score=...)` 로 생성자 override
5. `L5Layer(model_name="<새모델명>")` 로 초기화해 통합 테스트 (`scripts/smoke_l5_model.py` 활용)

### 10.2 글자 단위 + `[SP]` 학습 모델 (`adapter: "hf-charlevel"`)

KoELECTRA-Base-v3 + KLUE-NER 스타일로 글자 리스트 + `[SP]` 토큰 + `is_split_into_words=True` 로 학습된 PII 모델 (예: `pii_model_v11`).

1. `l5/model/<새모델명>/` 폴더 생성, HF 포맷 배치
2. `tokenizer_config.json` 의 `added_tokens` 에 `[SP]` 가 포함돼 있는지 확인 (학습 시 추가됐을 것). 없으면 어댑터가 추론 시점에 `add_tokens` 로 추가하고 모델 임베딩을 확장
3. `pii_labels.json` 에 다음 필드 명시:
   - `"adapter": "hf-charlevel"` (필수)
   - `label_map`, `block_singletons`, `block_combinations`, `min_score`
   - `"max_length": 256` (학습 시 사용한 값)
4. 학습 시 사용한 데이터 전처리(예: 공백 → `[SP]`) 와 동일하게 어댑터가 추론 입력을 변환하므로 추가 작업 불필요
5. `aggregation_strategy` 는 charlevel 에서 의미 없으므로 생략

### 10.3 GLiNER (zero-shot) 모델 (`adapter: "gliner"`)

`gliner.GLiNER.from_pretrained` 로 로드되는 zero-shot NER 모델 (예: `gliner_korean_pii`). 추론 시점에 라벨을 동적으로 전달하므로 모델 가중치 재학습 없이 새 PII 타입 추가 가능.

1. `l5/model/<새모델명>/` 폴더 생성, GLiNER 포맷(`gliner_config.json`, `model.safetensors`, `tokenizer.json`, `tokenizer_config.json`) 배치 — 학습 아티팩트(`optimizer.pt` 등) 는 추론에 불필요하니 제거 권장
2. `pii_labels.json` 에 다음 필드 명시:
   - `"adapter": "gliner"` (필수)
   - `"inference_labels"` — 학습 시 사용한 라벨 텍스트로 정확히 일치 (예: `["사람 이름", "주소", "기관명"]`). **약 10개로 제한 권장** (정형 PII 는 Regex 1단계가 처리)
   - `label_map` — `inference_labels` 의 각 라벨을 정규화 PII 타입으로 매핑
   - `category_thresholds` — 라벨별 학습 강도 차이 보정. PERSON (0.65) 처럼 잘 학습된 라벨은 낮게, CREDIT_RATING (0.85) 처럼 약한 라벨은 높게
   - `default_threshold` (기본 0.75) — 위에 없는 라벨용
   - `pre_threshold` (기본 0.4) — GLiNER 1차 cut
   - `block_singletons`, `block_combinations`
   - `words_splitter` (선택, 학습이 MeCab 형태소 분할이면 `"mecab"`)
   - `text_window_max_len` (기본 256), `text_window_overlap` (기본 64)
   - `max_length` 은 모델 `max_len` 과 일치
3. `min_score` 는 GLiNER 어댑터에선 보조 임계값(category_thresholds 의 fallback) — 일반적으로 `0.0` 으로 두고 라벨별 cut 으로 제어
4. 모델이 실제로 탐지 가능한 라벨인지 먼저 확인: `scripts/smoke_l5_model.py --model <새모델명>` 으로 표본 문장의 원시 엔티티 출력을 보고 `inference_labels` 와 `category_thresholds` 조정
5. 품질이 충분히 검증된 모델만 실제 배포에 사용 — 학습 덜 된 체크포인트는 fallback 라벨로 노이즈 매칭이 커지므로 후처리 필터에 의존
