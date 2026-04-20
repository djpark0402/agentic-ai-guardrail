# L1: Encoding Detection & Normalization

## 1. 목적

사용자 입력에 포함된 인코딩/난독화 페이로드(Base64, Hex escape, Unicode escape, HTML entity, URL percent) 및 투명/제어 문자 조작을 탐지하여 차단한다. 공격자가 후속 레이어의 텍스트 기반 검사를 우회하기 위해 페이로드를 인코딩하거나 비가시 문자를 끼워 넣는 것을 방지하는 **첫 번째 방어선**.

## 판정 원칙

> **미탐(false negative)은 허용, 오탐(false positive)은 절대 불허.**
>
> 인코딩을 못 찾아서 통과시키는 것은 허용한다 — 후속 레이어에서 잡을 수 있다.
> 정상 문장을 차단하는 것은 절대 안 된다.

이 원칙은 모든 탐지 기준의 최우선 필터다. 애매하면 허용한다. 정규식 매치만으로는 차단하지 않고 **실제 디코딩 시도 + 결과 검증**까지 통과해야 차단한다.

## 2. 판정 기준

입력은 두 단계로 검사한다. 0단계에서 투명/제어 문자를 제거·정규화하고 그 비율이 과도하면 차단. 1단계는 0단계 결과(cleaned)에 대해 5개 인코딩 패턴을 정규식 매치 + 실제 디코딩 성공 여부로 확인한다.

### 2.0 전처리 (0단계)

`preprocess_text(text) -> (cleaned, should_block, detail)`

1. `_INVISIBLE_RE` 로 알려진 invisible / bidi / zero-width 문자 제거
   - `\u200b-\u200f` (ZWSP, ZWNJ, ZWJ, LRM, RLM)
   - `\u202a-\u202e` (방향 제어)
   - `\u2060-\u2069` (word joiner, invisible separators)
   - `\u00ad` (soft hyphen), `\ufeff` (BOM/ZWNBSP), `\u034f` (CGJ), `\u061c` (ALM)
   - `\u115f`, `\u1160`, `\u3164`, `\uffa0` (Hangul/halfwidth filler)
2. Unicode 카테고리 `{Cf, Mn, Me}` 에 속하는 모든 문자 제거
3. 결과에 `unicodedata.normalize('NFKC', …)` 적용
4. 제거 비율 `removed / original_len > 10%` 이면 **차단** (encoding_type `invisible`)
5. 아니면 `cleaned` 를 1단계로 넘긴다

**c1 결정에 따른 주의**: 카테고리 `Mn`(Mark, Nonspacing) 에는 일부 다국어 결합 문자가 포함되어 과도 제거 가능성이 있다. 단, 비율 10% 이내면 차단으로 이어지지 않으므로 실질 오탐은 제한적이다.

### 2.1 정규식 + 디코딩 5종 (1단계)

각 탐지기는 다음 3단계를 **모두** 만족할 때만 차단:
1. 인코딩 특성 정규식과 매치
2. 해당 포맷으로 실제 디코딩 성공
3. 디코딩 결과가 의미 있는 값(변화 발생, UTF-8 유효, 출력 가능 등)

#### Base64

- 정규식: `_BASE64_RE = r'^[A-Za-z0-9+/]{4,}={0,2}$'` (전체 매치)
- 추가 조건: `text.strip()` 후 길이 ≥ 8
- 디코딩: `base64.b64decode(clean)` → `decode('utf-8')` 성공 + (`isprintable()` **또는** 한글 포함 `\uAC00-\uD7A3`)
- 근거:
  - 전체 매치라 문장 중간 토큰이 우연히 걸리지 않음
  - `len >= 8` 로 `"Hello"`, `"test"` 등 짧은 단어 자동 제외
  - UTF-8 디코드 + isprintable/한글 검증으로 `"password"` 같은 영단어가 만드는 바이너리 쓰레기 제외

#### Hex escape (`\xXX`)

- 정규식: `_HEX_ESCAPE_RE = r'(\\x[0-9a-fA-F]{2}){3,}'` (3회 이상 연속)
- 디코딩: `codecs.decode(text, 'unicode_escape')` → 결과가 원본과 다름
- 근거: 3회 연속이 자연어에서 우연히 나오기 어려움

#### Unicode escape (`\uXXXX`)

- 정규식: `_UNICODE_ESCAPE_RE = r'(\\u[0-9a-fA-F]{4}){3,}'` (3회 이상 연속)
- 디코딩: `codecs.decode(text, 'unicode_escape')` → 결과가 원본과 다름 + `isprintable()`

#### HTML entity (`&#...;` / `&#x...;`)

- 정규식: `_HTML_ENTITY_RE = r'(&#x?[0-9a-fA-F]+;){3,}'` (3회 이상 연속)
- 디코딩: `html.unescape(text)` → 결과가 원본과 다름

#### URL percent (`%XX`)

- 정규식: `_URL_PERCENT_RE = r'(%[0-9a-fA-F]{2}){2,}'` (2회 이상 연속)
- 디코딩: `urllib.parse.unquote(text)` → 결과가 원본과 다름
- 근거: 단일 `%XX` 는 정상 문장(예: `"100%"`, `"top 5%AC"`)에서 가능. 2회 이상 연속이어야 공격으로 간주.

### 2.2 탐지 순서

`Base64 → Hex escape → Unicode escape → HTML entity → URL percent`. 첫 번째로 차단 조건을 만족시키는 탐지기가 결과를 결정한다 (첫 매치 기준).

### 2.3 탐지하지 않는 것 (현재 범위 밖)

- `\UXXXXXXXX` (Python 32비트 Unicode)
- 중첩(이중) 인코딩 — 1단계 디코딩만 수행
- Raw hex 문자열 (예: `68656c6c6f`)
- 공백 삽입된 Base64 (`"S G V s b G 8="` 등)
- Invisible 문자 비율 ≤ 10% 의 자잘한 주입 (미탐 허용)

## 3. 입력/출력

### 입력: `GuardrailRequest`

| 필드 | 사용 여부 | 용도 |
|------|-----------|------|
| `user_input` | O | 전처리 + 디코딩 시도 대상 |
| `session_id` | X | 사용 안 함 |
| `metadata` | X | 사용 안 함 |

### 출력: `LayerResult`

**허용 시:**
```python
LayerResult(
    name="L1",
    allowed=True,
    confidence=1.0,
    severity=Severity.NONE,
)
```

**차단 시:**
```python
LayerResult(
    name="L1",
    allowed=False,
    reason="base64 encoding detected at position 15",
    confidence=0.0,
    severity=Severity.HIGH,
    tags=["encoding", "base64"],
)
```

- `reason`: `"{encoding_type} encoding detected at position {N}"` 포맷 유지
- `encoding_type` ∈ { `base64`, `hex`, `unicode`, `html`, `url`, `invisible` }
- `severity`: `HIGH`
- `tags`: `["encoding", "{encoding_type}"]`

### 전처리 결과 처리 (b1 결정)

전처리로 생성된 `cleaned` 는 L1 내부에서만 사용하며, `GuardrailRequest` / 후속 레이어로 전달하지 않는다. L1 은 원본 입력에 차단 판정만 내리며, 후속 레이어는 `user_input` 원본을 그대로 받는다.

### 복수 인코딩 감지 시

첫 매치 기준 차단. reason 에는 첫 번째 결과만 보고.

## 4. 엣지 케이스

| 케이스 | 판정 | 이유 |
|--------|------|------|
| 빈 문자열 `""` | 허용 | 검사 대상 없음 |
| `"Hello world"` | 허용 | 공백 포함 → Base64 전체 매치 실패, 다른 패턴도 없음 |
| `"Hello"` | 허용 | 5자 < 8 → Base64 컷 |
| `"password"` | 허용 | regex 매치하나 b64decode → UTF-8 decode 실패 |
| `"DatabaseEngine"` | 허용 | decode 결과 바이너리 쓰레기 |
| `"SGVsbG8gV29ybGQ="` | 차단 | decode → `"Hello World"` isprintable ✅ |
| `"안녕하세요2025ABCDEF=="` | 차단 가능 | decode 결과에 한글 포함 시 isprintable 대신 한글 조건 통과 |
| `"100%"` | 허용 | 단일 %XX → 2회 미만 |
| `"50%2F50"` | 허용 | 단일 %XX → 미탐 허용 (판정 원칙) |
| `"%20%20%20"` | 차단 | `%XX` 3회 → unquote 변화 |
| `"hello\x3C"` | 허용 | 1회 hex → {3,} 매치 실패 |
| `"\x3C\x73\x63"` | 차단 | 3회 연속 + codecs.decode 변화 |
| `"\u0041\u0042\u0043"` | 차단 | 3회 연속 + decode → `"ABC"` isprintable ✅ |
| `"&#65;&#66;&#67;"` | 차단 | 3회 연속 + html.unescape → `"ABC"` |
| `"Hello\u200bWorld"` (1 ZWSP) | 허용 | 제거 후 비율 약 9% → 10% 이내 |
| `"\u200b" * 10 + "hi"` | 차단 | 제거 비율 ~83% > 10% (invisible) |
| 매우 긴 입력 | 정상 동작 | O(n) |
| 예외 발생 | 허용 | fail-open |

## 5. 보안 고려

- **fail-open**: 예외 발생 시 허용. 판단 불가 상태에서 오탐을 만들지 않는다.
- **디코딩 안전성**: `base64.b64decode` / `codecs.decode(..., 'unicode_escape')` / `html.unescape` / `urllib.parse.unquote` 모두 예외를 던지거나 원본을 반환. 별도 `try/except` 로 감싸 폭발 방지.
- **성능**: 정규식 검사 O(n), 디코딩 후보 수가 제한적이라 추가 비용 미미.
- **우회 가능성 (미탐 허용)**:
  - 공백 삽입된 Base64, 패딩 없는 Base64, 16자 미만 단독 Base64 페이로드
  - 단일 `%XX` URL 인코딩
  - 2회 이하 연속 hex/unicode/html escape
  - 투명 문자 비율 10% 이하 주입
- **방어적 기본값**: 판단 불가 시 허용.
- **판정 원칙 예외 검토**: 정규식 매치 + 디코드 검증 조합이 기존 "UTF-8 디코드 필수" 로직과 실질 등가이므로, a1 선택으로 인한 오탐 리스크는 이 구현에서 발생하지 않는다. `Mn` 카테고리 제거로 발생할 수 있는 다국어 결합 문자 오탐도 10% 비율 문턱 덕에 단일 문자 차원에서는 차단으로 이어지지 않는다.

## 6. 의존성

- **선행 레이어**: 없음 (L1은 첫 번째 레이어)
- **Python 표준 라이브러리**: `base64`, `codecs`, `html`, `urllib.parse`, `re`, `unicodedata`
- **외부 라이브러리**: 없음
- **LangChain**: 사용 안 함

## 7. 향후 확장

- 중첩 인코딩 탐지 (2단계+)
- Raw hex (`68656c6c6f`) 패턴 지원
- 공백/구두점 삽입된 분산 인코딩 탐지
- 허용 목록(allowlist) — 특정 패턴은 정상으로 간주
- `data:` URI scheme 전용 탐지 강화
- Invisible 문자 10% 임계값을 카테고리별로 세분화
- 탐지 결과를 `context.annotations` 에 기록 (LayerContext 도입 시)
