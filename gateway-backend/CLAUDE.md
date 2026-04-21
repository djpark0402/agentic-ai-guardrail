# gateway-backend

## 개발 환경 (uv 사용)

| 명령 | 설명 |
|------|------|
| `uv sync` | 의존성 설치 |
| `uv run pytest` | 전체 테스트 실행 |
| `uv run pytest tests/path/test_x.py -v` | 단일 파일 테스트 |
| `uv run ruff check .` | 린트 검사 |
| `uv run ruff format .` | 코드 포맷 |
| `uv run uvicorn app.main:app --reload --port 8000` | 개발 서버 실행 |

## TDD 워크플로우 (필수)

1. **RED**: 실패하는 테스트 작성
2. **GREEN**: 테스트를 통과하는 최소 구현
3. **REFACTOR**: 중복 제거, 명확성 개선
4. **COMMIT**: 하나의 논리적 단위로 커밋

> ⚠️ 커밋 전 `ruff check` + `pytest`가 자동으로 실행되어 통과해야 커밋됩니다.

## 코딩 스타일
- **Docstring**: Google 스타일 (`convention = "google"`)
- **라인 길이**: 80자
- **타입 힌트**: 모든 함수 시그니처에 필수
- **에러 처리**: 모든 예외를 명시적으로 처리

## 커밋 고려하기
- 코드 리뷰에 적절한 단위를 고려하여, 커밋의 크기를 지정할 것
- 요청한 사항에 대해 커밋을 진행하며 작업할 것

### Google 스타일 docstring 예시

```python
def fetch_guardrail_result(prompt: str, model: str) -> dict[str, Any]:
    """Upstage AI에 보안 검증 요청을 보내고 결과를 반환한다.

    Args:
        prompt: 검증할 사용자 입력 텍스트.
        model: 사용할 Upstage 모델 이름.

    Returns:
        guardrail 검증 결과를 담은 딕셔너리.

    Raises:
        httpx.HTTPStatusError: API 호출 실패 시.
    """
```

## 커밋 규칙
- 포맷: `feat: 한글 메시지` — 타입 구분자(`feat:`, `fix:` 등)를 제외한 본문은 **반드시 한글**로 작성
- 타입: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`
- 크기: **하나의 커밋 = 하나의 논리적 변경 단위**
  - 구조적 변경(리네임, 추출)과 동작 변경(기능 추가)을 **반드시 분리**
  - 테스트와 구현을 함께 커밋 (TDD 사이클 완료 단위)

## 주석 규칙
- 코드 주석(인라인 `#` 주석, docstring 설명 문장 등)은 **가능한 한 한글**로 작성한다.
- Google 스타일 docstring의 섹션 키워드(`Args:`, `Returns:`, `Raises:`)는 영문 그대로 유지한다.

## Environment Variables
- **DO NOT** read or modify `.env` files directly.
- Refer to `.env.example` for the required environment variable structure.
- If a new environment variable is needed, add it to `.env.example` first.
