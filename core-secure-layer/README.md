# core-secure-layer

Agentic AI Guardrail의 핵심 보안 계층 모듈.

## 요구사항

- Python **3.14+**
- [uv](https://docs.astral.sh/uv/) (패키지/환경 관리)

## 빠른 시작

```bash
cd core-secure-layer

# Python 3.14 자동 설치 + 가상환경 생성 + 의존성 설치
uv sync

# 개발 의존성까지 설치
uv sync --group dev

# 테스트 실행
uv run pytest
```

## 디렉토리 구조

```
core-secure-layer/
├── core_secure_layer/    # 모듈 패키지 (구현 코드)
│   └── __init__.py
├── tests/                # pytest 테스트
│   ├── __init__.py
│   └── conftest.py
├── pyproject.toml        # 프로젝트 메타데이터 및 의존성
├── .python-version       # uv용 Python 버전 핀
├── CLAUDE.md             # 이 모듈 작업 시 Claude Code 규칙
└── README.md
```

## 작업 규칙

이 모듈의 작업 규칙(TDD, 브랜치 전략, 커밋/머지 정책 등)은 [`CLAUDE.md`](./CLAUDE.md)를 참고하세요.
