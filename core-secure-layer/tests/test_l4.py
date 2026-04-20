from unittest.mock import AsyncMock, MagicMock

import pytest

from core_secure_layer.layers.l4.l4 import L4Layer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    Severity,
)

# 테스트용 기본 설정 상수
_DEFAULT_NLI_THRESHOLD = 0.7
_DEFAULT_TOP_K = 3


def _req(text):
    """주어진 텍스트로 GuardrailRequest 를 생성한다."""
    return GuardrailRequest(user_input=text)


@pytest.fixture
def layer():
    """모델/DB 미로드 상태의 L4Layer 인스턴스.

    NLI, 임베딩, reranker, ChromaDB, LLM 모두 미로드.
    fail-open 동작을 테스트할 때 사용한다.
    """
    inst = L4Layer.__new__(L4Layer)
    inst.name = "L4"
    inst.nli_threshold = _DEFAULT_NLI_THRESHOLD
    inst.top_k = _DEFAULT_TOP_K
    inst._nli_model = None
    inst._embed_model = None
    inst._reranker_model = None
    inst._collection = None
    inst._llm = None
    return inst


@pytest.fixture
def layer_nli_pass():
    """NLI 선필터에서 의심 없음(즉시 허용)을 시뮬레이션하는 fixture.

    contradiction 점수가 높으면 → 정책 위반 의심 없음 → 즉시 허용.
    _nli_predict 를 monkeypatch 하여 점수를 제어한다.
    """
    inst = L4Layer.__new__(L4Layer)
    inst.name = "L4"
    inst.nli_threshold = _DEFAULT_NLI_THRESHOLD
    inst.top_k = _DEFAULT_TOP_K
    inst._nli_model = MagicMock()
    inst._embed_model = None
    inst._reranker_model = None
    inst._collection = None
    inst._llm = None
    return inst


@pytest.fixture
def layer_full_pipeline():
    """3단계 전체 파이프라인을 mock 가능한 상태의 fixture.

    NLI가 의심 → 벡터 검색 → reranking → LLM 판단까지
    전체 흐름을 테스트할 때 사용한다.
    """
    inst = L4Layer.__new__(L4Layer)
    inst.name = "L4"
    inst.nli_threshold = _DEFAULT_NLI_THRESHOLD
    inst.top_k = _DEFAULT_TOP_K
    inst._nli_model = MagicMock()
    inst._embed_model = MagicMock()
    inst._reranker_model = MagicMock()
    inst._collection = MagicMock()
    inst._llm = AsyncMock()
    return inst


# ──────────────────────────────────────────────
# 0. 생성자 계약 검증
# ──────────────────────────────────────────────


class TestConstructorContract:
    """L4Layer 생성자가 필수 파라미터를 받는지 확인."""

    def test_accepts_all_params(self):
        # 모든 초기화 파라미터를 전달할 수 있어야 한다
        inst = L4Layer(
            nli_model_name="nli-deberta-v3",
            embed_model_name="all-MiniLM-L6-v2",
            reranker_model_name="ms-marco-MiniLM-L-6",
            llm=None,
            nli_threshold=0.7,
            top_k=3,
        )
        assert inst.name == "L4"

    def test_default_nli_threshold(self):
        # 기본 nli_threshold 는 0.7
        inst = L4Layer(
            nli_model_name="nli-deberta-v3",
            embed_model_name="all-MiniLM-L6-v2",
            reranker_model_name="ms-marco-MiniLM-L-6",
        )
        assert inst.nli_threshold == _DEFAULT_NLI_THRESHOLD

    def test_default_top_k(self):
        # 기본 top_k 는 3
        inst = L4Layer(
            nli_model_name="nli-deberta-v3",
            embed_model_name="all-MiniLM-L6-v2",
            reranker_model_name="ms-marco-MiniLM-L-6",
        )
        assert inst.top_k == _DEFAULT_TOP_K


# ──────────────────────────────────────────────
# 1. 허용 골든 패스
# ──────────────────────────────────────────────


class TestAllowedGoldenPath:
    """정상 입력이 허용되는 기본 시나리오."""

    async def test_nli_no_suspicion_allows(self, layer_nli_pass, monkeypatch):
        # NLI contradiction 점수가 임계값 초과 → 의심 없음 → 즉시 허용
        # (벡터 검색/LLM 스킵)
        monkeypatch.setattr(
            layer_nli_pass,
            "_nli_predict",
            lambda text: 0.85,
        )
        result = await layer_nli_pass.check(
            _req("오늘 날씨가 좋다"),
        )
        assert result.allowed is True
        assert result.name == "L4"
        assert result.reason is None

    async def test_llm_allow_verdict(self, layer_full_pipeline, monkeypatch):
        # NLI 의심 → 벡터 검색 → LLM이 ALLOW 판단 → 허용
        # 1단계: NLI contradiction 점수가 임계값 이하 → 의심
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.5,
        )
        # 2단계: 벡터 검색 + reranking 결과
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [
                {
                    "text": "SQL Injection Prevention",
                    "name": "SQL Injection Prevention",
                    "category": "sql_injection",
                },
            ],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_rerank",
            lambda text, chunks: chunks[0],
        )
        # 3단계: LLM이 ALLOW 판단
        monkeypatch.setattr(
            layer_full_pipeline,
            "_llm_judge",
            AsyncMock(return_value="ALLOW"),
        )
        result = await layer_full_pipeline.check(
            _req("SELECT name FROM users WHERE id = 1"),
        )
        assert result.allowed is True

    async def test_normal_english_allowed(self, layer_nli_pass, monkeypatch):
        # 영문 일반 문장도 NLI 통과 → 허용
        monkeypatch.setattr(
            layer_nli_pass,
            "_nli_predict",
            lambda text: 0.9,
        )
        result = await layer_nli_pass.check(
            _req("Hello, how are you today?"),
        )
        assert result.allowed is True


# ──────────────────────────────────────────────
# 2. 차단 골든 패스
# ──────────────────────────────────────────────


class TestBlockedGoldenPath:
    """정책 위반 입력이 차단되는 시나리오."""

    async def test_full_pipeline_block(self, layer_full_pipeline, monkeypatch):
        # NLI 의심 → 벡터 검색 → LLM BLOCK → 차단
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.3,
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [
                {
                    "text": "SQL Injection Prevention policy",
                    "name": "SQL Injection Prevention",
                    "category": "sql_injection",
                },
            ],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_rerank",
            lambda text, chunks: chunks[0],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_llm_judge",
            AsyncMock(return_value="BLOCK"),
        )
        result = await layer_full_pipeline.check(
            _req("' OR 1=1; DROP TABLE users; --"),
        )
        assert result.allowed is False
        assert result.severity == Severity.CRITICAL

    async def test_blocked_reason_format(
        self, layer_full_pipeline, monkeypatch
    ):
        # reason 포맷: 'policy violation: "{name}" (nli: X.XX, llm: BLOCK)'
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.45,
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [
                {
                    "text": "XSS Prevention policy text",
                    "name": "XSS Prevention",
                    "category": "xss",
                },
            ],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_rerank",
            lambda text, chunks: chunks[0],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_llm_judge",
            AsyncMock(return_value="BLOCK"),
        )
        result = await layer_full_pipeline.check(
            _req("<script>alert('xss')</script>"),
        )
        assert result.allowed is False
        expected = 'policy violation: "XSS Prevention" (nli: 0.45, llm: BLOCK)'
        assert result.reason == expected

    async def test_blocked_tags(self, layer_full_pipeline, monkeypatch):
        # tags 에 "policy", "owasp", "{policy_category}" 포함
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.3,
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [
                {
                    "text": "SQL Injection Prevention",
                    "name": "SQL Injection Prevention",
                    "category": "sql_injection",
                },
            ],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_rerank",
            lambda text, chunks: chunks[0],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_llm_judge",
            AsyncMock(return_value="BLOCK"),
        )
        result = await layer_full_pipeline.check(
            _req("' OR 1=1 --"),
        )
        assert result.allowed is False
        assert "policy" in result.tags
        assert "owasp" in result.tags
        assert "sql_injection" in result.tags

    async def test_blocked_confidence_zero(
        self, layer_full_pipeline, monkeypatch
    ):
        # 차단 시 confidence 는 0.0
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.3,
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [
                {
                    "text": "Policy text",
                    "name": "Test Policy",
                    "category": "test",
                },
            ],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_rerank",
            lambda text, chunks: chunks[0],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_llm_judge",
            AsyncMock(return_value="BLOCK"),
        )
        result = await layer_full_pipeline.check(
            _req("malicious input"),
        )
        assert result.allowed is False
        assert result.confidence == 0.0


# ──────────────────────────────────────────────
# 3. 엣지 케이스
# ──────────────────────────────────────────────


class TestEdgeCases:
    """경계 조건과 특수 시나리오."""

    async def test_empty_string_allowed(self, layer):
        # 빈 문자열은 검사 불필요, 즉시 허용
        result = await layer.check(_req(""))
        assert result.allowed is True

    async def test_nli_model_not_loaded_allows(self, layer):
        # NLI 모델 미로드 → fail-open → 허용
        result = await layer.check(
            _req("' OR 1=1; DROP TABLE users; --"),
        )
        assert result.allowed is True

    async def test_embed_model_not_loaded_allows(
        self, layer_nli_pass, monkeypatch
    ):
        # NLI 의심 → 임베딩 모델 미로드 → fail-open → 허용
        monkeypatch.setattr(
            layer_nli_pass,
            "_nli_predict",
            lambda text: 0.3,
        )
        result = await layer_nli_pass.check(
            _req("suspicious input"),
        )
        assert result.allowed is True

    async def test_reranker_not_loaded_allows(
        self, layer_full_pipeline, monkeypatch
    ):
        # reranker 미로드 → fail-open
        inst = L4Layer.__new__(L4Layer)
        inst.name = "L4"
        inst.nli_threshold = _DEFAULT_NLI_THRESHOLD
        inst.top_k = _DEFAULT_TOP_K
        inst._nli_model = MagicMock()
        inst._embed_model = MagicMock()
        inst._reranker_model = None
        inst._collection = MagicMock()
        inst._llm = AsyncMock()
        monkeypatch.setattr(
            inst,
            "_nli_predict",
            lambda text: 0.3,
        )
        monkeypatch.setattr(
            inst,
            "_search_policies",
            lambda text: [
                {
                    "text": "Policy",
                    "name": "P1",
                    "category": "test",
                },
            ],
        )
        result = await inst.check(_req("suspicious input"))
        assert result.allowed is True

    async def test_llm_none_allows(self, layer_full_pipeline, monkeypatch):
        # LLM 미설정(None) → fail-open → 허용
        layer_full_pipeline._llm = None
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.3,
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [
                {
                    "text": "Policy text",
                    "name": "P1",
                    "category": "test",
                },
            ],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_rerank",
            lambda text, chunks: chunks[0],
        )
        result = await layer_full_pipeline.check(
            _req("suspicious input"),
        )
        assert result.allowed is True

    async def test_db_empty_allows(self, layer_full_pipeline, monkeypatch):
        # DB 비어있음 → 검색 결과 0개 → 허용
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.3,
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [],
        )
        result = await layer_full_pipeline.check(
            _req("suspicious input"),
        )
        assert result.allowed is True

    async def test_llm_parse_failure_allows(
        self, layer_full_pipeline, monkeypatch
    ):
        # LLM 응답 파싱 실패 → fail-open → 허용
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.3,
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [
                {
                    "text": "Policy text",
                    "name": "P1",
                    "category": "test",
                },
            ],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_rerank",
            lambda text, chunks: chunks[0],
        )
        # LLM이 파싱 불가능한 응답을 반환
        monkeypatch.setattr(
            layer_full_pipeline,
            "_llm_judge",
            AsyncMock(return_value="MAYBE_BLOCK_MAYBE_NOT"),
        )
        result = await layer_full_pipeline.check(
            _req("suspicious input"),
        )
        assert result.allowed is True

    async def test_nli_exception_allows(self, layer_nli_pass, monkeypatch):
        # NLI 추론 중 예외 발생 → fail-open
        def _boom(text):
            msg = "NLI model inference failed"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            layer_nli_pass,
            "_nli_predict",
            _boom,
        )
        result = await layer_nli_pass.check(
            _req("some input"),
        )
        assert result.allowed is True

    async def test_search_exception_allows(
        self, layer_full_pipeline, monkeypatch
    ):
        # 벡터 검색 중 예외 발생 → fail-open
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.3,
        )

        def _boom(text):
            msg = "ChromaDB connection error"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            _boom,
        )
        result = await layer_full_pipeline.check(
            _req("suspicious input"),
        )
        assert result.allowed is True

    async def test_llm_exception_allows(self, layer_full_pipeline, monkeypatch):
        # LLM 호출 중 예외 발생 → fail-open
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.3,
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [
                {
                    "text": "Policy text",
                    "name": "P1",
                    "category": "test",
                },
            ],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_rerank",
            lambda text, chunks: chunks[0],
        )

        async def _boom(text, chunk):
            msg = "LLM API timeout"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            layer_full_pipeline,
            "_llm_judge",
            _boom,
        )
        result = await layer_full_pipeline.check(
            _req("suspicious input"),
        )
        assert result.allowed is True

    async def test_nli_threshold_boundary_allows(
        self, layer_nli_pass, monkeypatch
    ):
        # NLI contradiction 점수가 정확히 임계값(0.7) → 의심 없음 경계
        # 설계: contradiction > threshold 면 의심 없음
        # 점수가 정확히 임계값이면 초과가 아님 → 의심 있음 → 2단계로
        # 하지만 embed/DB/LLM 미로드 → fail-open → 허용
        monkeypatch.setattr(
            layer_nli_pass,
            "_nli_predict",
            lambda text: 0.7,
        )
        result = await layer_nli_pass.check(
            _req("borderline input"),
        )
        assert result.allowed is True


# ──────────────────────────────────────────────
# 4. LayerResult 형태 검증
# ──────────────────────────────────────────────


class TestLayerResultShape:
    """LayerResult 필드 규격 검증."""

    async def test_allowed_result_shape(self, layer_nli_pass, monkeypatch):
        # 허용 시 전체 필드 규격 확인
        monkeypatch.setattr(
            layer_nli_pass,
            "_nli_predict",
            lambda text: 0.9,
        )
        result = await layer_nli_pass.check(
            _req("정상적인 문장입니다"),
        )
        assert result.name == "L4"
        assert result.allowed is True
        assert result.reason is None
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0
        assert result.tags == []
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_blocked_result_shape(self, layer_full_pipeline, monkeypatch):
        # 차단 시 전체 필드 규격 확인
        monkeypatch.setattr(
            layer_full_pipeline,
            "_nli_predict",
            lambda text: 0.3,
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_search_policies",
            lambda text: [
                {
                    "text": "SQL Injection Prevention",
                    "name": "SQL Injection Prevention",
                    "category": "sql_injection",
                },
            ],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_rerank",
            lambda text, chunks: chunks[0],
        )
        monkeypatch.setattr(
            layer_full_pipeline,
            "_llm_judge",
            AsyncMock(return_value="BLOCK"),
        )
        result = await layer_full_pipeline.check(
            _req("' OR 1=1; DROP TABLE users; --"),
        )
        assert result.name == "L4"
        assert result.allowed is False
        assert result.reason is not None
        assert isinstance(result.reason, str)
        assert result.severity == Severity.CRITICAL
        assert result.confidence == 0.0
        assert isinstance(result.tags, list)
        assert len(result.tags) == 3
        assert "policy" in result.tags
        assert "owasp" in result.tags
        assert "sql_injection" in result.tags
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_empty_input_result_shape(self, layer):
        # 빈 입력 허용 시 규격 확인
        result = await layer.check(_req(""))
        assert result.name == "L4"
        assert result.allowed is True
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0

    async def test_fail_open_result_shape(self, layer):
        # fail-open 허용 시에도 name, allowed, severity 규격 유지
        result = await layer.check(
            _req("some input with unloaded models"),
        )
        assert result.name == "L4"
        assert result.allowed is True
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0


# ──────────────────────────────────────────────
# 5. 버그 재현: NLI 라벨 인덱스 반전 (#1)
# ──────────────────────────────────────────────


def _make_bare_layer():
    # 모델 로드 없이 L4Layer 인스턴스를 구성한다.
    # __init__ 을 우회하기 때문에 실제 파일시스템/모델 접근이 발생하지 않는다.
    inst = L4Layer.__new__(L4Layer)
    inst.name = "L4"
    inst.nli_threshold = _DEFAULT_NLI_THRESHOLD
    inst.top_k = _DEFAULT_TOP_K
    inst._nli_model = None
    inst._embed_model = None
    inst._reranker_model = None
    inst._collection = None
    inst._llm = None
    return inst


class TestNliLabelIndexBug:
    """`_nli_predict` 가 contradiction(인덱스 0) 확률을 반환해야 함을 검증.

    `core_secure_layer/layers/l4/model/nli/nli_custom_model/config.json`
    의 id2label 은 `{0: contradiction, 1: neutral, 2: entailment}` 이므로
    cross-encoder 로짓의 인덱스 0 이 contradiction, 인덱스 2 가
    entailment 이다. 현재 구현은 인덱스 2 를 반환하여 라벨이 뒤집혀
    있으므로 아래 테스트들은 반드시 실패해야 한다.
    """

    def test_contradiction_dominant_2d_logits(self):
        # 2차원 로짓에서 contradiction 이 압도적이면 높은 확률을 반환해야 함
        import numpy as np

        inst = _make_bare_layer()
        inst._nli_model = MagicMock()
        inst._nli_model.predict.return_value = np.array(
            [[10.0, -1.0, -1.0]],
        )
        score = inst._nli_predict("arbitrary text")
        assert score >= 0.9, (
            f"contradiction 로짓이 압도적일 때 확률이 0.9 이상이어야 하는데 "
            f"{score} 가 반환됨 (인덱스 반전 버그)"
        )

    def test_entailment_dominant_2d_logits(self):
        # 2차원 로짓에서 entailment 가 압도적이면 contradiction 확률은 낮아야 함
        import numpy as np

        inst = _make_bare_layer()
        inst._nli_model = MagicMock()
        inst._nli_model.predict.return_value = np.array(
            [[-1.0, -1.0, 10.0]],
        )
        score = inst._nli_predict("arbitrary text")
        assert score <= 0.1, (
            f"entailment 로짓이 압도적일 때 contradiction 확률이 0.1 이하여야 "
            f"하는데 {score} 가 반환됨 (인덱스 반전 버그)"
        )

    def test_contradiction_dominant_1d_logits(self):
        # 1차원 로짓(ndim==1 분기) 도 동일하게 contradiction 을 반환해야 함
        import numpy as np

        inst = _make_bare_layer()
        inst._nli_model = MagicMock()
        inst._nli_model.predict.return_value = np.array(
            [10.0, -1.0, -1.0],
        )
        score = inst._nli_predict("arbitrary text")
        assert score >= 0.9, (
            f"1차원 로짓 contradiction 압도 시 확률이 0.9 이상이어야 하는데 "
            f"{score} 가 반환됨 (ndim==1 분기 인덱스 반전 버그)"
        )


# ──────────────────────────────────────────────
# 6. 버그 재현: Python 2 스타일 except 구문 잔재 (#2)
# ──────────────────────────────────────────────


class TestL4ModuleSyntax:
    """`l4.py` 에 Python 2 스타일 except 절이 남아 있지 않아야 함을 검증.

    현재 `_llm_judge` 내부에
    `except _json.JSONDecodeError, AttributeError:` (Python 2 문법) 이
    남아 있다. 올바른 형태는 `except (_json.JSONDecodeError, AttributeError):`.

    Python 3.14 이후에서는 `except A, B:` 가 SyntaxError 가 아닌 tuple
    해석으로 허용되지만, 이는 Python 2 잔재로서 의도가 모호하고 가독성이
    나쁘므로 명시적 괄호 tuple 형태로 작성해야 한다. 아래 테스트는
    `l4.py` 소스 텍스트에 해당 패턴이 남아 있으면 실패한다.
    """

    def test_no_python2_style_except_clause(self):
        # l4.py 에 `except X.Y, Z:` 혹은 `except X, Y:` 처럼 괄호 없이
        # 두 예외를 콤마로 나열한 Python 2 스타일 except 절이 없어야 한다.
        import re
        from pathlib import Path

        source_path = (
            Path(__file__).resolve().parent.parent
            / "core_secure_layer"
            / "layers"
            / "l4"
            / "l4.py"
        )
        source = source_path.read_text(encoding="utf-8")
        # `except <식별자/속성접근>, <식별자>:` 패턴 (괄호 없음)
        # 괄호로 묶인 tuple 형태는 매치하지 않는다.
        pattern = re.compile(
            r"^\s*except\s+[A-Za-z_][\w\.]*\s*,\s*[A-Za-z_][\w\.]*\s*:",
            re.MULTILINE,
        )
        matches = pattern.findall(source)
        assert not matches, (
            "l4.py 에 Python 2 스타일 except 절이 남아 있음: "
            f"{matches!r}. 괄호 tuple 문법 `except (A, B):` 로 수정 필요."
        )

    def test_except_json_decode_error_uses_tuple_syntax(self):
        # JSONDecodeError 가 포함된 except 절은 반드시 괄호 tuple 형태여야 함
        from pathlib import Path

        source_path = (
            Path(__file__).resolve().parent.parent
            / "core_secure_layer"
            / "layers"
            / "l4"
            / "l4.py"
        )
        source = source_path.read_text(encoding="utf-8")
        # 올바른 형태가 최소 1회 등장해야 함
        assert "except (_json.JSONDecodeError, AttributeError):" in source, (
            "_llm_judge 의 except 절이 괄호 tuple 형태"
            " `except (_json.JSONDecodeError, AttributeError):`"
            " 로 작성되어 있지 않음."
        )
        # 잘못된 Python 2 스타일이 존재하면 안 됨
        assert "except _json.JSONDecodeError, AttributeError:" not in source, (
            "l4.py 에 Python 2 스타일 "
            "`except _json.JSONDecodeError, AttributeError:` 가 남아 있음."
        )
