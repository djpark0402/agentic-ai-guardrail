import pytest

from core_secure_layer.layers.l6.l6 import L6Layer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    Severity,
)


def _req(text):
    """주어진 텍스트로 GuardrailRequest 를 생성한다."""
    return GuardrailRequest(user_input=text)


@pytest.fixture
def layer():
    """모델 미로드 상태의 L6Layer 인스턴스.

    _model_loaded=False 이므로 fail-open 으로 허용.
    """
    inst = L6Layer.__new__(L6Layer)
    inst.name = "L6"
    inst.model_name = "kanana-safeguard-8b"
    inst._model_loaded = False
    return inst


@pytest.fixture
def layer_loaded():
    """모델 로드 상태를 시뮬레이션하는 fixture.

    _model_loaded=True 로 설정하고 _predict 를
    monkeypatch 하여 모델 출력을 제어한다.
    """
    inst = L6Layer.__new__(L6Layer)
    inst.name = "L6"
    inst.model_name = "kanana-safeguard-8b"
    inst._model_loaded = True
    return inst


# ──────────────────────────────────────────────
# 0. 생성자 계약 검증
# ──────────────────────────────────────────────


class TestConstructorContract:
    """L6Layer 생성자가 model_name 을 받는지 확인."""

    def test_accepts_model_name(self):
        # model_name 을 전달할 수 있어야 한다
        inst = L6Layer(model_name="kanana-safeguard-8b")
        assert inst.name == "L6"

    def test_default_model_name(self):
        # 기본 model_name 은 "kanana-safeguard-8b"
        inst = L6Layer()
        assert inst.name == "L6"
        assert inst.model_name == "kanana-safeguard-8b"

    def test_custom_model_name(self):
        # 다른 모델명으로 생성 가능
        inst = L6Layer(model_name="llama-guard-3-8b")
        assert inst.model_name == "llama-guard-3-8b"


# ──────────────────────────────────────────────
# 1. 허용 골든 패스
# ──────────────────────────────────────────────


class TestAllowedGoldenPath:
    """모델이 safe 판정한 입력이 허용되는 시나리오."""

    async def test_safe_korean_input(self, layer_loaded, monkeypatch):
        # 일반 한국어 문장 → 모델 safe 판정 → 허용
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "safe",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("오늘 날씨가 좋다"),
        )
        assert result.allowed is True
        assert result.name == "L6"
        assert result.reason is None

    async def test_safe_english_input(self, layer_loaded, monkeypatch):
        # 일반 영문 문장 → 모델 safe 판정 → 허용
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "safe",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("Hello, how are you today?"),
        )
        assert result.allowed is True

    async def test_safe_with_confidence(self, layer_loaded, monkeypatch):
        # 허용 시 confidence=1.0
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "safe",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("일상적인 대화 내용"),
        )
        assert result.allowed is True
        assert result.confidence == 1.0
        assert result.severity == Severity.NONE


# ──────────────────────────────────────────────
# 2. 차단 골든 패스
# ──────────────────────────────────────────────


class TestBlockedGoldenPath:
    """모델이 unsafe 판정한 입력이 차단되는 시나리오."""

    async def test_unsafe_with_category(self, layer_loaded, monkeypatch):
        # 모델이 "unsafe\nS1" 출력 → 차단, 카테고리 S1
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "unsafe\nS1",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("위험한 내용이 포함된 입력"),
        )
        assert result.allowed is False
        assert result.severity == Severity.CRITICAL
        assert "unsafe: S1" in result.reason
        assert "safety_model" in result.tags
        assert "S1" in result.tags

    async def test_unsafe_without_category(self, layer_loaded, monkeypatch):
        # 모델이 "unsafe" 만 출력 → 차단, 기본 reason
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "unsafe",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("위험한 입력"),
        )
        assert result.allowed is False
        assert result.severity == Severity.CRITICAL
        assert result.reason == "unsafe content detected"
        assert "safety_model" in result.tags

    async def test_unsafe_tags_without_category(
        self, layer_loaded, monkeypatch
    ):
        # 카테고리 없는 unsafe → tags 에 "safety_model" 만
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "unsafe",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("위험한 내용"),
        )
        assert result.tags == ["safety_model"]

    async def test_unsafe_llama_guard_category(self, layer_loaded, monkeypatch):
        # Llama Guard 스타일 "unsafe\nO1" → 차단
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "unsafe\nO1",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("폭력적인 내용의 입력"),
        )
        assert result.allowed is False
        assert "unsafe: O1" in result.reason
        assert "O1" in result.tags
        assert "safety_model" in result.tags

    async def test_blocked_confidence_zero(self, layer_loaded, monkeypatch):
        # 차단 시 confidence=0.0
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "unsafe\nS1",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("위험 입력"),
        )
        assert result.confidence == 0.0


# ──────────────────────────────────────────────
# 3. 엣지 케이스
# ──────────────────────────────────────────────


class TestEdgeCases:
    """경계 조건과 특수 시나리오."""

    async def test_empty_string_allowed(self, layer_loaded, monkeypatch):
        # 빈 문자열 → 추론 불필요 → 허용
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "safe",
            raising=False,
        )
        result = await layer_loaded.check(_req(""))
        assert result.allowed is True

    async def test_model_not_loaded_allows(self, layer):
        # 모델 미로드 → fail-open → 허용
        result = await layer.check(
            _req("어떤 입력이든 허용"),
        )
        assert result.allowed is True

    async def test_predict_exception_allows(self, layer_loaded, monkeypatch):
        # 추론 중 예외 발생 → fail-open → 허용
        def _boom(text):
            msg = "model inference failed"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            _boom,
            raising=False,
        )
        result = await layer_loaded.check(
            _req("예외가 발생할 입력"),
        )
        assert result.allowed is True

    async def test_parse_failure_allows(self, layer_loaded, monkeypatch):
        # 모델 출력 파싱 실패 → fail-open → 허용
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "gibberish output 무의미한 결과",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("파싱 실패 유발 입력"),
        )
        assert result.allowed is True

    async def test_whitespace_only_model_output(
        self, layer_loaded, monkeypatch
    ):
        # 모델 출력이 공백만 → 파싱 실패 → fail-open
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "   \n  ",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("테스트 입력"),
        )
        assert result.allowed is True

    async def test_empty_model_output(self, layer_loaded, monkeypatch):
        # 모델 출력이 빈 문자열 → 파싱 실패 → fail-open
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("테스트 입력"),
        )
        assert result.allowed is True

    async def test_unsafe_with_extra_lines(self, layer_loaded, monkeypatch):
        # "unsafe\nS1\nextra info" → 카테고리 S1 추출
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "unsafe\nS1\nextra info",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("여러 줄 출력 테스트"),
        )
        assert result.allowed is False
        assert "unsafe: S1" in result.reason

    async def test_case_insensitive_safe(self, layer_loaded, monkeypatch):
        # 모델 출력 "Safe" (대소문자 혼용) → 허용
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "Safe",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("대소문자 테스트"),
        )
        assert result.allowed is True

    async def test_predict_returns_none_allows(self, layer_loaded, monkeypatch):
        # _predict 가 None 반환 → 파싱 실패 → fail-open
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: None,
            raising=False,
        )
        result = await layer_loaded.check(
            _req("None 반환 테스트"),
        )
        assert result.allowed is True


# ──────────────────────────────────────────────
# 4. LayerResult 형태 검증
# ──────────────────────────────────────────────


class TestLayerResultShape:
    """LayerResult 필드 규격 검증."""

    async def test_allowed_result_shape(self, layer_loaded, monkeypatch):
        # 허용 시 전체 필드 규격 확인
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "safe",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("정상적인 문장입니다"),
        )
        assert result.name == "L6"
        assert result.allowed is True
        assert result.reason is None
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0
        assert result.tags == []
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_blocked_with_category_shape(self, layer_loaded, monkeypatch):
        # 카테고리 포함 차단 시 전체 필드 규격 확인
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "unsafe\nS1",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("위험한 내용"),
        )
        assert result.name == "L6"
        assert result.allowed is False
        assert result.reason is not None
        assert isinstance(result.reason, str)
        assert "unsafe: S1" in result.reason
        assert result.severity == Severity.CRITICAL
        assert result.confidence == 0.0
        assert isinstance(result.tags, list)
        assert "safety_model" in result.tags
        assert "S1" in result.tags
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_blocked_without_category_shape(
        self, layer_loaded, monkeypatch
    ):
        # 카테고리 없는 차단 시 필드 규격 확인
        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            lambda text: "unsafe",
            raising=False,
        )
        result = await layer_loaded.check(
            _req("위험 내용"),
        )
        assert result.name == "L6"
        assert result.allowed is False
        assert result.reason == "unsafe content detected"
        assert result.severity == Severity.CRITICAL
        assert result.confidence == 0.0
        assert result.tags == ["safety_model"]
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_fail_open_result_shape(self, layer):
        # 모델 미로드 fail-open 시에도 규격 유지
        result = await layer.check(
            _req("모델 미로드 상태 테스트"),
        )
        assert result.name == "L6"
        assert result.allowed is True
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0
        assert result.tags == []

    async def test_exception_fail_open_shape(self, layer_loaded, monkeypatch):
        # 예외 발생 fail-open 시에도 규격 유지
        def _boom(text):
            msg = "boom"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            layer_loaded,
            "_predict",
            _boom,
            raising=False,
        )
        result = await layer_loaded.check(
            _req("예외 테스트"),
        )
        assert result.name == "L6"
        assert result.allowed is True
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0
