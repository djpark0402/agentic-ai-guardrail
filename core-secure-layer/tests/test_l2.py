import pytest

from core_secure_layer.layers.l2.l2 import L2Layer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    Severity,
)

# 테스트용 더미 모델 경로 상수
_FAKE_MODEL_PATH = "tests/fixtures/fake-gpt2"
_DEFAULT_THRESHOLD = 600.0


@pytest.fixture
def layer():
    # 모델 미로드 상태의 인스턴스 (1차 필터링만 동작)
    inst = L2Layer.__new__(L2Layer)
    inst.name = "L2"
    inst.model_path = _FAKE_MODEL_PATH
    inst.ppl_threshold = _DEFAULT_THRESHOLD
    return inst


@pytest.fixture
def layer_with_ppl():
    """모델 로드 상태를 시뮬레이션하는 fixture.

    _model_loaded=True 로 설정하고 _compute_ppl 을
    외부에서 monkeypatch 하여 PPL 값을 제어한다.
    """
    inst = L2Layer.__new__(L2Layer)
    inst.name = "L2"
    inst.model_path = _FAKE_MODEL_PATH
    inst.ppl_threshold = _DEFAULT_THRESHOLD
    inst._model_loaded = True
    return inst


def _req(text):
    """주어진 텍스트로 GuardrailRequest 를 생성한다."""
    return GuardrailRequest(user_input=text)


# ──────────────────────────────────────────────
# 0. 생성자 계약 검증
# ──────────────────────────────────────────────


class TestConstructorContract:
    """L2Layer 생성자가 model_name, ppl_threshold 를 받는지 확인."""

    def test_accepts_model_name_and_threshold(self):
        inst = L2Layer(
            model_name="gpt2",
            ppl_threshold=_DEFAULT_THRESHOLD,
        )
        assert inst.name == "L2"
        assert "gpt2" in inst.model_path
        assert inst.ppl_threshold == _DEFAULT_THRESHOLD

    def test_kogpt2_model_path(self):
        inst = L2Layer(
            model_name="kogpt2",
            ppl_threshold=_DEFAULT_THRESHOLD,
        )
        assert "kogpt2" in inst.model_path


# ──────────────────────────────────────────────
# 1. 허용 골든 패스 — 1차 문자셋 통과
# ──────────────────────────────────────────────


class TestAllowedGoldenPath:
    """정상 입력이 허용되는 기본 시나리오."""

    async def test_plain_korean(self, layer):
        result = await layer.check(
            _req("안녕하세요 반갑습니다"),
        )
        assert result.allowed is True
        assert result.name == "L2"
        assert result.reason is None

    async def test_plain_english(self, layer):
        result = await layer.check(
            _req("Hello world, how are you?"),
        )
        assert result.allowed is True

    async def test_mixed_korean_english(self, layer):
        result = await layer.check(
            _req("오늘 meeting 있어요!"),
        )
        assert result.allowed is True

    async def test_numbers_and_punctuation(self, layer):
        result = await layer.check(
            _req("2024년 1월 1일, 가격: $100.50"),
        )
        assert result.allowed is True

    async def test_math_symbols(self, layer):
        result = await layer.check(
            _req("x + y = z * 2 @email #tag"),
        )
        assert result.allowed is True

    async def test_brackets_and_special(self, layer):
        result = await layer.check(
            _req("function(a, b) { return [a + b]; }"),
        )
        assert result.allowed is True


# ──────────────────────────────────────────────
# 2. 차단 골든 패스 — 1차 문자셋 차단
# ──────────────────────────────────────────────


class TestCharsetBlocked:
    """허용 목록 외 문자가 포함되면 1차에서 즉시 차단."""

    async def test_emoji_blocked(self, layer):
        result = await layer.check(
            _req("안녕하세요 😊"),
        )
        assert result.allowed is False
        assert result.severity == Severity.MEDIUM
        assert "disallowed character detected at position" in (result.reason)
        assert "😊" in result.reason
        assert "charset" in result.tags
        assert "disallowed_character" in result.tags

    async def test_chinese_character_blocked(self, layer):
        result = await layer.check(_req("你好"))
        assert result.allowed is False
        assert "disallowed character detected at position" in (result.reason)

    async def test_japanese_blocked(self, layer):
        result = await layer.check(
            _req("こんにちは"),
        )
        assert result.allowed is False
        assert "disallowed character detected at position" in (result.reason)

    async def test_cyrillic_blocked(self, layer):
        result = await layer.check(
            _req("Привет мир"),
        )
        assert result.allowed is False

    async def test_zero_width_space_blocked(self, layer):
        result = await layer.check(
            _req("hello\u200bworld"),
        )
        assert result.allowed is False
        assert "disallowed character detected at position" in (result.reason)

    async def test_first_disallowed_char_position(self, layer):
        # "abc😊def" — 😊 는 인덱스 3
        result = await layer.check(
            _req("abc😊def"),
        )
        assert result.allowed is False
        assert "position 3" in result.reason
        assert "'😊'" in result.reason


# ──────────────────────────────────────────────
# 3. 차단 골든 패스 — 2차 PPL 차단 (모델 mock)
# ──────────────────────────────────────────────


class TestPerplexityBlocked:
    """문자셋 통과 후 PPL 이 임계값 초과 시 차단."""

    async def test_high_ppl_blocked(self, layer_with_ppl, monkeypatch):
        # PPL 이 임계값 초과하도록 mock
        monkeypatch.setattr(
            layer_with_ppl,
            "_compute_ppl",
            lambda text: 1500.0,
        )
        result = await layer_with_ppl.check(
            _req("asdf qwer zxcv bnm jkl uiop"),
        )
        assert result.allowed is False
        assert result.severity == Severity.MEDIUM
        assert "high perplexity" in result.reason
        assert "threshold" in result.reason
        assert "perplexity" in result.tags
        assert "anomaly" in result.tags

    async def test_ppl_reason_format(self, layer_with_ppl, monkeypatch):
        monkeypatch.setattr(
            layer_with_ppl,
            "_compute_ppl",
            lambda text: 1234.5,
        )
        result = await layer_with_ppl.check(
            _req("qqq www eee rrr ttt yyy"),
        )
        assert result.allowed is False
        assert "high perplexity: 1234.5" in result.reason
        assert "(threshold: 600.0)" in result.reason

    async def test_ppl_below_threshold_allowed(
        self, layer_with_ppl, monkeypatch
    ):
        # PPL 이 임계값 이하면 허용
        monkeypatch.setattr(
            layer_with_ppl,
            "_compute_ppl",
            lambda text: 50.0,
        )
        result = await layer_with_ppl.check(
            _req("Hello world, how are you?"),
        )
        assert result.allowed is True


# ──────────────────────────────────────────────
# 4. 엣지 케이스
# ──────────────────────────────────────────────


class TestEdgeCases:
    """경계 조건과 복합 시나리오."""

    async def test_empty_string_allowed(self, layer):
        result = await layer.check(_req(""))
        assert result.allowed is True

    async def test_whitespace_only_allowed(self, layer):
        result = await layer.check(_req("   \n  "))
        assert result.allowed is True

    async def test_newline_allowed(self, layer):
        result = await layer.check(
            _req("첫 줄\n둘째 줄"),
        )
        assert result.allowed is True

    async def test_tab_character_allowed(self, layer):
        result = await layer.check(
            _req("hello\tworld"),
        )
        assert result.allowed is True

    async def test_korean_jamo_allowed(self, layer):
        result = await layer.check(
            _req("ㄱㄴㄷㄹ ㅏㅓㅗㅜ"),
        )
        assert result.allowed is True

    async def test_all_allowed_special_chars(self, layer):
        result = await layer.check(
            _req(".,!?:;'\"-()[]{}@#$%^&*+-=~/\\|<>_"),
        )
        assert result.allowed is True

    async def test_charset_check_skips_ppl(self, layer):
        # 1차에서 차단되면 2차 PPL 스킵
        result = await layer.check(
            _req("hello 😊 world"),
        )
        assert result.allowed is False
        assert "charset" in result.tags
        assert "perplexity" not in result.tags

    async def test_custom_threshold(self):
        custom_layer = L2Layer(
            model_name="gpt2",
            ppl_threshold=100.0,
        )
        result = await custom_layer.check(
            _req("normal sentence"),
        )
        assert result.allowed is True

    async def test_model_not_loaded_allows(self, layer):
        # 모델 미로드 상태에서는 2차 필터링 스킵 → 허용
        result = await layer.check(
            _req("asdf qwer zxcv bnm jkl uiop"),
        )
        assert result.allowed is True


# ──────────────────────────────────────────────
# 5. LayerResult 형태 검증
# ──────────────────────────────────────────────


class TestLayerResultShape:
    """LayerResult 필드 규격 검증."""

    async def test_allowed_result_shape(self, layer):
        result = await layer.check(
            _req("정상적인 한글 문장입니다"),
        )
        assert result.name == "L2"
        assert result.allowed is True
        assert result.reason is None
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0
        assert result.tags == []
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_charset_blocked_result_shape(self, layer):
        result = await layer.check(
            _req("test 😊 emoji"),
        )
        assert result.name == "L2"
        assert result.allowed is False
        assert result.reason is not None
        assert isinstance(result.reason, str)
        assert result.severity == Severity.MEDIUM
        assert isinstance(result.tags, list)
        assert len(result.tags) >= 2
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_ppl_blocked_result_shape(self, layer_with_ppl, monkeypatch):
        monkeypatch.setattr(
            layer_with_ppl,
            "_compute_ppl",
            lambda text: 999.9,
        )
        result = await layer_with_ppl.check(
            _req("zxcv bnm qwer asdf poiu"),
        )
        assert result.name == "L2"
        assert result.allowed is False
        assert result.reason is not None
        assert result.severity == Severity.MEDIUM
        assert "perplexity" in result.tags
        assert "anomaly" in result.tags
        assert result.execution_time_ms is not None


# ──────────────────────────────────────────────
# 6. fail-open 검증
# ──────────────────────────────────────────────


class TestFailOpen:
    """예외 발생 시 fail-open(허용) 원칙 검증."""

    async def test_model_load_failure_allows(self):
        broken_layer = L2Layer(
            model_name="nonexistent_model",
            ppl_threshold=_DEFAULT_THRESHOLD,
        )
        result = await broken_layer.check(
            _req("normal sentence"),
        )
        assert result.allowed is True

    async def test_ppl_exception_allows(self, layer_with_ppl, monkeypatch):
        # PPL 계산 중 예외가 발생해도 fail-open
        def _boom(text: str) -> float:
            msg = "boom"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            layer_with_ppl,
            "_compute_ppl",
            _boom,
        )
        result = await layer_with_ppl.check(
            _req("normal sentence for ppl test"),
        )
        assert result.allowed is True

    async def test_none_metadata_allowed(self, layer):
        req = GuardrailRequest(
            user_input="hello",
            metadata=None,
        )
        result = await layer.check(req)
        assert result.allowed is True
