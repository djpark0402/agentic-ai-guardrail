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
    # L2Layer 는 model_path, ppl_threshold 를 받아야 한다.
    # 현재 스켈레톤은 __init__ 미정의 상태이므로
    # 생성자 계약 테스트에서 별도 검증한다.
    inst = L2Layer.__new__(L2Layer)
    inst.name = "L2"
    inst.model_path = _FAKE_MODEL_PATH
    inst.ppl_threshold = _DEFAULT_THRESHOLD
    return inst


def _req(text):
    """주어진 텍스트로 GuardrailRequest 를 생성한다."""
    return GuardrailRequest(user_input=text)


# ──────────────────────────────────────────────
# 0. 생성자 계약 검증
# ──────────────────────────────────────────────


class TestConstructorContract:
    """L2Layer 생성자가 model_path, ppl_threshold 를 받는지 확인."""

    def test_accepts_model_path_and_threshold(self):
        # 구현 후 L2Layer(model_path=..., ppl_threshold=...) 가 동작해야 한다
        inst = L2Layer(
            model_path=_FAKE_MODEL_PATH,
            ppl_threshold=_DEFAULT_THRESHOLD,
        )
        assert inst.name == "L2"
        assert inst.model_path == _FAKE_MODEL_PATH
        assert inst.ppl_threshold == _DEFAULT_THRESHOLD


# ──────────────────────────────────────────────
# 1. 허용 골든 패스 — 1차 문자셋 통과 + 2차 PPL 통과
# ──────────────────────────────────────────────


class TestAllowedGoldenPath:
    """정상 입력이 허용되는 기본 시나리오."""

    async def test_plain_korean(self, layer):
        # 한글 문장은 허용
        result = await layer.check(
            _req("안녕하세요 반갑습니다"),
        )
        assert result.allowed is True
        assert result.name == "L2"
        assert result.reason is None

    async def test_plain_english(self, layer):
        # 평범한 영문 문장은 허용
        result = await layer.check(
            _req("Hello world, how are you?"),
        )
        assert result.allowed is True

    async def test_mixed_korean_english(self, layer):
        # 한영 혼용 문장 허용
        result = await layer.check(
            _req("오늘 meeting 있어요!"),
        )
        assert result.allowed is True

    async def test_numbers_and_punctuation(self, layer):
        # 숫자 + 기본 구두점은 허용
        result = await layer.check(
            _req("2024년 1월 1일, 가격: $100.50"),
        )
        assert result.allowed is True

    async def test_math_symbols(self, layer):
        # 수학/기호 문자 허용
        result = await layer.check(
            _req("x + y = z * 2 @email #tag"),
        )
        assert result.allowed is True

    async def test_brackets_and_special(self, layer):
        # 괄호, 중괄호, 대괄호 등 허용 목록 내 특수문자
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
        # 이모지는 허용 목록에 없으므로 차단
        result = await layer.check(
            _req("안녕하세요 😊"),
        )
        assert result.allowed is False
        assert result.severity == Severity.MEDIUM
        assert "disallowed character detected at position" in (result.reason)
        # reason 에 문자가 포함되어야 함
        assert "😊" in result.reason
        assert "charset" in result.tags
        assert "disallowed_character" in result.tags

    async def test_chinese_character_blocked(self, layer):
        # 중국어 한자는 한글 범위 밖이므로 차단
        result = await layer.check(_req("你好"))
        assert result.allowed is False
        assert "disallowed character detected at position" in (result.reason)

    async def test_japanese_blocked(self, layer):
        # 일본어 히라가나/가타카나는 허용 목록에 없음
        result = await layer.check(
            _req("こんにちは"),
        )
        assert result.allowed is False
        assert "disallowed character detected at position" in (result.reason)

    async def test_cyrillic_blocked(self, layer):
        # 키릴 문자 차단
        result = await layer.check(
            _req("Привет мир"),
        )
        assert result.allowed is False

    async def test_zero_width_space_blocked(self, layer):
        # 제로 너비 공백(U+200B)은 허용 목록에 없음
        result = await layer.check(
            _req("hello\u200bworld"),
        )
        assert result.allowed is False
        assert "disallowed character detected at position" in (result.reason)

    async def test_first_disallowed_char_position(self, layer):
        # 첫 번째 비허용 문자의 위치가 정확한지 검증
        # "abc😊def" — 😊 는 인덱스 3
        result = await layer.check(
            _req("abc😊def"),
        )
        assert result.allowed is False
        assert "position 3" in result.reason
        assert "'😊'" in result.reason


# ──────────────────────────────────────────────
# 3. 차단 골든 패스 — 2차 PPL 차단
# ──────────────────────────────────────────────


class TestPerplexityBlocked:
    """문자셋 통과 후 PPL 이 임계값 초과 시 차단."""

    async def test_high_ppl_blocked(self, layer):
        # 무작위 토큰 나열 — PPL 이 높을 것으로 예상
        gibberish = "asdf qwer zxcv bnm jkl uiop"
        result = await layer.check(_req(gibberish))
        assert result.allowed is False
        assert result.severity == Severity.MEDIUM
        assert "high perplexity" in result.reason
        assert "threshold" in result.reason
        assert "perplexity" in result.tags
        assert "anomaly" in result.tags

    async def test_ppl_reason_format(self, layer):
        # reason 형식: "high perplexity: {ppl:.1f} ..."
        gibberish = "qqq www eee rrr ttt yyy"
        result = await layer.check(_req(gibberish))
        assert result.allowed is False
        assert "high perplexity:" in result.reason
        assert "(threshold: 600.0)" in result.reason


# ──────────────────────────────────────────────
# 4. 엣지 케이스
# ──────────────────────────────────────────────


class TestEdgeCases:
    """경계 조건과 복합 시나리오."""

    async def test_empty_string_allowed(self, layer):
        # 빈 문자열은 허용
        result = await layer.check(_req(""))
        assert result.allowed is True

    async def test_whitespace_only_allowed(self, layer):
        # 공백만 있는 입력은 허용
        result = await layer.check(_req("   \n  "))
        assert result.allowed is True

    async def test_newline_allowed(self, layer):
        # 줄바꿈은 허용 목록에 포함
        result = await layer.check(
            _req("첫 줄\n둘째 줄"),
        )
        assert result.allowed is True

    async def test_tab_character_allowed(self, layer):
        # 오탐 불허 원칙에 따라 탭도 공백 범주로 허용
        result = await layer.check(
            _req("hello\tworld"),
        )
        assert result.allowed is True

    async def test_korean_jamo_allowed(self, layer):
        # 한글 자모(ㄱ-ㅎ, ㅏ-ㅣ)는 허용
        result = await layer.check(
            _req("ㄱㄴㄷㄹ ㅏㅓㅗㅜ"),
        )
        assert result.allowed is True

    async def test_all_allowed_special_chars(self, layer):
        # 허용 목록 내 모든 특수문자 종류가 포함된 입력
        result = await layer.check(
            _req(".,!?:;'\"-()[]{}@#$%^&*+-=~/\\|<>_"),
        )
        assert result.allowed is True

    async def test_charset_check_skips_ppl(self, layer):
        # 1차에서 차단되면 2차 PPL 스킵 — 태그에 perplexity 없음
        result = await layer.check(
            _req("hello 😊 world"),
        )
        assert result.allowed is False
        assert "charset" in result.tags
        assert "perplexity" not in result.tags

    async def test_custom_threshold(self):
        # ppl_threshold 를 다른 값으로 설정해도 동작
        custom_layer = L2Layer(
            model_path=_FAKE_MODEL_PATH,
            ppl_threshold=100.0,
        )
        result = await custom_layer.check(
            _req("normal sentence"),
        )
        # 정상 문장은 PPL < 100 이므로 허용
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

    async def test_ppl_blocked_result_shape(self, layer):
        # PPL 차단 시 형태 검증
        gibberish = "zxcv bnm qwer asdf poiu"
        result = await layer.check(_req(gibberish))
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
        # 존재하지 않는 모델 경로 — fail-open
        broken_layer = L2Layer(
            model_path="/nonexistent/model/path",
            ppl_threshold=_DEFAULT_THRESHOLD,
        )
        result = await broken_layer.check(
            _req("normal sentence"),
        )
        assert result.allowed is True

    async def test_ppl_computation_exception_allows(
        self,
        layer,
    ):
        # PPL 계산 도중 예외가 발생해도 fail-open
        # 문자셋 통과 후 모델 미로드 상태에서 허용
        result = await layer.check(
            _req("normal sentence for ppl test"),
        )
        assert result.allowed is True

    async def test_none_metadata_allowed(self, layer):
        # metadata 가 None 이어도 정상 동작
        req = GuardrailRequest(
            user_input="hello",
            metadata=None,
        )
        result = await layer.check(req)
        assert result.allowed is True
