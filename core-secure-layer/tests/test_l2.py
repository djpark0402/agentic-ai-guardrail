import pytest

from core_secure_layer.layers.l2.l2 import L2Layer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    Severity,
)

# 테스트용 더미 모델 경로 상수
_FAKE_MODEL_PATH = "tests/fixtures/fake-gpt2"
_DEFAULT_THRESHOLD = 600.0
_DEFAULT_ENTROPY_LOW = 1.5
_DEFAULT_ENTROPY_HIGH = 5.5


@pytest.fixture(autouse=True)
def _skip_real_model_load(monkeypatch):
    # L2Layer 의 실제 GPT-2 모델 로딩을 스킵해 RAM 압박/스왑 확장을 방지.
    # _load_model 이 호출되는 모든 테스트에 자동 적용된다.
    def _noop(self):
        self._tokenizer = None
        self._model = None
        self._model_loaded = False

    monkeypatch.setattr(L2Layer, "_load_model", _noop)


@pytest.fixture
def layer():
    # 모델 미로드 상태의 인스턴스 (1차 필터링만 동작)
    inst = L2Layer.__new__(L2Layer)
    inst.name = "L2"
    inst.model_path = _FAKE_MODEL_PATH
    inst.ppl_threshold = _DEFAULT_THRESHOLD
    inst.entropy_low = _DEFAULT_ENTROPY_LOW
    inst.entropy_high = _DEFAULT_ENTROPY_HIGH
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
    inst.entropy_low = _DEFAULT_ENTROPY_LOW
    inst.entropy_high = _DEFAULT_ENTROPY_HIGH
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


# ──────────────────────────────────────────────
# 7. (신규) 2차 regex 모듈 함수 직접 검증
# ──────────────────────────────────────────────


class TestCheckRegexFunction:
    """모듈 함수 ``_check_regex`` 의 포지티브/네거티브 매치 검증.

    구현 완료 시 ``_check_regex`` 는 (violated, message) 튜플을 반환하며,
    매치된 경우 메시지는 ``"의심 패턴 탐지: <desc>"`` 형식이어야 한다.
    """

    def test_same_char_repeated_10_times_blocked(self):
        # 10자 동일 문자 → `(.)\1{9,}` 매치
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("aaaaaaaaaa")
        assert violated is True
        assert msg == "의심 패턴 탐지: 동일 문자 10회 이상 반복"

    def test_same_char_repeated_9_times_not_blocked(self):
        # 9자 동일 문자는 9회 반복(총 길이 9) 이므로 \1{9,} 기준
        # 추가 9회 반복이 필요해 미매치 (10자 필요)
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("aaaaaaaaa")
        assert violated is False
        assert msg == "의심 패턴 없음"

    def test_korean_jamo_5_chars_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("ㄱㄴㄷㄹㅁ")
        assert violated is True
        assert msg == "의심 패턴 탐지: 자음/모음만 5자 이상 나열"

    def test_korean_jamo_2_chars_not_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, _msg = _check_regex("ㄱㄴ")
        assert violated is False

    def test_sql_select_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("SELECT * FROM users")
        assert violated is True
        assert msg == "의심 패턴 탐지: SQL 명령"

    def test_rm_rf_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("rm -rf /")
        assert violated is True
        assert msg == "의심 패턴 탐지: rm -rf"

    def test_anthropic_api_key_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex(
            "sk-ant-api03-abcdefghij1234567890",
        )
        assert violated is True
        assert msg == "의심 패턴 탐지: Anthropic API Key"

    def test_aws_access_key_blocked(self):
        # AKIA + 16자 uppercase/digit
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("AKIAABCDEFGHIJKLMNOP")
        assert violated is True
        assert msg == "의심 패턴 탐지: AWS Access Key"

    def test_jwt_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        )
        assert violated is True
        assert msg == "의심 패턴 탐지: JWT"

    def test_password_exposure_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("password=hunter2")
        assert violated is True
        assert msg == "의심 패턴 탐지: 비밀번호 노출"

    def test_script_injection_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("<script>alert(1)</script>")
        assert violated is True
        assert msg == "의심 패턴 탐지: 스크립트 인젝션"

    def test_normal_korean_sentence_not_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("오늘 날씨가 좋다")
        assert violated is False
        assert msg == "의심 패턴 없음"

    def test_normal_english_sentence_not_blocked(self):
        from core_secure_layer.layers.l2.l2 import _check_regex

        violated, msg = _check_regex("Hello world")
        assert violated is False
        assert msg == "의심 패턴 없음"

    def test_default_patterns_constant_exists(self):
        # 모듈 상수 _DEFAULT_PATTERNS 는 22개 튜플 리스트여야 함
        from core_secure_layer.layers.l2 import l2 as l2_module

        assert hasattr(l2_module, "_DEFAULT_PATTERNS")
        patterns = l2_module._DEFAULT_PATTERNS
        assert len(patterns) == 22
        # 각 원소는 (str, str) 튜플
        for item in patterns:
            assert isinstance(item, tuple)
            assert len(item) == 2
            assert isinstance(item[0], str)
            assert isinstance(item[1], str)


# ──────────────────────────────────────────────
# 8. (신규) 3차 _shannon_entropy 수치 검증
# ──────────────────────────────────────────────


class TestShannonEntropyFunction:
    """모듈 함수 ``_shannon_entropy`` 가 정확한 값을 내는지 검증."""

    def test_empty_string_entropy_is_zero(self):
        from core_secure_layer.layers.l2.l2 import _shannon_entropy

        assert _shannon_entropy("") == 0.0

    def test_single_char_entropy_is_zero(self):
        from core_secure_layer.layers.l2.l2 import _shannon_entropy

        assert _shannon_entropy("a") == pytest.approx(0.0)

    def test_uniform_single_symbol_entropy_is_zero(self):
        from core_secure_layer.layers.l2.l2 import _shannon_entropy

        assert _shannon_entropy("aaaa") == pytest.approx(0.0)

    def test_two_symbols_uniform_entropy_is_one(self):
        from core_secure_layer.layers.l2.l2 import _shannon_entropy

        # "ab" → 두 심볼 균등 → -2 * (0.5 * log2(0.5)) = 1.0
        assert _shannon_entropy("ab") == pytest.approx(1.0)

    def test_four_symbols_uniform_entropy_is_two(self):
        from core_secure_layer.layers.l2.l2 import _shannon_entropy

        # "abcd" → 네 심볼 균등 → log2(4) = 2.0
        assert _shannon_entropy("abcd") == pytest.approx(2.0)


# ──────────────────────────────────────────────
# 9. (신규) 3차 _check_entropy 시그니처 및 메시지 포맷
# ──────────────────────────────────────────────


class TestCheckEntropyFunction:
    """모듈 함수 ``_check_entropy`` 의 반환값 튜플 검증.

    반환 형식은 ``(violated, message, ent)`` 세쌍 튜플.
    메시지 포맷은 원본 스펙 그대로 유지한다.
    """

    def test_very_low_entropy_blocked(self):
        # "aaaa" 엔트로피 0.0 < 하한 1.5 → 차단
        from core_secure_layer.layers.l2.l2 import _check_entropy

        violated, msg, ent = _check_entropy("aaaa")
        assert violated is True
        assert ent == pytest.approx(0.0)
        # 메시지는 `엔트로피 {ent:.2f} < 하한 {low} (너무 단조로움)`
        assert "엔트로피 0.00" in msg
        assert "< 하한 1.5" in msg
        assert "너무 단조로움" in msg

    def test_normal_korean_sentence_in_range(self):
        from core_secure_layer.layers.l2.l2 import _check_entropy

        violated, msg, ent = _check_entropy("오늘 날씨가 좋다")
        assert violated is False
        assert "정상 범위" in msg
        # 엔트로피 값은 대략 2~4 정도 범위가 기대됨
        assert _DEFAULT_ENTROPY_LOW <= ent <= _DEFAULT_ENTROPY_HIGH

    def test_very_high_entropy_blocked(self):
        # 매우 다양한 64자 base64-like → 엔트로피 약 5.95
        from core_secure_layer.layers.l2.l2 import _check_entropy

        payload = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )
        violated, msg, ent = _check_entropy(payload)
        assert violated is True
        assert ent > _DEFAULT_ENTROPY_HIGH
        assert "> 상한 5.5" in msg
        assert "너무 무작위" in msg

    def test_custom_low_high_params_allow(self):
        # low=0.5, high=2.5 로 확장하면 "abcd" (ent=2.0) 허용
        from core_secure_layer.layers.l2.l2 import _check_entropy

        violated, msg, ent = _check_entropy(
            "abcd",
            low=0.5,
            high=2.5,
        )
        assert violated is False
        assert ent == pytest.approx(2.0)
        assert "정상 범위" in msg


# ──────────────────────────────────────────────
# 10. (신규) L2Layer._check 통합 — 2차 regex 차단
# ──────────────────────────────────────────────


class TestRegexBlocked:
    """1차 통과 후 2차 regex 매치로 차단되는 시나리오."""

    async def test_same_char_10_times_blocks_with_regex_tags(self, layer):
        result = await layer.check(_req("aaaaaaaaaa"))
        assert result.allowed is False
        assert result.severity == Severity.MEDIUM
        assert "동일 문자 10회 이상 반복" in result.reason
        assert result.tags == ["anomaly", "regex"]

    async def test_anthropic_key_blocked_with_regex_tags(self, layer):
        result = await layer.check(
            _req("sk-ant-api03-abcdefghij1234567890"),
        )
        assert result.allowed is False
        assert "Anthropic API Key" in result.reason
        assert result.tags == ["anomaly", "regex"]

    async def test_sql_select_blocked_with_regex_tags(self, layer):
        result = await layer.check(_req("SELECT * FROM users"))
        assert result.allowed is False
        assert "SQL 명령" in result.reason
        assert result.tags == ["anomaly", "regex"]

    async def test_no_space_50_chars_blocked_with_regex_tags(self, layer):
        # "abc" * 30 = 90자 공백 없음 → "공백 없는 50자 이상 연속" 매치
        # (entropy 보다 먼저 regex 에서 잡혀야 함)
        result = await layer.check(_req("abc" * 30))
        assert result.allowed is False
        assert "공백 없는 50자 이상 연속" in result.reason
        assert result.tags == ["anomaly", "regex"]

    async def test_password_exposure_blocked_reason_format(self, layer):
        result = await layer.check(_req("password=hunter2"))
        assert result.allowed is False
        # 메시지는 "의심 패턴 탐지: <desc>" 포맷
        assert result.reason.startswith("의심 패턴 탐지:")
        assert "비밀번호 노출" in result.reason

    async def test_regex_block_severity_is_medium(self, layer):
        result = await layer.check(_req("rm -rf /"))
        assert result.allowed is False
        assert result.severity == Severity.MEDIUM


# ──────────────────────────────────────────────
# 11. (신규) L2Layer._check 통합 — 3차 entropy 차단
# ──────────────────────────────────────────────


class TestEntropyBlocked:
    """1/2차 통과 후 3차 엔트로피 범위 이탈로 차단되는 시나리오."""

    async def test_high_entropy_blocks_when_regex_bypassed(
        self,
        layer,
        monkeypatch,
    ):
        # regex 단계를 우회(전역 모듈 함수 mock)해 3차 entropy 만 검증
        from core_secure_layer.layers.l2 import l2 as l2_module

        monkeypatch.setattr(
            l2_module,
            "_check_regex",
            lambda text, patterns=None: (False, "의심 패턴 없음"),
        )
        # 엔트로피 > 5.5 유도용 문자열
        payload = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )
        result = await layer.check(_req(payload))
        assert result.allowed is False
        assert result.severity == Severity.MEDIUM
        assert result.tags == ["anomaly", "entropy"]
        assert "너무 무작위" in result.reason
        assert "> 상한 5.5" in result.reason

    async def test_entropy_block_reason_starts_with_prefix(
        self,
        layer,
        monkeypatch,
    ):
        from core_secure_layer.layers.l2 import l2 as l2_module

        monkeypatch.setattr(
            l2_module,
            "_check_regex",
            lambda text, patterns=None: (False, "의심 패턴 없음"),
        )
        payload = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )
        result = await layer.check(_req(payload))
        assert result.reason.startswith("엔트로피")


# ──────────────────────────────────────────────
# 12. (신규) 4단계 순서 잠금 검증
# ──────────────────────────────────────────────


class TestFourStageOrdering:
    """1 → 2 → 3 → 4차 순서 보장. 앞 단계 차단 시 뒤 단계 미실행."""

    async def test_charset_violation_skips_regex_stage(
        self,
        layer,
        monkeypatch,
    ):
        # regex 가 (True, "의심 패턴 탐지: FAKE") 를 반환하도록 하더라도
        # charset 위반(이모지)은 1차에서 먼저 차단돼 regex 분기 미진입
        from core_secure_layer.layers.l2 import l2 as l2_module

        calls: list[str] = []

        def _regex_spy(text, patterns=None):
            calls.append(text)
            return True, "의심 패턴 탐지: FAKE"

        monkeypatch.setattr(
            l2_module,
            "_check_regex",
            _regex_spy,
        )
        result = await layer.check(_req("안녕 😀"))
        assert result.allowed is False
        # 1차 차단이므로 charset 태그가 달려야 한다
        assert "charset" in result.tags
        assert "disallowed_character" in result.tags
        # regex 단계는 호출되지 않아야 한다
        assert calls == []

    async def test_regex_match_skips_entropy_stage(
        self,
        layer,
        monkeypatch,
    ):
        from core_secure_layer.layers.l2 import l2 as l2_module

        entropy_calls: list[str] = []

        def _entropy_spy(text, low=1.5, high=5.5):
            entropy_calls.append(text)
            return False, "엔트로피 3.00 정상 범위", 3.0

        monkeypatch.setattr(
            l2_module,
            "_check_entropy",
            _entropy_spy,
        )
        # regex 단계에서 "rm -rf" 매치로 차단 → entropy 미호출
        result = await layer.check(_req("rm -rf /"))
        assert result.allowed is False
        assert result.tags == ["anomaly", "regex"]
        assert entropy_calls == []

    async def test_entropy_match_skips_ppl_stage(
        self,
        layer_with_ppl,
        monkeypatch,
    ):
        from core_secure_layer.layers.l2 import l2 as l2_module

        ppl_calls: list[str] = []

        def _ppl_spy(text: str) -> float:
            ppl_calls.append(text)
            return 9999.0

        monkeypatch.setattr(
            layer_with_ppl,
            "_compute_ppl",
            _ppl_spy,
        )
        # regex 는 통과시키고 entropy 만 차단되도록 강제
        monkeypatch.setattr(
            l2_module,
            "_check_regex",
            lambda text, patterns=None: (False, "의심 패턴 없음"),
        )
        monkeypatch.setattr(
            l2_module,
            "_check_entropy",
            lambda text, low=1.5, high=5.5: (
                True,
                "엔트로피 0.50 < 하한 1.5 (너무 단조로움)",
                0.5,
            ),
        )
        result = await layer_with_ppl.check(_req("무해해보이는 정상문장"))
        assert result.allowed is False
        assert result.tags == ["anomaly", "entropy"]
        # PPL 계산은 3차 차단 때문에 호출되지 않아야 한다
        assert ppl_calls == []


# ──────────────────────────────────────────────
# 13. (신규) 4단계 전부 통과 — 허용 경로
# ──────────────────────────────────────────────


class TestFourStageAllowPath:
    """네 단계 모두 통과하는 정상 입력은 허용된다."""

    async def test_normal_korean_sentence_passes_all_stages(
        self,
        layer,
    ):
        # 모델 미로드 → 4차는 자동 skip. 1~3차 통과 확인
        result = await layer.check(_req("오늘 날씨가 좋다"))
        assert result.allowed is True
        assert result.reason is None
        assert result.tags == []

    async def test_plain_english_passes_all_stages(self, layer):
        result = await layer.check(_req("Hello world"))
        assert result.allowed is True


# ──────────────────────────────────────────────
# 14. (신규) 엔트로피 파라미터 커스터마이징
# ──────────────────────────────────────────────


class TestEntropyConstructorParams:
    """``entropy_low`` / ``entropy_high`` 파라미터가 런타임에 반영되는가."""

    def test_constructor_accepts_entropy_low_high(self):
        inst = L2Layer(
            model_name="gpt2",
            ppl_threshold=_DEFAULT_THRESHOLD,
            entropy_low=0.5,
            entropy_high=7.0,
        )
        assert inst.entropy_low == 0.5
        assert inst.entropy_high == 7.0

    def test_constructor_default_entropy_low_high(self):
        inst = L2Layer(
            model_name="gpt2",
            ppl_threshold=_DEFAULT_THRESHOLD,
        )
        assert inst.entropy_low == _DEFAULT_ENTROPY_LOW
        assert inst.entropy_high == _DEFAULT_ENTROPY_HIGH

    async def test_lowered_high_blocks_normal_like_input(
        self,
        monkeypatch,
    ):
        # entropy_high=3.0 으로 낮추면 "abcd" (ent=2.0) 는 통과,
        # "abcdefghij" (ent=약 3.32) 는 차단
        from core_secure_layer.layers.l2 import l2 as l2_module

        inst = L2Layer.__new__(L2Layer)
        inst.name = "L2"
        inst.model_path = _FAKE_MODEL_PATH
        inst.ppl_threshold = _DEFAULT_THRESHOLD
        inst.entropy_low = 0.5
        inst.entropy_high = 3.0
        # regex 는 통과시킴 (10자 공백 없음이지만 50자 미만이라 미매치)
        monkeypatch.setattr(
            l2_module,
            "_check_regex",
            lambda text, patterns=None: (False, "의심 패턴 없음"),
        )
        result = await inst.check(_req("abcdefghij"))
        assert result.allowed is False
        assert result.tags == ["anomaly", "entropy"]
        assert "> 상한 3.0" in result.reason

    async def test_raised_low_still_allows_diverse_input(
        self,
        monkeypatch,
    ):
        # entropy_low=0.5 로 낮춰도 "오늘 날씨가 좋다" 는 여전히 정상 범위
        from core_secure_layer.layers.l2 import l2 as l2_module

        inst = L2Layer.__new__(L2Layer)
        inst.name = "L2"
        inst.model_path = _FAKE_MODEL_PATH
        inst.ppl_threshold = _DEFAULT_THRESHOLD
        inst.entropy_low = 0.5
        inst.entropy_high = _DEFAULT_ENTROPY_HIGH
        monkeypatch.setattr(
            l2_module,
            "_check_regex",
            lambda text, patterns=None: (False, "의심 패턴 없음"),
        )
        result = await inst.check(_req("오늘 날씨가 좋다"))
        assert result.allowed is True
