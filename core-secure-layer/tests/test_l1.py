"""L1 레이어 인코딩 탐지 재설계 테스트.

설계 문서: ``docs/l1-design.md`` (섹션 2, 4 기반).

판정 원칙: 미탐 허용, 오탐 절대 불허.

본 테스트 스위트는 다음 새 계약을 잠근다.

1. ``preprocess_text(text) -> (cleaned, should_block, detail)``
   - invisible/bidi/zero-width 제거 + NFKC 정규화
   - 제거 비율 > 10%% → 차단
2. 5개 탐지기 (``_try_base64`` / ``_try_hex`` / ``_try_unicode_escape`` /
   ``_try_html_entity`` / ``_try_url_percent``) — 각각 정규식 + 디코딩 검증
3. ``L1Layer._check()`` 게이트
   - 탐지 순서: Base64 → Hex → Unicode → HTML → URL
   - 인코딩 타입: ``base64``, ``hex``, ``unicode``, ``html``, ``url``,
     ``invisible``
   - 예외 시 fail-open
"""

import pytest

from core_secure_layer.layers.l1 import l1 as l1_module
from core_secure_layer.layers.l1.l1 import L1Layer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    Severity,
)


@pytest.fixture
def layer():
    # 레이어 인스턴스를 생성
    return L1Layer()


def _req(text):
    """주어진 텍스트로 GuardrailRequest 를 생성한다."""
    return GuardrailRequest(user_input=text)


# ──────────────────────────────────────────────
# Group A — preprocess_text 순수 함수 검증
# ──────────────────────────────────────────────


class TestPreprocessText:
    """0단계 preprocess_text 순수 함수 계약 검증."""

    def test_empty_string_no_exception(self):
        # 빈 문자열 입력 시 예외 없이 tuple 리턴 (ratio 계산에 0 처리)
        cleaned, should_block, detail = l1_module.preprocess_text("")
        assert cleaned == ""
        assert should_block is False
        assert isinstance(detail, str)

    def test_single_zwsp_allowed(self):
        # ZWSP 하나가 섞인 일반 문장 — 비율 10% 이하
        text = "Hello\u200bWorld"
        cleaned, should_block, _detail = l1_module.preprocess_text(text)
        assert cleaned == "HelloWorld"
        assert should_block is False

    def test_majority_zero_width_blocks(self):
        # 대부분이 zero-width — 비율 > 10%
        text = "\u200b" * 10 + "hi"
        cleaned, should_block, detail = l1_module.preprocess_text(text)
        assert should_block is True
        # detail 에 비율 표기가 들어있어야 함 (포맷은 유연, %만 확인)
        assert "%" in detail
        # cleaned 에 invisible 은 남아있지 않아야 함
        assert "\u200b" not in cleaned

    def test_nfkc_normalization_fullwidth(self):
        # 전각 영문 → NFKC 로 반각 영문 ("hello")
        text = "\uff48\uff45\uff4c\uff4c\uff4f"
        cleaned, should_block, _detail = l1_module.preprocess_text(text)
        assert cleaned == "hello"
        assert should_block is False

    def test_combining_mark_removed(self):
        # Mn 카테고리 (combining acute) 제거
        # "a\u0301b" → len=3, 1개(\u0301) 제거 → 비율 1/3 ≈ 33% > 10% → 차단
        text = "a\u0301b"
        cleaned, should_block, _detail = l1_module.preprocess_text(text)
        # \u0301 은 제거돼야 한다
        assert "\u0301" not in cleaned
        # 비율 33% 이므로 차단
        assert should_block is True


# ──────────────────────────────────────────────
# Group B — _try_base64 포지티브/네거티브
# ──────────────────────────────────────────────


class TestTryBase64:
    """Base64 탐지기 단위 테스트."""

    def test_valid_base64_decodes_to_hello_world(self):
        # "SGVsbG8gV29ybGQ=" → "Hello World"
        assert l1_module._try_base64("SGVsbG8gV29ybGQ=") == "Hello World"

    def test_too_short_returns_none(self):
        # 길이 8 미만 → None ("Hello" 는 5자)
        assert l1_module._try_base64("Hello") is None

    def test_decode_failure_returns_none(self):
        # "password" 는 base64 패턴 매치하나 UTF-8 decode 실패 가능성
        # + 최소한 isprintable/한글 조건을 만족하지 않아야 None
        assert l1_module._try_base64("password") is None

    def test_binary_decode_returns_none(self):
        # "DatabaseEngine" → decode 결과가 바이너리 쓰레기 → None
        assert l1_module._try_base64("DatabaseEngine") is None


# ──────────────────────────────────────────────
# Group B — _try_hex 포지티브/네거티브
# ──────────────────────────────────────────────


class TestTryHex:
    """Hex escape 탐지기 단위 테스트."""

    def test_three_hex_escapes_decoded(self):
        # "\\x3C\\x73\\x63" → decoded != 원본
        decoded = l1_module._try_hex("\\x3C\\x73\\x63")
        assert decoded is not None
        assert decoded != "\\x3C\\x73\\x63"

    def test_single_hex_escape_returns_none(self):
        # 1회만 존재 → 정규식 {3,} 매치 실패
        assert l1_module._try_hex("\\x3C") is None

    def test_plain_text_returns_none(self):
        # 일반 텍스트 → None
        assert l1_module._try_hex("normal text") is None


# ──────────────────────────────────────────────
# Group B — _try_unicode_escape 포지티브/네거티브
# ──────────────────────────────────────────────


class TestTryUnicodeEscape:
    """Unicode escape 탐지기 단위 테스트."""

    def test_three_unicode_escapes_decoded_to_abc(self):
        # "\\u0041\\u0042\\u0043" → "ABC"
        assert l1_module._try_unicode_escape("\\u0041\\u0042\\u0043") == "ABC"

    def test_single_unicode_escape_returns_none(self):
        # 1회만 존재 → 매치 실패
        assert l1_module._try_unicode_escape("\\u0041") is None


# ──────────────────────────────────────────────
# Group B — _try_html_entity 포지티브/네거티브
# ──────────────────────────────────────────────


class TestTryHtmlEntity:
    """HTML entity 탐지기 단위 테스트."""

    def test_three_numeric_entities_decoded(self):
        # "&#65;&#66;&#67;" → "ABC"
        decoded = l1_module._try_html_entity("&#65;&#66;&#67;")
        assert decoded == "ABC"

    def test_single_named_entity_returns_none(self):
        # "&amp;" 단일 — 정규식 {3,} 매치 실패
        assert l1_module._try_html_entity("&amp;") is None


# ──────────────────────────────────────────────
# Group B — _try_url_percent 포지티브/네거티브
# ──────────────────────────────────────────────


class TestTryUrlPercent:
    """URL percent encoding 탐지기 단위 테스트."""

    def test_three_percent_spaces_decoded(self):
        # "%20%20%20" → "   " (공백 3개)
        decoded = l1_module._try_url_percent("%20%20%20")
        assert decoded == "   "

    def test_hundred_percent_returns_none(self):
        # "100%" — %XX 패턴 아님 → None
        assert l1_module._try_url_percent("100%") is None

    def test_single_percent_xx_returns_none(self):
        # 단일 %XX ("50%2F50") → 2회 연속 미만 → None
        assert l1_module._try_url_percent("50%2F50") is None


# ──────────────────────────────────────────────
# Group C — L1Layer._check 통합 테스트 (허용)
# ──────────────────────────────────────────────


class TestAllowedGoldenPath:
    """정상 입력이 허용되는 통합 시나리오."""

    async def test_empty_string(self, layer):
        # 빈 문자열은 허용
        result = await layer.check(_req(""))
        assert result.allowed is True
        assert result.name == "L1"
        assert result.reason is None

    async def test_plain_english(self, layer):
        # "Hello world" — 공백 때문에 Base64 전체 매치 실패
        result = await layer.check(_req("Hello world"))
        assert result.allowed is True

    async def test_plain_korean(self, layer):
        # 한글 문장은 허용
        result = await layer.check(_req("안녕하세요 반갑습니다"))
        assert result.allowed is True

    async def test_short_word_under_eight(self, layer):
        # "Hello" — 5자 < 8 → Base64 컷, 다른 것도 매치 없음
        result = await layer.check(_req("Hello"))
        assert result.allowed is True

    async def test_password_allowed(self, layer):
        # "password" — decode 실패 → 허용
        result = await layer.check(_req("password"))
        assert result.allowed is True

    async def test_database_engine_allowed(self, layer):
        # "DatabaseEngine" — 바이너리 쓰레기 → 허용
        result = await layer.check(_req("DatabaseEngine"))
        assert result.allowed is True

    async def test_percent_without_encoding(self, layer):
        # "100%" 처럼 %XX 패턴 아님 → 허용
        result = await layer.check(_req("100%"))
        assert result.allowed is True

    async def test_single_percent_xx_allowed(self, layer):
        # 단일 %XX — 이전 구현 차단 → 새 계약에서는 허용 (미탐 허용)
        result = await layer.check(_req("50%2F50"))
        assert result.allowed is True

    async def test_single_hex_escape_allowed(self, layer):
        # "\\x41" 1회 → {3,} 매치 실패 → 허용
        result = await layer.check(_req("\\x41"))
        assert result.allowed is True

    async def test_single_zwsp_allowed(self, layer):
        # ZWSP 1개 섞인 일반 문자열 — 비율 10% 이하 → 허용
        result = await layer.check(_req("Hello\u200bWorld"))
        assert result.allowed is True

    async def test_base64_non_utf8_decode_allowed(self, layer):
        # "/////w==" → 디코딩 결과가 유효 UTF-8 아님 → 허용
        result = await layer.check(_req("/////w=="))
        assert result.allowed is True

    async def test_only_whitespace(self, layer):
        # 공백만 있는 입력은 허용
        result = await layer.check(_req("   "))
        assert result.allowed is True


# ──────────────────────────────────────────────
# Group C — L1Layer._check 통합 테스트 (차단)
# ──────────────────────────────────────────────


class TestBlockedGoldenPath:
    """명확한 인코딩이 차단되는 통합 시나리오."""

    async def test_base64_block(self, layer):
        # Base64 차단 — reason 에 base64 + tags = [encoding, base64]
        result = await layer.check(_req("SGVsbG8gV29ybGQ="))
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "base64" in result.reason.lower()
        assert "encoding detected at position" in result.reason
        assert result.tags == ["encoding", "base64"]

    async def test_hex_block(self, layer):
        # Hex 3회 연속 → 차단
        result = await layer.check(_req("\\x3C\\x73\\x63"))
        assert result.allowed is False
        assert "hex" in result.reason.lower()
        assert "encoding detected at position" in result.reason
        assert result.tags == ["encoding", "hex"]

    async def test_unicode_escape_block(self, layer):
        # \uXXXX 3회 연속 → 차단, 태그는 unicode
        result = await layer.check(_req("\\u0041\\u0042\\u0043"))
        assert result.allowed is False
        assert "unicode" in result.reason.lower()
        assert "encoding detected at position" in result.reason
        assert result.tags == ["encoding", "unicode"]

    async def test_html_entity_block(self, layer):
        # HTML entity 3회 연속 → 차단
        result = await layer.check(_req("&#65;&#66;&#67;"))
        assert result.allowed is False
        assert "html" in result.reason.lower()
        assert "encoding detected at position" in result.reason
        assert result.tags == ["encoding", "html"]

    async def test_url_percent_block(self, layer):
        # %XX 2회 이상 연속 → 차단
        result = await layer.check(_req("%20%20%20"))
        assert result.allowed is False
        assert "url" in result.reason.lower()
        assert "encoding detected at position" in result.reason
        assert result.tags == ["encoding", "url"]

    async def test_invisible_block(self, layer):
        # 투명 문자 비율 > 10% → invisible 차단
        text = "\u200b" * 10 + "hi"
        result = await layer.check(_req(text))
        assert result.allowed is False
        assert "invisible" in result.reason.lower()
        assert "position 0" in result.reason
        assert result.tags == ["encoding", "invisible"]


# ──────────────────────────────────────────────
# Group D — 탐지 순서 확인
# ──────────────────────────────────────────────


class TestDetectionOrder:
    """탐지 순서(Base64 → Hex → Unicode → HTML → URL) 잠금."""

    async def test_base64_fires_before_hex(self, layer, monkeypatch):
        # 두 탐지기 모두 매치 가능하면 Base64 가 먼저 실행돼야 한다
        # monkeypatch 로 Base64 와 Hex 탐지기가 모두 "탐지" 를 리턴하게 해서
        # 순서만 잠근다.
        monkeypatch.setattr(
            l1_module,
            "_try_base64",
            lambda _text: "FAKE_BASE64_DECODED",
        )
        monkeypatch.setattr(
            l1_module,
            "_try_hex",
            lambda _text: "FAKE_HEX_DECODED",
        )
        result = await layer.check(_req("anything"))
        assert result.allowed is False
        # Base64 가 먼저 잡혔어야 함
        assert "base64" in result.reason.lower()
        assert result.tags == ["encoding", "base64"]

    async def test_hex_fires_before_unicode(self, layer, monkeypatch):
        # Base64 는 허용, Hex 와 Unicode 둘 다 탐지 시 Hex 가 먼저
        monkeypatch.setattr(l1_module, "_try_base64", lambda _t: None)
        monkeypatch.setattr(
            l1_module,
            "_try_hex",
            lambda _t: "FAKE_HEX",
        )
        monkeypatch.setattr(
            l1_module,
            "_try_unicode_escape",
            lambda _t: "FAKE_UNICODE",
        )
        result = await layer.check(_req("anything"))
        assert result.allowed is False
        assert "hex" in result.reason.lower()
        assert result.tags == ["encoding", "hex"]

    async def test_unicode_fires_before_html(self, layer, monkeypatch):
        # Base64/Hex 허용, Unicode 와 HTML 둘 다 탐지 시 Unicode 가 먼저
        monkeypatch.setattr(l1_module, "_try_base64", lambda _t: None)
        monkeypatch.setattr(l1_module, "_try_hex", lambda _t: None)
        monkeypatch.setattr(
            l1_module,
            "_try_unicode_escape",
            lambda _t: "FAKE_UNI",
        )
        monkeypatch.setattr(
            l1_module,
            "_try_html_entity",
            lambda _t: "FAKE_HTML",
        )
        result = await layer.check(_req("anything"))
        assert result.allowed is False
        assert "unicode" in result.reason.lower()
        assert result.tags == ["encoding", "unicode"]

    async def test_html_fires_before_url(self, layer, monkeypatch):
        # Base64/Hex/Unicode 허용, HTML 과 URL 둘 다 탐지 시 HTML 이 먼저
        monkeypatch.setattr(l1_module, "_try_base64", lambda _t: None)
        monkeypatch.setattr(l1_module, "_try_hex", lambda _t: None)
        monkeypatch.setattr(
            l1_module,
            "_try_unicode_escape",
            lambda _t: None,
        )
        monkeypatch.setattr(
            l1_module,
            "_try_html_entity",
            lambda _t: "FAKE_HTML",
        )
        monkeypatch.setattr(
            l1_module,
            "_try_url_percent",
            lambda _t: "FAKE_URL",
        )
        result = await layer.check(_req("anything"))
        assert result.allowed is False
        assert "html" in result.reason.lower()
        assert result.tags == ["encoding", "html"]


# ──────────────────────────────────────────────
# LayerResult 형태 검증
# ──────────────────────────────────────────────


class TestLayerResultShape:
    """LayerResult 필드 규격 검증."""

    async def test_allowed_result_shape(self, layer):
        result = await layer.check(_req("normal text"))
        assert result.name == "L1"
        assert result.allowed is True
        assert result.reason is None
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0
        assert result.tags == []
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_blocked_result_shape(self, layer):
        # 확실한 차단 케이스 (Base64)
        result = await layer.check(_req("SGVsbG8gV29ybGQ="))
        assert result.name == "L1"
        assert result.allowed is False
        assert result.reason is not None
        assert isinstance(result.reason, str)
        assert result.severity == Severity.HIGH
        assert result.confidence == 0.0
        assert isinstance(result.tags, list)
        assert len(result.tags) == 2
        assert result.tags[0] == "encoding"
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_reason_format_contains_position(self, layer):
        # reason 포맷: "{type} encoding detected at position {N}"
        result = await layer.check(_req("%20%20%20"))
        assert result.allowed is False
        assert "encoding detected at position" in result.reason
        parts = result.reason.split("position ")
        assert len(parts) == 2
        assert parts[1].strip().isdigit()


# ──────────────────────────────────────────────
# 예외 시 fail-open 검증
# ──────────────────────────────────────────────


class TestFailOpen:
    """예외 발생 시 fail-open(허용) 원칙 검증."""

    async def test_none_metadata_allowed(self, layer):
        # metadata 가 None 이어도 정상 동작
        req = GuardrailRequest(user_input="hello", metadata=None)
        result = await layer.check(req)
        assert result.allowed is True

    async def test_preprocess_exception_allows(self, layer, monkeypatch):
        # preprocess_text 가 예외를 던져도 fail-open
        def _boom(_text):
            msg = "boom"
            raise RuntimeError(msg)

        monkeypatch.setattr(l1_module, "preprocess_text", _boom)
        result = await layer.check(_req("anything"))
        assert result.allowed is True

    async def test_base64_detector_exception_allows(self, layer, monkeypatch):
        # Base64 탐지기가 터져도 fail-open
        def _boom(_text):
            msg = "boom"
            raise RuntimeError(msg)

        monkeypatch.setattr(l1_module, "_try_base64", _boom)
        result = await layer.check(_req("SGVsbG8gV29ybGQ="))
        assert result.allowed is True

    async def test_url_detector_exception_allows(self, layer, monkeypatch):
        # URL 탐지기가 터져도 fail-open — 앞 4개 탐지기는 None 리턴하게 고정
        def _boom(_text):
            msg = "boom"
            raise RuntimeError(msg)

        monkeypatch.setattr(l1_module, "_try_base64", lambda _t: None)
        monkeypatch.setattr(l1_module, "_try_hex", lambda _t: None)
        monkeypatch.setattr(
            l1_module,
            "_try_unicode_escape",
            lambda _t: None,
        )
        monkeypatch.setattr(l1_module, "_try_html_entity", lambda _t: None)
        monkeypatch.setattr(l1_module, "_try_url_percent", _boom)
        result = await layer.check(_req("%20%20%20"))
        assert result.allowed is True
