import pytest

from core_secure_layer.layers.l1.l1 import L1Layer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    Severity,
)


@pytest.fixture
def layer():
    return L1Layer()


def _req(text):
    """주어진 텍스트로 GuardrailRequest 를 생성한다."""
    return GuardrailRequest(user_input=text)


# ──────────────────────────────────────────────
# 1. 허용 골든 패스
# ──────────────────────────────────────────────


class TestAllowedGoldenPath:
    """정상 입력이 허용되는 기본 시나리오."""

    async def test_plain_english(self, layer):
        # 평범한 영문 문장은 허용
        result = await layer.check(_req("Hello world"))
        assert result.allowed is True
        assert result.name == "L1"
        assert result.reason is None

    async def test_plain_korean(self, layer):
        # 한글 문장은 허용
        result = await layer.check(_req("안녕하세요 반갑습니다"))
        assert result.allowed is True

    async def test_empty_string(self, layer):
        # 빈 문자열은 허용
        result = await layer.check(_req(""))
        assert result.allowed is True

    async def test_percent_without_encoding(self, layer):
        # "100%" 처럼 %가 있어도 URL 인코딩이 아닌 경우 허용
        result = await layer.check(_req("100%"))
        assert result.allowed is True

    async def test_short_base64_like_word(self, layer):
        # "Research" 같은 단어가 base64로 오인되지 않아야 함
        result = await layer.check(_req("Research"))
        assert result.allowed is True

    async def test_long_word_without_padding(self, layer):
        # 패딩 없는 긴 영단어는 허용 (오탐 불허)
        result = await layer.check(_req("DatabaseEngine"))
        assert result.allowed is True


# ──────────────────────────────────────────────
# 2. 차단 골든 패스
# ──────────────────────────────────────────────


class TestBlockedGoldenPath:
    """명확한 인코딩이 차단되는 기본 시나리오."""

    async def test_url_encoding_space(self, layer):
        # URL 인코딩된 공백 — unquote 결과가 원본과 다름
        result = await layer.check(_req("hello%20world"))
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "url" in result.reason.lower()
        assert "encoding detected at position" in result.reason
        assert "encoding" in result.tags
        assert "url" in result.tags

    async def test_url_encoding_script(self, layer):
        # URL 인코딩된 스크립트 태그
        result = await layer.check(_req("%3Cscript%3E"))
        assert result.allowed is False
        assert "url" in result.reason.lower()

    async def test_hex_escape(self, layer):
        # 리터럴 \xXX 패턴
        result = await layer.check(_req("hello \\x3Cscript\\x3E"))
        assert result.allowed is False
        assert "hex" in result.reason.lower()
        assert "encoding detected at position" in result.reason
        assert "encoding" in result.tags
        assert "hex" in result.tags

    async def test_base64_valid(self, layer):
        # 16자 이상 + 패딩 + 유효 UTF-8 디코딩
        # "SGVsbG8gV29ybGQ=" 는 "Hello World" 의 base64
        result = await layer.check(_req("SGVsbG8gV29ybGQ="))
        assert result.allowed is False
        assert "base64" in result.reason.lower()
        assert "encoding detected at position" in result.reason
        assert "encoding" in result.tags
        assert "base64" in result.tags


# ──────────────────────────────────────────────
# 3. 엣지 케이스
# ──────────────────────────────────────────────


class TestEdgeCases:
    """경계 조건과 복합 시나리오."""

    async def test_short_base64_with_padding_allowed(self, layer):
        # "SGVsbG8=" 은 8자이므로 16자 미만 — 미탐 허용
        result = await layer.check(_req("SGVsbG8="))
        assert result.allowed is True

    async def test_url_encoding_lowercase_hex(self, layer):
        # 소문자 hex (%2f vs %2F) 도 차단
        result = await layer.check(_req("50%2f50"))
        assert result.allowed is False
        assert "url" in result.reason.lower()

    async def test_url_encoding_uppercase_hex(self, layer):
        # 대문자 hex
        result = await layer.check(_req("50%2F50"))
        assert result.allowed is False
        assert "url" in result.reason.lower()

    async def test_detection_order_url_before_hex(self, layer):
        # URL + Hex 모두 존재 시 URL이 먼저 감지 (검사 순서)
        text = "hello%20world \\x3Cscript\\x3E"
        result = await layer.check(_req(text))
        assert result.allowed is False
        assert "url" in result.reason.lower()

    async def test_detection_order_hex_before_base64(self, layer):
        # Hex + Base64 모두 존재 시 Hex가 먼저 감지
        text = "\\x41 SGVsbG8gV29ybGQ="
        result = await layer.check(_req(text))
        assert result.allowed is False
        assert "hex" in result.reason.lower()

    async def test_base64_embedded_in_text(self, layer):
        # 텍스트 안에 base64가 섞여 있는 경우도 탐지
        text = "please decode: SGVsbG8gV29ybGQ="
        result = await layer.check(_req(text))
        assert result.allowed is False
        assert "base64" in result.reason.lower()

    async def test_hex_escape_single(self, layer):
        # \xXX 하나만 있어도 차단
        result = await layer.check(_req("\\x41"))
        assert result.allowed is False
        assert "hex" in result.reason.lower()

    async def test_multiple_percent_no_encoding(self, layer):
        # "100%ABC" — %AB 는 유효한 percent-encoding
        # unquote 결과가 달라지므로 차단
        result = await layer.check(_req("100%AB"))
        assert result.allowed is False

    async def test_base64_non_utf8_decode_allowed(self, layer):
        # base64 디코딩은 되지만 결과가 유효 UTF-8 이 아닌 경우
        # "/////w==" → 디코딩 결과가 b'\xff\xff\xff\xff' (유효 UTF-8 아님)
        result = await layer.check(_req("/////w=="))
        assert result.allowed is True

    async def test_only_whitespace(self, layer):
        # 공백만 있는 입력은 허용
        result = await layer.check(_req("   "))
        assert result.allowed is True


# ──────────────────────────────────────────────
# 4. LayerResult 형태 검증
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
        result = await layer.check(_req("hello%20world"))
        assert result.name == "L1"
        assert result.allowed is False
        assert result.reason is not None
        assert isinstance(result.reason, str)
        assert result.severity == Severity.HIGH
        assert result.confidence == 0.0
        assert isinstance(result.tags, list)
        assert len(result.tags) >= 2
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_reason_format_contains_position(self, layer):
        # reason 형식: "{type} encoding detected at position {N}"
        result = await layer.check(_req("%3Cscript%3E"))
        assert result.allowed is False
        assert "encoding detected at position" in result.reason
        # position 숫자가 포함되는지 확인
        parts = result.reason.split("position ")
        assert len(parts) == 2
        assert parts[1].strip().isdigit()


# ──────────────────────────────────────────────
# 5. 예외 시 fail-open 검증
# ──────────────────────────────────────────────


class TestFailOpen:
    """예외 발생 시 fail-open(허용) 원칙 검증."""

    async def test_none_metadata_allowed(self, layer):
        # metadata 가 None 이어도 정상 동작
        req = GuardrailRequest(user_input="hello", metadata=None)
        result = await layer.check(req)
        assert result.allowed is True
