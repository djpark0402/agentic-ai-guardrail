"""request_verifier 유틸 테스트."""

import hashlib

import pytest

from app.services.request_verifier import (
    HeaderVerificationError,
    NonceStore,
    VerifiedHeaders,
    body_hash_hex,
    extract_headers,
    verify_and_remember_nonce,
    verify_timestamp,
)

_HEADER_API_KEY = "X-API-Key"
_HEADER_TIMESTAMP = "X-Timestamp"
_HEADER_NONCE = "X-Nonce"
_HEADER_SIGNATURE = "X-Signature"


def _full_headers() -> dict[str, str]:
    """정상 케이스용 4개 헤더 딕셔너리."""
    return {
        _HEADER_API_KEY: "uak_test",
        _HEADER_TIMESTAMP: "1700000000",
        _HEADER_NONCE: "nonce-abc",
        _HEADER_SIGNATURE: "a" * 64,
    }


class TestExtractHeaders:
    def test_returns_verified_headers_when_all_present(self):
        """4개 헤더가 모두 있으면 VerifiedHeaders 를 반환한다."""
        result = extract_headers(_full_headers())
        assert isinstance(result, VerifiedHeaders)
        assert result.api_key == "uak_test"
        assert result.timestamp == "1700000000"
        assert result.nonce == "nonce-abc"
        assert result.signature == "a" * 64

    def test_is_case_insensitive(self):
        """헤더 키는 대소문자 구분 없이 인식한다."""
        headers = {
            "x-api-key": "uak_test",
            "X-TIMESTAMP": "1700000000",
            "x-NONCE": "nonce-abc",
            "x-signature": "a" * 64,
        }
        result = extract_headers(headers)
        assert result.api_key == "uak_test"

    @pytest.mark.parametrize(
        "missing_key",
        [_HEADER_API_KEY, _HEADER_TIMESTAMP, _HEADER_NONCE, _HEADER_SIGNATURE],
    )
    def test_raises_when_any_header_missing(self, missing_key):
        """필수 헤더가 하나라도 누락되면 HeaderVerificationError."""
        headers = _full_headers()
        headers.pop(missing_key)
        with pytest.raises(HeaderVerificationError) as exc_info:
            extract_headers(headers)
        assert missing_key.lower() in str(exc_info.value).lower()

    @pytest.mark.parametrize(
        "empty_key",
        [_HEADER_API_KEY, _HEADER_TIMESTAMP, _HEADER_NONCE, _HEADER_SIGNATURE],
    )
    def test_raises_when_header_is_empty_string(self, empty_key):
        """빈 문자열 헤더도 누락과 동일하게 처리."""
        headers = _full_headers()
        headers[empty_key] = ""
        with pytest.raises(HeaderVerificationError):
            extract_headers(headers)


class TestVerifyTimestamp:
    def test_passes_within_skew(self):
        """시간차가 허용 범위 이내이면 통과."""
        verify_timestamp("1000000000", now=1_000_000_060.0, skew_sec=300)

    def test_raises_when_too_old(self):
        """과거 타임스탬프가 skew 를 넘으면 실패."""
        with pytest.raises(HeaderVerificationError):
            verify_timestamp("1000000000", now=1_000_000_301.0, skew_sec=300)

    def test_raises_when_too_future(self):
        """미래 타임스탬프가 skew 를 넘으면 실패."""
        with pytest.raises(HeaderVerificationError):
            verify_timestamp("1000000301", now=1_000_000_000.0, skew_sec=300)

    def test_raises_when_not_integer(self):
        """정수로 파싱되지 않는 값은 실패."""
        with pytest.raises(HeaderVerificationError):
            verify_timestamp("abc", now=1_000_000_000.0, skew_sec=300)


class TestNonceStore:
    def test_first_nonce_passes(self):
        """처음 보는 nonce 는 통과."""
        store = NonceStore(ttl_sec=600)
        verify_and_remember_nonce("n1", store, now=100.0)

    def test_replayed_nonce_raises(self):
        """같은 nonce 가 재연되면 실패."""
        store = NonceStore(ttl_sec=600)
        verify_and_remember_nonce("n1", store, now=100.0)
        with pytest.raises(HeaderVerificationError):
            verify_and_remember_nonce("n1", store, now=150.0)

    def test_nonce_expires_after_ttl(self):
        """TTL 이후에는 같은 nonce 도 다시 통과."""
        store = NonceStore(ttl_sec=600)
        verify_and_remember_nonce("n1", store, now=100.0)
        verify_and_remember_nonce("n1", store, now=800.0)

    def test_distinct_nonces_independent(self):
        """서로 다른 nonce 는 서로 영향 없음."""
        store = NonceStore(ttl_sec=600)
        verify_and_remember_nonce("n1", store, now=100.0)
        verify_and_remember_nonce("n2", store, now=100.0)


class TestBodyHashHex:
    def test_returns_sha256_hex_lowercase(self):
        """hashlib.sha256 결과와 일치하고 소문자 hex 64자이다."""
        body = b'{"hello":"world"}'
        expected = hashlib.sha256(body).hexdigest()
        actual = body_hash_hex(body)
        assert actual == expected
        assert len(actual) == 64
        assert actual == actual.lower()

    def test_empty_body(self):
        """빈 바이트열도 유효한 해시를 반환한다."""
        expected = hashlib.sha256(b"").hexdigest()
        assert body_hash_hex(b"") == expected
