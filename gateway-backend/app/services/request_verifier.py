"""사용자 요청 검증 유틸 — 헤더 추출·timestamp·nonce·body hash.

서명(HMAC-SHA256) 자체 검증은 ADMIN 이 담당하므로 여기서는 수행하지 않는다.
게이트웨이는 timestamp skew 와 nonce 재연만 직접 막고, signature/body-hash 는
그대로 ADMIN `/api/v1/gateway/verify` 로 전달한다.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock

_HEADER_API_KEY = "x-api-key"
_HEADER_TIMESTAMP = "x-timestamp"
_HEADER_NONCE = "x-nonce"
_HEADER_SIGNATURE = "x-signature"


class HeaderVerificationError(Exception):
    """요청 헤더 검증 실패.

    사유 문자열은 사용자 응답의 `error.reason` 에 그대로 실리므로
    내부 상태(세션 id, 민감 정보 등)는 포함하지 않는다.
    """


@dataclass(frozen=True)
class VerifiedHeaders:
    """검증을 통과한(또는 skip 모드에서 읽어 들인) 4개 헤더 값.

    Attributes:
        api_key: 사용자 발급 API 키 (`X-API-Key`).
        timestamp: Unix epoch 초 문자열 (`X-Timestamp`).
        nonce: 요청 nonce (`X-Nonce`).
        signature: HMAC-SHA256 hex 서명 (`X-Signature`).
    """

    api_key: str
    timestamp: str
    nonce: str
    signature: str


def _get_header(headers: Mapping[str, str], key_lower: str) -> str | None:
    """대소문자 무관 헤더 조회 (starlette Headers 는 기본적으로 lower 사용)."""
    if hasattr(headers, "get"):
        direct = headers.get(key_lower)
        if direct is not None:
            return direct
    for k, v in headers.items():
        if k.lower() == key_lower:
            return v
    return None


def extract_headers(headers: Mapping[str, str]) -> VerifiedHeaders:
    """4개 필수 헤더를 추출해 `VerifiedHeaders` 로 묶어 반환한다.

    Args:
        headers: 대소문자 구분 없이 접근 가능한 요청 헤더 매핑.

    Returns:
        4개 헤더가 모두 비어 있지 않은 경우 `VerifiedHeaders`.

    Raises:
        HeaderVerificationError: 헤더가 누락되었거나 빈 문자열일 때.
    """
    required = {
        "X-API-Key": _HEADER_API_KEY,
        "X-Timestamp": _HEADER_TIMESTAMP,
        "X-Nonce": _HEADER_NONCE,
        "X-Signature": _HEADER_SIGNATURE,
    }
    values: dict[str, str] = {}
    for display_name, lower_key in required.items():
        value = _get_header(headers, lower_key)
        if not value:
            raise HeaderVerificationError(
                f"{display_name} 헤더가 누락되었거나 비어 있습니다"
            )
        values[display_name] = value
    return VerifiedHeaders(
        api_key=values["X-API-Key"],
        timestamp=values["X-Timestamp"],
        nonce=values["X-Nonce"],
        signature=values["X-Signature"],
    )


def verify_timestamp(
    timestamp: str,
    *,
    now: float,
    skew_sec: int,
) -> None:
    """`X-Timestamp` 값이 현재 시각과 허용 오차 이내인지 검증한다.

    Args:
        timestamp: `X-Timestamp` 헤더 문자열 (Unix epoch 초).
        now: 현재 시각(Unix epoch 초).
        skew_sec: 허용 오차(초). 보통 300 (5분).

    Raises:
        HeaderVerificationError: 정수 파싱 실패 또는 시간차 초과.
    """
    try:
        ts = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise HeaderVerificationError(
            "X-Timestamp 값을 정수로 해석할 수 없습니다"
        ) from exc
    if abs(now - ts) > skew_sec:
        raise HeaderVerificationError(
            f"X-Timestamp 시간차가 허용 범위({skew_sec}초)를 초과했습니다"
        )


class NonceStore:
    """만료 시간이 있는 in-memory nonce 저장소.

    데모 용도로 단일 프로세스 범위에서만 재연을 방지한다. 프로덕션에서는
    Redis 등 공유 저장소로 교체해야 한다.
    """

    def __init__(self, ttl_sec: int) -> None:
        """NonceStore 를 초기화한다.

        Args:
            ttl_sec: nonce 를 기억하는 시간(초). 보통 `skew_sec * 2`.
        """
        self._ttl = ttl_sec
        self._seen: dict[str, float] = {}
        self._lock = Lock()

    def _purge_expired(self, now: float) -> None:
        """만료된 nonce 를 제거한다. 호출자는 lock 을 보유해야 한다."""
        cutoff = now - self._ttl
        expired = [n for n, ts in self._seen.items() if ts < cutoff]
        for n in expired:
            del self._seen[n]

    def seen(self, nonce: str, now: float) -> bool:
        """Nonce 가 TTL 안에 기록된 적이 있는지 확인한다."""
        with self._lock:
            self._purge_expired(now)
            return nonce in self._seen

    def remember(self, nonce: str, now: float) -> None:
        """Nonce 를 현재 시각으로 기록한다."""
        with self._lock:
            self._purge_expired(now)
            self._seen[nonce] = now


def verify_and_remember_nonce(
    nonce: str,
    store: NonceStore,
    *,
    now: float,
) -> None:
    """Nonce 가 재연인지 검사하고, 신규라면 저장소에 기록한다.

    Args:
        nonce: `X-Nonce` 헤더 값.
        store: 공유 `NonceStore` 인스턴스.
        now: 현재 시각(Unix epoch 초).

    Raises:
        HeaderVerificationError: 동일 nonce 가 이미 TTL 내에 관측되었을 때.
    """
    if store.seen(nonce, now):
        raise HeaderVerificationError(
            "X-Nonce 가 이미 사용된 값입니다 (replay attack 의심)"
        )
    store.remember(nonce, now)


def body_hash_hex(body: bytes) -> str:
    """요청 body 원문의 SHA-256 hex 다이제스트(소문자 64자)를 반환한다.

    Args:
        body: 요청 body 의 원본 바이트열.

    Returns:
        `hashlib.sha256(body).hexdigest()` 결과.
    """
    return hashlib.sha256(body).hexdigest()
