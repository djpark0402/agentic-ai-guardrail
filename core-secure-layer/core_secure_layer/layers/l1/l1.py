"""L1 가드레일 레이어 — 인코딩 탐지 및 차단."""

import base64
import re
import urllib.parse
from typing import Any

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

# 리터럴 \xXX 패턴 (백슬래시 + x + hex 2자리)
_HEX_ESCAPE_RE: re.Pattern[str] = re.compile(r"\\x[0-9A-Fa-f]{2}")

# Base64 후보: 16자 이상 연속 Base64 문자 + 패딩 필수
_BASE64_CANDIDATE_RE: re.Pattern[str] = re.compile(r"[A-Za-z0-9+/]{15,}={1,2}")

# URL 인코딩 패턴 위치 탐지용 (%XX)
_PERCENT_ENCODING_RE: re.Pattern[str] = re.compile(r"%[0-9A-Fa-f]{2}")


def _detect_url_encoding(
    text: str,
) -> tuple[bool, int]:
    """URL 인코딩 여부를 탐지한다.

    Args:
        text: 검사할 입력 문자열.

    Returns:
        (탐지 여부, 첫 %XX 패턴 위치) 튜플.
    """
    decoded = urllib.parse.unquote(text)
    if decoded != text:
        match = _PERCENT_ENCODING_RE.search(text)
        pos = match.start() if match else 0
        return True, pos
    return False, -1


def _detect_hex_escape(
    text: str,
) -> tuple[bool, int]:
    """리터럴 Hex escape 패턴을 탐지한다.

    Args:
        text: 검사할 입력 문자열.

    Returns:
        (탐지 여부, 첫 패턴 위치) 튜플.
    """
    match = _HEX_ESCAPE_RE.search(text)
    if match:
        return True, match.start()
    return False, -1


def _is_valid_utf8_base64(candidate: str) -> bool:
    """Base64 후보가 유효 UTF-8로 디코딩되는지 확인한다.

    Args:
        candidate: Base64 후보 문자열.

    Returns:
        디코딩 성공 및 유효 UTF-8이면 True.
    """
    try:
        decoded_bytes = base64.b64decode(candidate)
        decoded_bytes.decode("utf-8")
    except Exception:
        return False
    return True


def _detect_base64(
    text: str,
) -> tuple[bool, int]:
    """Base64 인코딩 후보를 탐지한다.

    16자 이상 + 패딩 필수 + 디코딩 결과가 유효 UTF-8일 때만
    차단 판정.

    Args:
        text: 검사할 입력 문자열.

    Returns:
        (탐지 여부, 첫 후보 위치) 튜플.
    """
    for match in _BASE64_CANDIDATE_RE.finditer(text):
        if _is_valid_utf8_base64(match.group()):
            return True, match.start()
    return False, -1


class L1Layer(BaseLayer):
    """인코딩 탐지 가드레일 레이어.

    사용자 입력에서 URL 인코딩, Hex escape, Base64 인코딩을
    탐지하여 차단한다. 검사 순서: URL → Hex → Base64.
    예외 발생 시 fail-open(허용) 원칙을 따른다.
    """

    name: str = "L1"

    async def _check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """인코딩 탐지 검사를 실행한다.

        Args:
            request: 가드레일 요청 객체.

        Returns:
            인코딩 탐지 결과를 담은 LayerResult.
        """
        try:
            return self._inspect(request.user_input)
        except Exception:
            # fail-open: 예외 시 허용
            return self._allow()

    def _inspect(self, text: str) -> LayerResult:
        """입력 텍스트에서 인코딩 패턴을 순차 검사한다.

        Args:
            text: 검사할 원본 입력 문자열.

        Returns:
            탐지 결과 LayerResult.
        """
        # 검사 순서: URL → Hex → Base64
        _detectors: tuple[tuple[str, Any], ...] = (
            ("url", _detect_url_encoding),
            ("hex", _detect_hex_escape),
            ("base64", _detect_base64),
        )
        for enc_type, detector in _detectors:
            found, pos = detector(text)
            if found:
                return self._block(enc_type, pos)
        return self._allow()

    def _allow(self) -> LayerResult:
        """허용 결과를 생성한다.

        Returns:
            허용 상태의 LayerResult.
        """
        return LayerResult(
            name=self.name,
            allowed=True,
            confidence=1.0,
            severity=Severity.NONE,
        )

    def _block(
        self,
        encoding_type: str,
        position: int,
    ) -> LayerResult:
        """차단 결과를 생성한다.

        Args:
            encoding_type: 탐지된 인코딩 유형.
            position: 입력 내 탐지 위치.

        Returns:
            차단 상태의 LayerResult.
        """
        reason = f"{encoding_type} encoding detected at position {position}"
        return LayerResult(
            name=self.name,
            allowed=False,
            reason=reason,
            confidence=0.0,
            severity=Severity.HIGH,
            tags=["encoding", encoding_type],
        )
