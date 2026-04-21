"""L1 가드레일 레이어 — 인코딩 탐지 및 정규화.

두 단계로 검사한다.

0단계 :func:`preprocess_text`
    invisible / bidi / zero-width 문자 제거 후 NFKC 정규화.
    제거 비율이 10% 를 초과하면 ``invisible`` 로 차단한다.

1단계 5개 디코더 (:func:`_try_base64`, :func:`_try_hex`,
:func:`_try_unicode_escape`, :func:`_try_html_entity`,
:func:`_try_url_percent`)
    정규식 매치 + 실제 디코딩 성공 + 결과 검증의 3단계를 모두
    통과해야 차단한다. 탐지 순서는 Base64 → Hex → Unicode →
    HTML → URL 이며, 첫 매치가 결과를 결정한다.

판정 원칙(모듈 공통): 미탐 허용, 오탐 절대 불허. 예외 발생 시
fail-open (허용).
"""

import base64
import codecs
import html
import re
import unicodedata
import urllib.parse

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

# 투명/제어 문자 제거용 정규식. Cf 카테고리 이외에도 명시적으로
# 열거해 두어 카테고리 제거만으로 누락될 수 있는 문자도 함께 제거한다.
_INVISIBLE_RE: re.Pattern[str] = re.compile(
    "["
    "\u200b-\u200f"
    "\u202a-\u202e"
    "\u2060-\u2069"
    "\u00ad\ufeff\u034f\u061c\u115f\u1160\u3164\uffa0"
    "]+"
)

# 전체 매치 기준 Base64 후보. 문장 중간 토큰이 우연히 걸리는 것을
# 막기 위해 앵커(^$) 를 둔다.
_BASE64_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9+/]{4,}={0,2}$")

# 각 인코딩 패턴이 "3회 이상 연속" (URL 은 2회 이상) 나타나야만
# 공격 페이로드로 간주한다. 자연어에서 우연히 나오기 어려운 임계.
_HEX_ESCAPE_RE: re.Pattern[str] = re.compile(r"(\\x[0-9a-fA-F]{2}){3,}")
_UNICODE_ESCAPE_RE: re.Pattern[str] = re.compile(r"(\\u[0-9a-fA-F]{4}){3,}")
_HTML_ENTITY_RE: re.Pattern[str] = re.compile(r"(&#x?[0-9a-fA-F]+;){3,}")
_URL_PERCENT_RE: re.Pattern[str] = re.compile(r"(%[0-9a-fA-F]{2}){2,}")

# 전처리에서 제거 대상이 되는 Unicode 카테고리. 각각 Format,
# Mark-Nonspacing, Mark-Enclosing 을 의미한다.
_SUSPECT_CATEGORIES: frozenset[str] = frozenset({"Cf", "Mn", "Me"})

# Base64 최소 길이. "Hello", "test" 같은 짧은 단어를 자동 제외.
_BASE64_MIN_LEN: int = 8

# 전처리 단계에서 차단으로 넘어가는 제거 비율 임계값.
_INVISIBLE_RATIO_THRESHOLD: float = 0.10

# 탐지기 디스패치 순서. 이름 기반으로 선언해 모듈 속성이 monkeypatch
# 로 교체되어도 ``_inspect`` 가 교체본을 호출하도록 한다. (Group D
# 테스트가 이 호환성을 요구한다.)
_ENCODING_CHECK_NAMES: tuple[tuple[str, str], ...] = (
    ("base64", "_try_base64"),
    ("hex", "_try_hex"),
    ("unicode", "_try_unicode_escape"),
    ("html", "_try_html_entity"),
    ("url", "_try_url_percent"),
)

# 각 인코딩 타입에서 position 계산에 사용할 정규식 매핑.
# base64 / invisible 은 position=0 으로 고정하므로 제외한다.
_POSITION_PATTERNS: dict[str, re.Pattern[str]] = {
    "hex": _HEX_ESCAPE_RE,
    "unicode": _UNICODE_ESCAPE_RE,
    "html": _HTML_ENTITY_RE,
    "url": _URL_PERCENT_RE,
}


def preprocess_text(text: str) -> tuple[str, bool, str]:
    """투명/제어 문자를 제거하고 NFKC 로 정규화한다.

    제거 비율이 :data:`_INVISIBLE_RATIO_THRESHOLD` 를 초과하면
    ``invisible`` 로 차단해야 함을 의미하는 ``should_block=True`` 를
    돌려준다.

    Args:
        text: 원본 사용자 입력.

    Returns:
        ``(cleaned, should_block, detail)`` 튜플.
        ``cleaned`` 는 정규화된 문자열, ``should_block`` 은 차단
        필요 여부, ``detail`` 은 로깅/디버깅용 한 줄 요약.
    """
    original_len = len(text)
    cleaned = _INVISIBLE_RE.sub("", text)
    cleaned = "".join(
        c for c in cleaned if unicodedata.category(c) not in _SUSPECT_CATEGORIES
    )
    cleaned = unicodedata.normalize("NFKC", cleaned)

    removed = original_len - len(cleaned)
    ratio = removed / original_len if original_len else 0.0

    if ratio > _INVISIBLE_RATIO_THRESHOLD:
        return (
            cleaned,
            True,
            f"투명/제어 문자 {removed}개 ({ratio:.0%}) 탐지",
        )
    return cleaned, False, f"투명 문자 {removed}개 제거"


def _try_base64(text: str) -> str | None:
    """Base64 인코딩 여부를 확인하고 디코딩 결과를 돌려준다.

    정규식 전체 매치 + 최소 길이 8 + UTF-8 디코딩 성공 +
    (``isprintable`` 또는 한글 포함) 을 모두 만족해야 차단 대상이다.

    Args:
        text: 검사 대상 문자열.

    Returns:
        디코딩된 문자열. 조건을 만족하지 못하면 ``None``.
    """
    clean = text.strip()
    if not _BASE64_RE.match(clean) or len(clean) < _BASE64_MIN_LEN:
        return None
    try:
        decoded = base64.b64decode(clean).decode("utf-8")
    except Exception:
        return None
    # isprintable 만으로는 한글이 걸러지므로 한글 범위도 허용한다.
    if decoded.isprintable() or any("\uac00" <= c <= "\ud7a3" for c in decoded):
        return decoded
    return None


def _try_hex(text: str) -> str | None:
    r"""``\xXX`` hex escape 시퀀스를 탐지·디코딩한다.

    3회 이상 연속될 때만 공격 페이로드로 간주한다.

    Args:
        text: 검사 대상 문자열.

    Returns:
        디코딩된 결과. 매치가 없거나 변화가 없으면 ``None``.
    """
    if not _HEX_ESCAPE_RE.search(text):
        return None
    try:
        decoded = codecs.decode(text, "unicode_escape")
    except Exception:
        return None
    return decoded if decoded != text else None


def _try_unicode_escape(text: str) -> str | None:
    r"""``\uXXXX`` unicode escape 시퀀스를 탐지·디코딩한다.

    3회 이상 연속 + 디코딩 결과가 원본과 다르고 ``isprintable`` 을
    만족할 때만 탐지로 본다.

    Args:
        text: 검사 대상 문자열.

    Returns:
        디코딩된 결과. 조건 불충족 시 ``None``.
    """
    if not _UNICODE_ESCAPE_RE.search(text):
        return None
    try:
        decoded = codecs.decode(text, "unicode_escape")
    except Exception:
        return None
    if decoded != text and decoded.isprintable():
        return decoded
    return None


def _try_html_entity(text: str) -> str | None:
    """숫자/16진수 HTML entity 연속 패턴을 탐지·디코딩한다.

    3회 이상 연속될 때만 탐지로 본다. ``&amp;`` 같은 명명된
    entity 1회 단독은 오탐 방지를 위해 제외.

    Args:
        text: 검사 대상 문자열.

    Returns:
        디코딩된 결과. 매치가 없거나 변화가 없으면 ``None``.
    """
    if not _HTML_ENTITY_RE.search(text):
        return None
    try:
        decoded = html.unescape(text)
    except Exception:
        return None
    return decoded if decoded != text else None


def _try_url_percent(text: str) -> str | None:
    """``%XX`` URL 인코딩 2회 이상 연속 패턴을 탐지·디코딩한다.

    단일 ``%XX`` 는 자연 문장에서도 발생할 수 있어 미탐으로
    허용한다.

    Args:
        text: 검사 대상 문자열.

    Returns:
        디코딩된 결과. 매치가 없거나 변화가 없으면 ``None``.
    """
    if not _URL_PERCENT_RE.search(text):
        return None
    try:
        decoded = urllib.parse.unquote(text)
    except Exception:
        return None
    return decoded if decoded != text else None


def _first_match_start(text: str, pattern: re.Pattern[str]) -> int:
    """주어진 패턴의 첫 매치 시작 위치를 반환한다.

    Args:
        text: 검사 대상 문자열.
        pattern: 위치 조회용 정규식.

    Returns:
        첫 매치의 시작 인덱스. 매치가 없으면 ``0``.
    """
    match = pattern.search(text)
    return match.start() if match else 0


class L1Layer(BaseLayer):
    """인코딩 탐지 가드레일 레이어.

    사용자 입력에 대해 전처리(invisible/제어 문자 제거 + NFKC)를
    수행한 뒤, Base64 → Hex → Unicode → HTML → URL 순으로 5개
    디코더를 실행한다. 예외 발생 시 fail-open.
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
            인코딩 탐지 결과를 담은 ``LayerResult``.
        """
        try:
            return self._inspect(request.user_input)
        except Exception:
            # fail-open: 어떤 예외라도 오탐을 만들지 않는다.
            return self._allow()

    def _inspect(self, text: str) -> LayerResult:
        """전처리 후 5개 탐지기를 순서대로 실행한다.

        Args:
            text: 검사할 원본 입력.

        Returns:
            탐지 결과 ``LayerResult``.
        """
        cleaned, should_block, _detail = preprocess_text(text)
        if should_block:
            return self._block("invisible", position=0)

        # 이름 기반 dispatch — 테스트가 ``l1_module._try_*`` 를
        # monkeypatch 로 교체해도 현재 모듈 네임스페이스에서 최신
        # 함수를 재참조해야 한다.
        module_globals = globals()
        for enc_type, fn_name in _ENCODING_CHECK_NAMES:
            fn = module_globals[fn_name]
            decoded = fn(cleaned)
            if decoded is not None:
                position = (
                    0
                    if enc_type == "base64"
                    else _first_match_start(
                        cleaned, _POSITION_PATTERNS[enc_type]
                    )
                )
                return self._block(enc_type, position)
        return self._allow()

    def _allow(self) -> LayerResult:
        """허용 결과를 생성한다.

        Returns:
            허용 상태의 ``LayerResult``.
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
            차단 상태의 ``LayerResult``.
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
