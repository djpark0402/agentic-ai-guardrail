"""L2 가드레일 레이어 — 혼란도(perplexity) 기반 비정상 입력 탐지."""

import logging
import math
import pathlib
import re
from collections import Counter
from typing import Any

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

logger = logging.getLogger(__name__)

# 기본 모델 베이스 경로: l2/model/ 디렉토리
_MODEL_BASE_DIR: pathlib.Path = (
    pathlib.Path(__file__).resolve().parent / "model"
)

# 1차 필터: 허용 문자셋 정규식
# 한국어(가-힣, ㄱ-ㅎ, ㅏ-ㅣ) + 영어 + 숫자 + 공백/탭/줄바꿈
# + 기본 구두점 + 수학/기호
_ALLOWED_RE: re.Pattern[str] = re.compile(
    r"^[가-힣ㄱ-ㅎㅏ-ㅣA-Za-z0-9"
    r"\s"
    r".,!?:;'\"\-()\[\]{}"
    r"@#$%^&*+=~/\\|<>_"
    r"]*$",
)

# 2차 필터: 의심 패턴 정규식 목록 (정규식, 한글 설명)
# 계약상 `len(_DEFAULT_PATTERNS) == 22` 를 고정. 설계 문서의 24개 원본에서
# 단독 위협성이 낮고 다른 패턴과 문맥 중복이 큰 document.cookie / nmap scan
# 두 항목을 제외하고 22개로 확정한다.
_DEFAULT_PATTERNS: tuple[tuple[str, str], ...] = (
    # (A) 텍스트 구조 이상
    (r"(.)\1{9,}", "동일 문자 10회 이상 반복"),
    # 공백 허용 형태(`\s*`) 는 "ㄱㄴㄷㄹ ㅏㅓㅗㅜ" 같은 정상 자모 나열을
    # 오탐하므로 회귀 방지 차원에서 연속 자모 5자 이상으로 제한한다.
    (r"[ㄱ-ㅎㅏ-ㅣ]{5,}", "자음/모음만 5자 이상 나열"),
    (r"[\x00-\x08\x0b\x0c\x0e-\x1f]{2,}", "제어 문자 다수 포함"),
    (r"(?:[^\s]{50,})", "공백 없는 50자 이상 연속"),
    # (B) 위험 명령어 / 코드 인젝션
    (r"(?i)rm\s+-rf", "rm -rf"),
    (r"(?i)DROP\s+TABLE", "DROP TABLE"),
    (r"(?i)os\.system\s*\(", "os.system"),
    (r"(?i)exec\s*\(|eval\s*\(", "exec/eval"),
    (r"(?i)subprocess\.|Popen\s*\(", "subprocess"),
    (
        r"(?i)SELECT\s+.+FROM|INSERT\s+INTO|UPDATE\s+.+SET|DELETE\s+FROM",
        "SQL 명령",
    ),
    (r"(?i)<script[\s>]|javascript:", "스크립트 인젝션"),
    (
        r"(?i)\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}"
        r"|%[0-9a-f]{2}.*%[0-9a-f]{2}",
        "인코딩 페이로드",
    ),
    # (C) API 키 / 시크릿
    (
        r"(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key"
        r"|access[_-]?key|auth[_-]?token)\s*[=:]\s*\S+",
        "API 키 노출",
    ),
    (r"sk-ant-api03-[a-zA-Z0-9_-]{20,}", "Anthropic API Key"),
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
    (r"github_pat_[a-zA-Z0-9_]{20,}", "GitHub Fine-grained"),
    (r"xox[bpsa]-[a-zA-Z0-9-]{10,}", "Slack Token"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private Key"),
    (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "JWT"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+", "비밀번호 노출"),
)


def _check_regex(
    text: str,
    patterns: tuple[tuple[str, str], ...] = _DEFAULT_PATTERNS,
) -> tuple[bool, str]:
    """패턴 리스트를 순회하여 첫 매치를 보고한다.

    Args:
        text: 검사 대상 문자열.
        patterns: (정규식, 설명) 튜플 리스트.

    Returns:
        (탐지 여부, 메시지) 튜플. 매치 시 메시지는
        ``"의심 패턴 탐지: <desc>"`` 형식, 미매치 시
        ``"의심 패턴 없음"``.
    """
    for pattern, desc in patterns:
        if re.search(pattern, text):
            return True, f"의심 패턴 탐지: {desc}"
    return False, "의심 패턴 없음"


def _shannon_entropy(text: str) -> float:
    """문자 분포 Shannon 엔트로피를 계산한다.

    Args:
        text: 검사 대상 문자열.

    Returns:
        엔트로피 값. 빈 문자열은 0.0.
    """
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    # `+ 0.0` 은 단일 심볼 케이스의 음의 영(-0.0) 을 양의 영으로 정규화한다.
    entropy = -sum(
        (c / length) * math.log2(c / length) for c in counter.values()
    )
    return entropy + 0.0


def _check_entropy(
    text: str,
    low: float = 1.5,
    high: float = 5.5,
) -> tuple[bool, str, float]:
    """엔트로피 범위 밖이면 차단 신호를 반환한다.

    Args:
        text: 검사 대상 문자열.
        low: 엔트로피 하한. 미만이면 "너무 단조로움".
        high: 엔트로피 상한. 초과면 "너무 무작위".

    Returns:
        (탐지 여부, 메시지, 엔트로피 값) 세쌍 튜플.
    """
    ent = _shannon_entropy(text)
    if ent < low:
        return (
            True,
            f"엔트로피 {ent:.2f} < 하한 {low} (너무 단조로움)",
            ent,
        )
    if ent > high:
        return (
            True,
            f"엔트로피 {ent:.2f} > 상한 {high} (너무 무작위)",
            ent,
        )
    return False, f"엔트로피 {ent:.2f} 정상 범위", ent


class L2Layer(BaseLayer):
    """혼란도 탐지 가드레일 레이어.

    4단계 필터링으로 비정상 입력을 차단한다.
    1차: 문자셋 허용 목록 기반 차단.
    2차: 의심 regex 패턴 매치 차단.
    3차: Shannon 엔트로피 범위 이탈 차단.
    4차: perplexity(PPL) 기반 이상 탐지.
    모델 미로드 시 4차는 허용으로 처리한다.
    """

    name: str = "L2"

    def __init__(
        self,
        model_name: str = "gpt2",
        ppl_threshold: float = 600.0,
        entropy_low: float = 1.5,
        entropy_high: float = 5.5,
    ) -> None:
        """L2 레이어를 초기화한다.

        Args:
            model_name: 모델 폴더명 (``"gpt2"`` 또는
                ``"kogpt2"``).
            ppl_threshold: 4차 PPL 차단 임계값.
            entropy_low: 3차 엔트로피 하한 (기본 1.5).
            entropy_high: 3차 엔트로피 상한 (기본 5.5).
        """
        self.model_path = str(
            _MODEL_BASE_DIR / model_name,
        )
        self.ppl_threshold = ppl_threshold
        self.entropy_low = entropy_low
        self.entropy_high = entropy_high
        self._model: Any = None
        self._tokenizer: Any = None
        self._model_loaded = False
        self._load_model()

    def _load_model(self) -> None:
        """Transformers 모델을 로드한다.

        로드 실패 시 경고만 남기고 4차 필터링은
        비활성 상태로 동작한다 (허용 처리).
        """
        try:
            import transformers

            transformers.logging.set_verbosity_error()

            self._tokenizer = transformers.AutoTokenizer.from_pretrained(
                self.model_path,
            )
            import torch

            self._device = "mps" if torch.backends.mps.is_available() else "cpu"
            self._model = transformers.AutoModelForCausalLM.from_pretrained(
                self.model_path,
            ).to(self._device)
            self._model.eval()
            self._model_loaded = True
        except Exception:
            logger.warning(
                "GPT-2 모델 로드 실패: %s — 4차 필터링 비활성",
                self.model_path,
            )
            self._model_loaded = False

    def _compute_ppl(self, text: str) -> float:
        """GPT-2 모델로 PPL을 계산한다.

        Args:
            text: 분석 대상 텍스트.

        Returns:
            계산된 perplexity 값.
        """
        import warnings

        import torch

        device = getattr(self, "_device", "cpu")
        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with warnings.catch_warnings(), torch.no_grad():
            warnings.filterwarnings(
                "ignore",
                message=".*loss_type.*",
            )
            outputs = self._model(
                **inputs,
                labels=inputs["input_ids"],
            )
        return float(torch.exp(outputs.loss).item())

    async def _check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """L2 검사를 실행한다.

        1차 문자셋 → 2차 regex → 3차 엔트로피 → 4차 PPL
        순서로 순차 검사. 어느 단계든 예외는 fail-open.

        Args:
            request: 가드레일 요청 객체.

        Returns:
            레이어의 검사 결과.
        """
        try:
            return self._inspect(request.user_input)
        except Exception:
            return self._allow()

    def _inspect(self, text: str) -> LayerResult:
        """입력 텍스트를 순차 검사한다.

        Args:
            text: 검사할 원본 입력 문자열.

        Returns:
            검사 결과 LayerResult.
        """
        # 빈 문자열 / 공백만 → 허용
        if not text or not text.strip():
            return self._allow()

        # 1차: 문자셋 허용 목록 검사
        if not _ALLOWED_RE.match(text):
            return self._block_charset(text)

        # 2차: regex 패턴 검사
        # monkeypatch 로 교체 가능하도록 모듈 글로벌 이름을 그대로 참조한다.
        violated, message = _check_regex(text)
        if violated:
            return self._block_regex(message)

        # 3차: 엔트로피 범위 검사
        violated, message, _ent = _check_entropy(
            text,
            self.entropy_low,
            self.entropy_high,
        )
        if violated:
            return self._block_entropy(message)

        # 4차: PPL 검사 (모델 미로드 시 허용)
        if not getattr(self, "_model_loaded", False):
            return self._allow()

        ppl = self._compute_ppl(text)
        if ppl > self.ppl_threshold:
            return self._block_ppl(ppl)

        return self._allow()

    def _block_charset(self, text: str) -> LayerResult:
        """1차 문자셋 위반으로 차단한다.

        Args:
            text: 비허용 문자가 포함된 입력 문자열.

        Returns:
            차단 상태의 LayerResult.
        """
        for i, ch in enumerate(text):
            if not _ALLOWED_RE.match(ch):
                reason = (
                    f"disallowed character detected at position {i}: '{ch}'"
                )
                return LayerResult(
                    name=self.name,
                    allowed=False,
                    reason=reason,
                    severity=Severity.MEDIUM,
                    tags=[
                        "charset",
                        "disallowed_character",
                    ],
                )
        return self._allow()

    def _block_regex(self, message: str) -> LayerResult:
        """2차 regex 패턴 매치로 차단한다.

        Args:
            message: ``"의심 패턴 탐지: <desc>"`` 형식 메시지.

        Returns:
            차단 상태의 LayerResult.
        """
        return LayerResult(
            name=self.name,
            allowed=False,
            reason=message,
            severity=Severity.MEDIUM,
            tags=["anomaly", "regex"],
        )

    def _block_entropy(self, message: str) -> LayerResult:
        """3차 엔트로피 범위 이탈로 차단한다.

        Args:
            message: ``"엔트로피 ... (너무 단조로움|너무 무작위)"``
                형식 메시지.

        Returns:
            차단 상태의 LayerResult.
        """
        return LayerResult(
            name=self.name,
            allowed=False,
            reason=message,
            severity=Severity.MEDIUM,
            tags=["anomaly", "entropy"],
        )

    def _block_ppl(self, ppl: float) -> LayerResult:
        """4차 PPL 초과로 차단한다.

        Args:
            ppl: 계산된 perplexity 값.

        Returns:
            차단 상태의 LayerResult.
        """
        reason = (
            f"high perplexity: {ppl:.1f} (threshold: {self.ppl_threshold:.1f})"
        )
        return LayerResult(
            name=self.name,
            allowed=False,
            reason=reason,
            severity=Severity.MEDIUM,
            tags=["perplexity", "anomaly"],
        )

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
