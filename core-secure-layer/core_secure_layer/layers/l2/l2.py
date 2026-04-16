"""L2 가드레일 레이어 — 혼란도(perplexity) 기반 비정상 입력 탐지."""

import logging
import re
from typing import Any

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

logger = logging.getLogger(__name__)

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


class L2Layer(BaseLayer):
    """혼란도 탐지 가드레일 레이어.

    2단계 필터링으로 비정상 입력을 차단한다.
    1차: 문자셋 허용 목록 기반 차단.
    2차: perplexity(PPL) 기반 이상 탐지.
    모델 미로드 시 2차는 허용으로 처리한다.
    """

    name: str = "L2"

    def __init__(
        self,
        model_path: str = "",
        ppl_threshold: float = 600.0,
    ) -> None:
        """L2 레이어를 초기화한다.

        Args:
            model_path: GPT-2 모델 로컬 디렉토리 경로.
            ppl_threshold: PPL 차단 임계값.
        """
        self.model_path = model_path
        self.ppl_threshold = ppl_threshold
        self._model: Any = None
        self._tokenizer: Any = None
        self._model_loaded = False
        self._load_model()

    def _load_model(self) -> None:
        """Transformers 모델을 로드한다.

        로드 실패 시 경고만 남기고 2차 필터링은
        비활성 상태로 동작한다 (허용 처리).
        """
        try:
            from transformers import (
                AutoModelForCausalLM,
                AutoTokenizer,
            )

            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_path,
            )
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
            )
            self._model.eval()
            self._model_loaded = True
        except Exception:
            logger.warning(
                "GPT-2 모델 로드 실패: %s — 2차 필터링 비활성",
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
        import torch

        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
        )
        with torch.no_grad():
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

        1차 문자셋 필터 → 2차 PPL 필터 순서로 검사.

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

        # 2차: PPL 검사 (모델 미로드 시 허용)
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

    def _block_ppl(self, ppl: float) -> LayerResult:
        """2차 PPL 초과로 차단한다.

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
