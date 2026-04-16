"""L6 가드레일 레이어: 로컬 safety 모델 기반 안전성 판별."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

logger = logging.getLogger(__name__)

_MODEL_BASE_DIR: Path = Path(__file__).parent / "model"


@dataclass
class SafetyResult:
    """모델 출력 파싱 결과.

    Attributes:
        is_safe: 안전 여부.
        category: 위험 카테고리 (예: S1, O1).
    """

    is_safe: bool
    category: str | None = None


class L6Layer(BaseLayer):
    """로컬 safety 모델로 입력 안전성을 판별하는 레이어.

    Kanana-Safeguard-8B, Llama Guard 등 사전 학습된 안전성
    판별 모델의 출력을 파싱하여 safe/unsafe 를 결정한다.
    모델 미로드, 추론 예외, 파싱 실패 시 fail-open 으로 허용.
    """

    name: str = "L6"

    def __init__(
        self,
        model_name: str = "kanana-safeguard-8b",
    ) -> None:
        """L6Layer 를 초기화한다.

        Args:
            model_name: 사용할 safety 모델 이름.
        """
        self.model_name = model_name
        self._model_loaded = False

    def _predict(self, text: str) -> str | None:
        """모델 추론을 실행한다.

        실제 모델이 로드되지 않은 스켈레톤 상태에서는
        None 을 반환한다. 모델 로드 후 오버라이드된다.

        Args:
            text: 판별 대상 텍스트.

        Returns:
            모델 출력 문자열. 실패 시 None.
        """
        return None

    def _parse_output(
        self,
        raw_output: str | None,
    ) -> SafetyResult | None:
        """모델 raw 출력을 SafetyResult 로 파싱한다.

        첫 줄이 safe/unsafe 판정, 두 번째 줄이 카테고리.
        대소문자를 무시하여 파싱한다.

        Args:
            raw_output: 모델의 원시 출력 문자열.

        Returns:
            파싱된 SafetyResult. 파싱 실패 시 None.
        """
        if raw_output is None:
            return None

        lines = raw_output.strip().splitlines()
        if not lines or not lines[0].strip():
            return None

        verdict = lines[0].strip().lower()

        if verdict == "safe":
            return SafetyResult(is_safe=True)

        if verdict == "unsafe":
            category: str | None = None
            if len(lines) > 1 and lines[1].strip():
                category = lines[1].strip()
            return SafetyResult(
                is_safe=False,
                category=category,
            )

        # safe/unsafe 이외의 출력은 파싱 실패
        return None

    def _make_allowed(self) -> LayerResult:
        """허용 결과를 생성한다.

        Returns:
            허용 상태의 LayerResult.
        """
        return LayerResult(
            name=self.name,
            allowed=True,
            severity=Severity.NONE,
            confidence=1.0,
        )

    def _make_blocked(
        self,
        safety: SafetyResult,
    ) -> LayerResult:
        """차단 결과를 생성한다.

        Args:
            safety: unsafe 판정된 SafetyResult.

        Returns:
            차단 상태의 LayerResult.
        """
        if safety.category:
            reason = f"unsafe: {safety.category}"
            tags = ["safety_model", safety.category]
        else:
            reason = "unsafe content detected"
            tags = ["safety_model"]

        return LayerResult(
            name=self.name,
            allowed=False,
            reason=reason,
            severity=Severity.CRITICAL,
            confidence=0.0,
            tags=tags,
        )

    async def _check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """L6 안전성 검사를 실행한다.

        모델이 로드되지 않았거나 추론/파싱 실패 시
        fail-open 으로 허용한다. 오탐 절대 불허 원칙.

        Args:
            request: 가드레일 요청 객체.

        Returns:
            레이어의 검사 결과.
        """
        if not self._model_loaded:
            logger.info(
                "모델 미로드 상태 — fail-open 허용: %s",
                self.model_name,
            )
            return self._make_allowed()

        try:
            raw_output = self._predict(request.user_input)
        except Exception:
            logger.warning(
                "모델 추론 중 예외 발생 — fail-open 허용",
                exc_info=True,
            )
            return self._make_allowed()

        safety = self._parse_output(raw_output)

        if safety is None:
            logger.warning(
                "모델 출력 파싱 실패 — fail-open 허용: %s",
                raw_output,
            )
            return self._make_allowed()

        if safety.is_safe:
            return self._make_allowed()

        return self._make_blocked(safety)
