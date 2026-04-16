"""L6 가드레일 레이어: 로컬 safety 모델 기반 안전성 판별."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

    Kanana-Safeguard-8B, Llama Guard 등 사전 학습된
    안전성 판별 모델의 출력을 파싱하여 safe/unsafe 를
    결정한다. 모델 미로드, 추론 예외, 파싱 실패 시
    fail-open 으로 허용.
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
        self._model: Any = None
        self._tokenizer: Any = None
        self._model_loaded = False
        self._load_model()

    def _load_model(self) -> None:
        """Safety 모델과 토크나이저를 로드한다.

        로드 실패 시 경고만 남기고 fail-open 동작.
        """
        model_path = _MODEL_BASE_DIR / self.model_name
        if not model_path.exists():
            logger.warning(
                "모델 경로 없음: %s",
                model_path,
            )
            return
        try:
            import transformers

            transformers.logging.set_verbosity_error()
            self._tokenizer = transformers.AutoTokenizer.from_pretrained(
                str(model_path),
            )
            import torch

            self._device = "mps" if torch.backends.mps.is_available() else "cpu"
            self._model = transformers.AutoModelForCausalLM.from_pretrained(
                str(model_path),
                torch_dtype=torch.float16,
            ).to(self._device)
            self._model.eval()
            self._model_loaded = True
            logger.info(
                "Safety 모델 로드 완료: %s",
                self.model_name,
            )
        except Exception:
            logger.warning(
                "Safety 모델 로드 실패: %s",
                self.model_name,
                exc_info=True,
            )
            self._model_loaded = False

    def _predict(self, text: str) -> str | None:
        """모델 추론을 실행한다.

        Args:
            text: 판별 대상 텍스트.

        Returns:
            모델 출력 문자열. 실패 시 None.
        """
        if not self._model_loaded:
            return None

        try:
            import torch

            messages = [
                {"role": "user", "content": text},
            ]
            encoded = self._tokenizer.apply_chat_template(
                messages,
                return_tensors="pt",
                add_generation_prompt=True,
            )
            # BatchEncoding 또는 텐서 대응
            if hasattr(encoded, "input_ids"):
                input_ids = encoded.input_ids.to(
                    self._model.device,
                )
            else:
                input_ids = encoded.to(
                    self._model.device,
                )

            with torch.no_grad():
                output_ids = self._model.generate(
                    input_ids,
                    max_new_tokens=64,
                    do_sample=False,
                )
            input_len = input_ids.shape[1]
            generated = output_ids[0, input_len:]
            return self._tokenizer.decode(
                generated,
                skip_special_tokens=True,
            )
        except Exception:
            logger.warning(
                "모델 추론 실패",
                exc_info=True,
            )
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

        import re

        text = raw_output.strip().lower()
        if not text:
            return None

        # <SAFE> 또는 safe
        if "<safe>" in text or text == "safe":
            return SafetyResult(is_safe=True)

        # <UNSAFE-S4> 또는 unsafe\nS4 형태
        unsafe_match = re.search(
            r"<unsafe(?:-([^>]+))?>",
            text,
        )
        if unsafe_match:
            category = unsafe_match.group(1)
            return SafetyResult(
                is_safe=False,
                category=category.upper() if category else None,
            )

        # 줄 기반 파싱 (Llama Guard 등)
        lines = text.splitlines()
        if lines and lines[0].strip() == "unsafe":
            category_val: str | None = None
            if len(lines) > 1 and lines[1].strip():
                category_val = lines[1].strip()
            return SafetyResult(
                is_safe=False,
                category=category_val,
            )

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
        fail-open 으로 허용한다.

        Args:
            request: 가드레일 요청 객체.

        Returns:
            레이어의 검사 결과.
        """
        if not self._model_loaded:
            return self._make_allowed()

        try:
            raw_output = self._predict(
                request.user_input,
            )
        except Exception:
            logger.warning(
                "L6 추론 예외 — fail-open",
                exc_info=True,
            )
            return self._make_allowed()

        safety = self._parse_output(raw_output)

        if safety is None:
            logger.warning(
                "파싱 실패 — fail-open: %s",
                raw_output,
            )
            return self._make_allowed()

        if safety.is_safe:
            return self._make_allowed()

        return self._make_blocked(safety)
