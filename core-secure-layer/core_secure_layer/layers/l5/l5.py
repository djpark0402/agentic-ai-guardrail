"""L5 가드레일 레이어: PII/민감정보 2단계 탐지.

1단계 Regex(기본 + extra_patterns)로 정형 PII를 탐지하고,
2단계 NER 모델로 PII 엔티티를 탐지한다.
PII 특화 NER 모델(이름, 주소, 전화번호 등)이 엔티티를
감지하면 즉시 차단한다.
fail-open 원칙: 모델 미로드나 예외 시 허용.
"""

import logging
import re
from pathlib import Path
from typing import Any

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

logger = logging.getLogger(__name__)

# NER 모델 기본 경로
_MODEL_BASE_DIR = Path(__file__).parent / "model"

# 기본 Regex 패턴: (패턴이름, 컴파일된 정규식)
_DEFAULT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "resident_id",
        re.compile(r"\d{6}-[1-4]\d{6}"),
    ),
    (
        "phone_number",
        re.compile(r"\d{2,3}-\d{3,4}-\d{4}"),
    ),
    (
        "email",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    ),
    (
        "openai_api_key",
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    ),
    (
        "aws_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    (
        "bearer_token",
        re.compile(r"Bearer\s+[a-zA-Z0-9._\-]+"),
    ),
)

# NER 엔티티에서 B- / I- 접두사를 제거한 레이블 매핑
# PII 특화 NER 모델은 "B-이름", "I-전화번호" 등 반환
_ENTITY_LABEL_MAP: dict[str, str] = {
    "이름": "person",
    "전화번호": "phone_number",
    "휴대전화번호": "mobile_number",
    "주민등록번호": "resident_id",
    "계좌번호": "account_number",
    "카드번호": "card_number",
    "여권번호": "passport_number",
    "운전면허번호": "driver_license",
    "전자메일": "email",
    "로그인ID": "login_id",
    "상세주소": "address",
    "우편번호": "zip_code",
    "가맹점명": "merchant",
    "결제금액": "payment_amount",
    "신용점수": "credit_score",
}


class L5Layer(BaseLayer):
    """PII/민감정보 2단계 탐지 레이어.

    1단계 Regex로 정형 PII를 빠르게 걸러내고,
    2단계 NER 모델로 엔티티 조합을 검사한다.
    """

    name: str = "L5"

    def __init__(
        self,
        model_name: str = "ner-ko",
        extra_patterns: list[str] | None = None,
    ) -> None:
        """L5Layer 초기화.

        Args:
            model_name: NER 모델 폴더명.
            extra_patterns: 추가 차단 정규식 리스트.
        """
        self.model_name = model_name
        self.extra_patterns: list[str] = (
            extra_patterns if extra_patterns is not None else []
        )
        self._ner_model: Any = self._load_ner_model(model_name)

    def _load_ner_model(self, model_name: str) -> Any:
        """NER 모델 로드를 시도한다.

        Args:
            model_name: 모델 폴더명.

        Returns:
            로드된 파이프라인 또는 None(fail-open).
        """
        model_path = _MODEL_BASE_DIR / model_name
        try:
            from transformers import (
                pipeline,
            )

            return pipeline(
                "ner",
                model=str(model_path),
                tokenizer=str(model_path),
            )
        except Exception:
            logger.debug(
                "NER 모델 로드 실패, fail-open: %s",
                model_path,
            )
            return None

    def _ner_predict(self, text: str) -> list[dict[str, Any]]:
        """NER 모델로 엔티티를 추론한다.

        Args:
            text: 분석 대상 텍스트.

        Returns:
            엔티티 리스트. 각 항목은
            {"entity", "word", "start"} 형태.
        """
        if self._ner_model is None:
            return []
        return self._ner_model(text)  # type: ignore[no-any-return]

    def _check_regex(self, text: str) -> LayerResult | None:
        """1단계: Regex 패턴으로 정형 PII를 탐지한다.

        Args:
            text: 검사 대상 텍스트.

        Returns:
            차단 결과 또는 None(매칭 없음).
        """
        # 기본 패턴 검사
        for pii_type, pattern in _DEFAULT_PATTERNS:
            match = pattern.search(text)
            if match:
                return LayerResult(
                    name=self.name,
                    allowed=False,
                    reason=(
                        f"PII detected: {pii_type} at position {match.start()}"
                    ),
                    severity=Severity.HIGH,
                    confidence=0.0,
                    tags=["pii", pii_type],
                )

        # 추가 패턴 검사
        for pat_str in self.extra_patterns:
            match = re.search(pat_str, text)
            if match:
                return LayerResult(
                    name=self.name,
                    allowed=False,
                    reason=(
                        f"PII detected: extra_pattern"
                        f" at position {match.start()}"
                    ),
                    severity=Severity.HIGH,
                    confidence=0.0,
                    tags=["pii", "extra_pattern"],
                )

        return None

    def _check_ner(self, text: str) -> LayerResult | None:
        """2단계: NER 모델로 PII 엔티티를 탐지한다.

        PII 특화 NER 모델이 엔티티를 감지하면
        즉시 차단한다.

        Args:
            text: 검사 대상 텍스트.

        Returns:
            차단 결과 또는 None(차단 조건 미충족).
        """
        if self._ner_model is None:
            return None

        try:
            entities = self._ner_predict(text)
        except Exception:
            logger.debug("NER 추론 중 예외 발생, fail-open")
            return None

        if not entities:
            return None

        # 첫 번째 감지된 엔티티로 차단
        first = entities[0]
        raw_label = first.get("entity", "")
        # B-이름, I-전화번호 → 이름, 전화번호
        clean_label = raw_label.split("-", 1)[-1]
        pii_type = _ENTITY_LABEL_MAP.get(
            clean_label,
            clean_label,
        )
        start = first.get("start", 0)

        return LayerResult(
            name=self.name,
            allowed=False,
            reason=(f"PII detected: {pii_type} at position {start}"),
            severity=Severity.HIGH,
            confidence=0.0,
            tags=["pii", "ner", pii_type],
        )

    async def _check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """L5 검사 실행: Regex → NER 순서로 PII 탐지.

        Args:
            request: 가드레일 요청 객체.

        Returns:
            레이어의 검사 결과.
        """
        text = request.user_input

        # 1단계: Regex
        regex_result = self._check_regex(text)
        if regex_result is not None:
            return regex_result

        # 2단계: NER
        ner_result = self._check_ner(text)
        if ner_result is not None:
            return ner_result

        # 허용
        return LayerResult(
            name=self.name,
            allowed=True,
            severity=Severity.NONE,
            confidence=1.0,
        )
