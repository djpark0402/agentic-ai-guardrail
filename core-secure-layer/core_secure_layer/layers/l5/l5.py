"""L5 가드레일 레이어: PII/민감정보 2단계 탐지.

1단계 Regex(기본 + extra_patterns)로 정형 PII를 탐지하고,
2단계 NER 모델로 PII 엔티티를 탐지한다.
각 모델 폴더(`model/<name>/`)는 자기 계약 파일
`pii_labels.json` 을 가지며 `label_map` · `block_singletons` ·
`block_combinations` · `min_score` · `aggregation_strategy` 를
공개한다. 이 값들은 `L5Layer` 생성자 인자로 덮어쓸 수 있고,
인스턴스 속성으로도 런타임에 갱신할 수 있다 — 차후 ADMIN 정책이
`min_score` 등을 주입하는 경로에서 사용된다.
fail-open 원칙: 모델 미로드나 예외 시 허용.
"""

import json
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

# 각 모델 폴더 안에 배포되는 L5 운영 계약 파일
_PII_LABELS_FILENAME = "pii_labels.json"

# pii_labels.json 파일이 없거나 파싱 실패 시 사용하는 fail-open 기본값.
# min_score=0.0 은 사실상 스코어 필터 미적용과 동일.
_DEFAULT_LABELS_CONFIG: dict[str, Any] = {
    "label_map": {},
    "block_singletons": [],
    "block_combinations": [],
    "min_score": 0.0,
    "aggregation_strategy": "simple",
}

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

def _load_pii_labels(model_dir: Path) -> dict[str, Any]:
    """모델 폴더에서 `pii_labels.json` 을 읽어 dict 로 반환한다.

    파일이 없거나 파싱 실패 시 fail-open — `_DEFAULT_LABELS_CONFIG`
    기반 빈 기본값을 반환하고 debug 로그 한 줄만 남긴다.

    Args:
        model_dir: NER 모델 폴더 (`_MODEL_BASE_DIR / model_name`).

    Returns:
        키(`label_map`, `block_singletons`, `block_combinations`,
        `min_score`, `aggregation_strategy`) 를 모두 채운 dict.
    """
    config: dict[str, Any] = {
        "label_map": {},
        "block_singletons": [],
        "block_combinations": [],
        "min_score": _DEFAULT_LABELS_CONFIG["min_score"],
        "aggregation_strategy": _DEFAULT_LABELS_CONFIG[
            "aggregation_strategy"
        ],
    }
    labels_path = model_dir / _PII_LABELS_FILENAME
    try:
        with labels_path.open("r", encoding="utf-8") as fp:
            raw = json.load(fp)
    except (OSError, ValueError):
        logger.debug(
            "pii_labels.json 로드 실패, fail-open 기본값 사용: %s",
            labels_path,
        )
        return config

    if isinstance(raw, dict):
        for key in _DEFAULT_LABELS_CONFIG:
            if key in raw:
                config[key] = raw[key]
    return config


class L5Layer(BaseLayer):
    """PII/민감정보 2단계 탐지 레이어.

    1단계 Regex로 정형 PII를 빠르게 걸러내고,
    2단계 NER 모델로 엔티티 조합을 검사한다.
    NER 판정 계약(`label_map`, `block_singletons`, `min_score`,
    `aggregation_strategy`) 은 모델 폴더의 `pii_labels.json` 에서
    읽어 인스턴스 속성에 저장된다. 생성자 인자로 오버라이드하거나
    런타임에 속성 대입으로 갱신할 수 있다 — 차후 ADMIN 정책이
    `min_score` 등을 주입할 때 사용되는 주입 표면.
    """

    name: str = "L5"

    def __init__(
        self,
        model_name: str = "ner-ko",
        extra_patterns: list[str] | None = None,
        *,
        min_score: float | None = None,
        label_map: dict[str, str] | None = None,
        block_singletons: list[str] | None = None,
        aggregation_strategy: str | None = None,
    ) -> None:
        """L5Layer 초기화.

        Args:
            model_name: NER 모델 폴더명.
            extra_patterns: 추가 차단 정규식 리스트.
            min_score: NER 엔티티 스코어 컷오프. `None` 이면 모델
                폴더의 `pii_labels.json` 값을 사용.
            label_map: 모델 로컬 라벨(B-/I- 접두 제거 후) → 정규화
                PII 타입 매핑. `None` 이면 `pii_labels.json` 값 사용.
            block_singletons: 단일 검출로 차단할 정규화 타입 목록.
                `None` 이면 `pii_labels.json` 값 사용.
            aggregation_strategy: HuggingFace NER 파이프라인
                aggregation 전략. `None` 이면 `pii_labels.json` 값 사용.
        """
        self.model_name = model_name
        self.extra_patterns: list[str] = (
            extra_patterns if extra_patterns is not None else []
        )

        # 1) 모델 폴더의 pii_labels.json 을 먼저 읽고,
        # 2) 생성자 오버라이드(None 아닌 값)로 덮어쓴 뒤,
        # 3) 평평한 mutable 속성으로 보관 — _check_ner 가 매 호출 시
        #    직접 참조하므로 `layer.min_score = X` 형태의 라이브
        #    갱신도 다음 요청부터 즉시 반영된다.
        file_cfg = _load_pii_labels(_MODEL_BASE_DIR / model_name)

        self.min_score: float = float(
            file_cfg["min_score"] if min_score is None else min_score,
        )
        self.label_map: dict[str, str] = dict(
            file_cfg["label_map"] if label_map is None else label_map,
        )
        self.block_singletons: frozenset[str] = frozenset(
            file_cfg["block_singletons"]
            if block_singletons is None
            else block_singletons,
        )
        self.aggregation_strategy: str = str(
            file_cfg["aggregation_strategy"]
            if aggregation_strategy is None
            else aggregation_strategy,
        )
        # block_combinations 는 현재 계약상 빈 배열 — 미래 예약.
        self._block_combinations: tuple[tuple[str, ...], ...] = tuple(
            tuple(combo)
            for combo in file_cfg.get("block_combinations", [])
        )

        self._ner_model: Any = self._load_ner_model(model_name)

    def _load_ner_model(self, model_name: str) -> Any:
        """NER 모델 로드를 시도한다.

        모델 계약(`pii_labels.json`) 의 `aggregation_strategy` 를 HF
        `pipeline("ner", ...)` 에 전달한다. 기본값 `"simple"` 에서는
        각 예측이 `entity` 대신 `entity_group` 키로 집계되므로
        `_check_ner` 는 두 키를 모두 허용한다.

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
                aggregation_strategy=self.aggregation_strategy,
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

        계약: `score >= self.min_score` 인 엔티티를 순회하며, 각 엔티티
        라벨(B-/I- 접두 제거 후 `self.label_map` 정규화)이
        `self.block_singletons` 에 포함되면 해당 엔티티로 차단한다.
        조건을 만족하는 첫 엔티티가 없으면 허용(None).

        평평한 속성 (`self.min_score`, `self.label_map`,
        `self.block_singletons`) 을 매 호출 시 참조하므로, ADMIN 정책
        핫스왑(속성 대입) 시 다음 호출부터 즉시 반영된다.

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

        for ent in entities:
            # 1) score 컷오프. score 가 없으면 0.0 으로 간주 → min_score>0
            #    환경에서는 자동 필터. min_score=0.0 인 테스트/기본값
            #    환경에서는 모든 엔티티가 통과한다.
            score = float(ent.get("score", 0.0))
            if score < self.min_score:
                continue

            # 2) 라벨 정규화. aggregation 여부에 따라 key 가 다를 수 있어
            #    `entity` 와 `entity_group` 둘 다 확인.
            raw_label = ent.get("entity") or ent.get("entity_group") or ""
            clean_label = raw_label.split("-", 1)[-1]
            pii_type = self.label_map.get(clean_label, clean_label)

            # 3) block_singletons 게이트. 비어 있으면 어떤 엔티티도 차단
            #    하지 않는다 — 계약을 전혀 선언하지 않은 fail-open 상태.
            if pii_type not in self.block_singletons:
                continue

            start = ent.get("start", 0)
            return LayerResult(
                name=self.name,
                allowed=False,
                reason=(
                    f"PII detected: {pii_type} at position {start}"
                ),
                severity=Severity.HIGH,
                confidence=0.0,
                tags=["pii", "ner", pii_type],
            )

        # TODO: block_combinations 는 현재 계약상 비어 있어 no-op.
        return None

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
