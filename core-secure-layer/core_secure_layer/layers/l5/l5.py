"""L5 가드레일 레이어: PII/민감정보 2단계 탐지.

1단계 Regex(기본 + extra_patterns)로 정형 PII를 탐지하고,
2단계 NER 모델로 PII 엔티티를 탐지한다.
NER 판정 로직은 모델 폴더 내 ``pii_labels.json`` 스펙에서 읽어
데이터 드리븐으로 결정하며, JSON 이 없으면 ``config.json`` 의
``id2label`` 로 관대 폴백한다.
fail-open 원칙: 모델 미로드, 추론 예외, JSON 파싱 실패 시 허용.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

from transformers import pipeline

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

logger = logging.getLogger(__name__)

# NER 모델 기본 경로 (테스트에서 monkeypatch 로 치환 가능)
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


def _strip_bio_prefix(label: str) -> str:
    """BIO 스키마 접두사(B-, I-)를 제거한다."""
    if label.startswith(("B-", "I-")):
        return label[2:]
    return label


class L5Layer(BaseLayer):
    """PII/민감정보 2단계 탐지 레이어.

    1단계 Regex로 정형 PII를 빠르게 걸러내고,
    2단계 NER 모델로 엔티티 기반 차단을 수행한다.
    판정 규칙은 모델 폴더의 ``pii_labels.json`` 에서 읽는다.
    """

    name: str = "L5"

    def __init__(
        self,
        model_name: str = "ner-ko",
        extra_patterns: list[str] | None = None,
        min_score: float | None = None,
    ) -> None:
        """L5Layer 초기화.

        Args:
            model_name: NER 모델 폴더명(``model/`` 하위).
            extra_patterns: 추가 차단 정규식 리스트.
            min_score: NER 엔티티 신뢰도 임계값. ``None`` 이면
                ``pii_labels.json`` 의 값을 사용하고, 값이 주어지면
                JSON 스펙을 override 한다.
        """
        self.model_name = model_name
        self.extra_patterns: list[str] = (
            extra_patterns if extra_patterns is not None else []
        )
        # 생성자 override 값(로딩 후 스펙에 최우선 적용)
        self._min_score_override: float | None = min_score
        # pii_labels 스펙 속성(로딩 과정에서 채워짐)
        self._label_map: dict[str, str] = {}
        self._block_singletons: list[str] = []
        self._block_combinations: list[list[str]] = []
        self._min_score: float = 0.0
        self._aggregation_strategy: str = "simple"
        self._ner_model: Any = self._load_ner_model(model_name)

    def _load_ner_model(self, model_name: str) -> Any:
        """NER 모델과 ``pii_labels.json`` 스펙을 로드한다.

        처리 순서:
            1. ``pii_labels.json`` 존재 여부 확인
               - 있으면 JSON 파싱 → 스펙 속성 세팅
               - 파싱 실패 시 NER 비활성화(fail-open)
               - 없으면 폴백 플래그 설정 후 파이프라인 로드 후 id2label 추출
            2. ``transformers.pipeline`` 로드
            3. 폴백이 필요한 경우 id2label 로 스펙 재구성

        Args:
            model_name: 모델 폴더명.

        Returns:
            로드된 파이프라인 또는 None(fail-open).
        """
        model_path = _MODEL_BASE_DIR / model_name
        spec_path = model_path / "pii_labels.json"

        need_fallback = False
        if spec_path.exists():
            try:
                spec_text = spec_path.read_text(encoding="utf-8")
                spec = json.loads(spec_text)
            except (OSError, json.JSONDecodeError) as exc:
                logger.debug(
                    "pii_labels.json 파싱 실패, NER 비활성화: %s (%s)",
                    spec_path,
                    exc,
                )
                # 잘못된 스펙으로 의도치 않은 차단 규칙이 돌면 위험 — fail-open
                return None
            self._apply_spec(spec)
        else:
            need_fallback = True
            logger.warning(
                "pii_labels.json 없음, 폴백 동작 —"
                " 범용 NER 모델은 오탐 위험이 큼: %s",
                spec_path,
            )

        try:
            ner_pipeline = pipeline(
                "ner",
                model=str(model_path),
                tokenizer=str(model_path),
                aggregation_strategy=self._aggregation_strategy,
            )
        except Exception:
            logger.debug(
                "NER 모델 로드 실패, fail-open: %s",
                model_path,
            )
            return None

        if need_fallback:
            self._apply_fallback_spec(model_path, ner_pipeline)

        return ner_pipeline

    def _apply_spec(self, spec: dict[str, Any]) -> None:
        """``pii_labels.json`` 파싱 결과를 인스턴스 속성에 반영한다.

        생성자에서 ``min_score`` 가 주어진 경우 JSON 값을 덮어쓴다.
        """
        self._label_map = dict(spec.get("label_map", {}))
        self._block_singletons = list(spec.get("block_singletons", []))
        self._block_combinations = [
            list(rule) for rule in spec.get("block_combinations", [])
        ]
        if self._min_score_override is not None:
            self._min_score = float(self._min_score_override)
        else:
            self._min_score = float(spec.get("min_score", 0.0))
        self._aggregation_strategy = str(
            spec.get("aggregation_strategy", "simple")
        )

    def _apply_fallback_spec(self, model_path: Path, ner_pipeline: Any) -> None:
        """``pii_labels.json`` 부재 시 id2label 로 스펙을 구성한다.

        모델 폴더의 ``config.json`` 을 우선 읽고, 실패하면 파이프라인의
        ``model.config.id2label`` 을 시도한다.
        """
        id2label: dict[Any, Any] = {}
        config_path = model_path / "config.json"
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            id2label = dict(config.get("id2label", {}))
        except OSError, json.JSONDecodeError:
            try:
                id2label = dict(ner_pipeline.model.config.id2label)
            except AttributeError, TypeError:
                id2label = {}

        label_map: dict[str, str] = {}
        for raw_label in id2label.values():
            clean = _strip_bio_prefix(str(raw_label))
            if not clean or clean == "O":
                continue
            label_map[clean] = clean

        self._label_map = label_map
        self._block_singletons = list(label_map.keys())
        self._block_combinations = []
        if self._min_score_override is not None:
            self._min_score = float(self._min_score_override)
        else:
            self._min_score = 0.0
        self._aggregation_strategy = "simple"

    def _ner_predict(self, text: str) -> list[dict[str, Any]]:
        """NER 모델로 엔티티를 추론한다.

        Args:
            text: 분석 대상 텍스트.

        Returns:
            엔티티 리스트. 각 항목은 파이프라인 반환 형식을 따른다.
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

        ``pii_labels.json`` 스펙(label_map / block_singletons /
        block_combinations / min_score) 에 따라 판정한다.
        싱글톤 매칭을 조합 매칭보다 먼저 검사한다.

        Args:
            text: 검사 대상 텍스트.

        Returns:
            차단 결과 또는 None(허용).
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

        singleton_set = set(self._block_singletons)
        # 순서 보존을 위해 리스트와 집합을 병행
        detected_order: list[str] = []
        detected_set: set[str] = set()
        first_positions: dict[str, int] = {}

        for entity in entities:
            score = float(entity.get("score", 1.0))
            if score < self._min_score:
                continue
            raw_label = entity.get("entity") or entity.get("entity_group") or ""
            clean_label = _strip_bio_prefix(str(raw_label))
            pii_type = self._label_map.get(clean_label)
            if pii_type is None:
                continue
            if pii_type not in detected_set:
                detected_set.add(pii_type)
                detected_order.append(pii_type)
                first_positions[pii_type] = int(entity.get("start", 0))

        if not detected_set:
            return None

        for pii_type in detected_order:
            if pii_type in singleton_set:
                start = first_positions[pii_type]
                return LayerResult(
                    name=self.name,
                    allowed=False,
                    reason=(f"PII detected: {pii_type} at position {start}"),
                    severity=Severity.HIGH,
                    confidence=0.0,
                    tags=["pii", "ner", pii_type],
                )

        for rule in self._block_combinations:
            if all(t in detected_set for t in rule):
                return LayerResult(
                    name=self.name,
                    allowed=False,
                    reason=f"PII detected: {'+'.join(rule)}",
                    severity=Severity.HIGH,
                    confidence=0.0,
                    tags=["pii", "ner", *rule],
                )

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

        regex_result = self._check_regex(text)
        if regex_result is not None:
            return regex_result

        ner_result = self._check_ner(text)
        if ner_result is not None:
            return ner_result

        return LayerResult(
            name=self.name,
            allowed=True,
            severity=Severity.NONE,
            confidence=1.0,
        )
