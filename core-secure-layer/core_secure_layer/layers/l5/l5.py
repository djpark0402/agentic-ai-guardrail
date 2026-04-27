"""L5 가드레일 레이어: PII/민감정보 2단계 탐지.

1단계 Regex(기본 + extra_patterns)로 정형 PII를 탐지하고,
2단계 NER 모델로 PII 엔티티를 탐지한다.
NER 판정 로직은 모델 폴더 내 ``pii_labels.json`` 스펙에서 읽어
데이터 드리븐으로 결정하며, JSON 이 없으면 ``config.json`` 의
``id2label`` 로 관대 폴백한다.
모델 학습 방식별 로딩·추론 차이는 ``_HFPipelineAdapter`` /
``_HFCharLevelAdapter`` 어댑터 클래스로 캡슐화하며,
``pii_labels.json`` 의 ``adapter`` 필드로 분기한다.
fail-open 원칙: 모델 미로드, 추론 예외, JSON 파싱 실패 시 허용.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

import torch
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    pipeline,
)

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

logger = logging.getLogger(__name__)

# NER 모델 기본 경로 (테스트에서 monkeypatch 로 치환 가능)
_MODEL_BASE_DIR = Path(__file__).parent / "model"

# charlevel 어댑터 청크 분할에 사용하는 문장 종결 부호
_SENTENCE_BOUNDARIES: frozenset[str] = frozenset({".", "!", "?", "\n"})

# charlevel 어댑터 청크 크기 비율 (max_length 대비)
_CHUNK_RATIO: float = 0.8

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


class _HFPipelineAdapter:
    """``transformers.pipeline("ner", ...)`` 기반 NER 어댑터.

    자연 텍스트 입력 + WordPiece subword 토큰화로 학습된 PII 모델용.
    """

    def __init__(self, model_path: Path, spec: dict[str, Any]) -> None:
        """파이프라인을 즉시 로드한다.

        Args:
            model_path: 모델 폴더 경로.
            spec: ``pii_labels.json`` 파싱 결과.

        Raises:
            Exception: ``transformers.pipeline`` 로드 실패 시 그대로 전파.
        """
        aggregation_strategy = str(spec.get("aggregation_strategy", "simple"))
        self._pipeline = pipeline(
            "ner",
            model=str(model_path),
            tokenizer=str(model_path),
            aggregation_strategy=aggregation_strategy,
        )
        # L5Layer 의 ``_ner_model`` 호환성 유지를 위한 내부 모델 핸들
        self.model: Any = self._pipeline

    def predict(self, text: str) -> list[dict[str, Any]]:
        """입력 텍스트에 대한 엔티티 리스트를 반환한다.

        Args:
            text: 분석 대상 텍스트.

        Returns:
            ``{"entity", "word", "start", "score"}`` 키를 가진 dict 목록.
        """
        raw = self._pipeline(text)
        normalized: list[dict[str, Any]] = []
        for ent in raw:
            label = ent.get("entity_group", ent.get("entity", ""))
            normalized.append(
                {
                    "entity": str(label),
                    "word": str(ent.get("word", "")),
                    "start": int(ent.get("start", 0)),
                    "score": float(ent.get("score", 0.0)),
                }
            )
        return normalized


class _HFCharLevelAdapter:
    """글자 단위 + ``[SP]`` 토큰 학습 모델 전용 NER 어댑터.

    ``is_split_into_words=True`` 입력으로 학습된 모델을 학습 분포 그대로
    추론하기 위해 텍스트를 글자 리스트로 변환하고 공백을 ``[SP]`` 로
    치환해 토크나이저와 모델을 직접 호출한다.
    """

    def __init__(self, model_path: Path, spec: dict[str, Any]) -> None:
        """토크나이저와 모델을 즉시 로드한다.

        Args:
            model_path: 모델 폴더 경로.
            spec: ``pii_labels.json`` 파싱 결과.

        Raises:
            Exception: 토크나이저/모델 로드 실패 시 그대로 전파.
        """
        self._max_length = int(spec.get("max_length", 256))
        self._tokenizer = AutoTokenizer.from_pretrained(
            str(model_path),
            use_fast=True,
        )
        # 학습 시 추가됐던 [SP] 토큰이 vocab 에 없으면 직접 등록
        try:
            vocab = self._tokenizer.get_vocab()
        except Exception:
            vocab = {}
        if "[SP]" not in vocab:
            self._tokenizer.add_tokens(["[SP]"])
        self._model = AutoModelForTokenClassification.from_pretrained(
            str(model_path),
        )
        # 토크나이저 vocab 확장에 맞춰 임베딩 테이블 확장
        self._model.resize_token_embeddings(len(self._tokenizer))
        self._model.eval()
        # L5Layer 의 ``_ner_model`` 호환성 유지를 위한 내부 모델 핸들
        self.model: Any = self._model
        # id2label 은 BIO 디코딩 시 라벨 인덱스를 문자열로 매핑하는 데 사용
        try:
            self._id2label: dict[int, str] = dict(self._model.config.id2label)
        except AttributeError, TypeError:
            self._id2label = {}

    @staticmethod
    def _text_to_chars(text: str) -> list[str]:
        """텍스트를 글자 리스트로 변환하며 공백은 ``[SP]`` 로 치환."""
        return ["[SP]" if ch == " " else ch for ch in text]

    def _predict_chunk(
        self,
        chars: list[str],
    ) -> list[tuple[str, float]]:
        """글자 청크를 토큰화 후 모델 직접 호출 → 글자별 (라벨, 점수).

        Args:
            chars: 글자 청크 (공백은 ``[SP]`` 로 치환된 상태).

        Returns:
            각 글자에 대한 ``(라벨문자열, 신뢰도)`` 리스트.
        """
        inputs = self._tokenizer(
            chars,
            is_split_into_words=True,
            return_tensors="pt",
            truncation=True,
            max_length=self._max_length,
            padding=True,
        )
        word_ids = inputs.word_ids(0)
        with torch.no_grad():
            outputs = self._model(**inputs)
        probabilities = torch.softmax(outputs.logits, dim=-1)
        predictions = torch.argmax(probabilities, dim=-1)[0].cpu().tolist()
        scores = probabilities[0].cpu().max(dim=-1).values.tolist()

        char_labels: list[tuple[str, float]] = [("O", 1.0)] * len(chars)
        seen: set[int] = set()
        for i, wid in enumerate(word_ids):
            if wid is None or wid in seen:
                continue
            if wid >= len(chars):
                continue
            seen.add(wid)
            label = self._id2label.get(int(predictions[i]), "O")
            char_labels[wid] = (str(label), float(scores[i]))
        return char_labels

    def _split_chars_into_chunks(
        self,
        chars: list[str],
        chunk_size: int,
    ) -> list[tuple[int, int]]:
        r"""글자 리스트를 문장 부호 기준으로 청크 (start, end) 로 분할.

        문장 종결 부호(``. ! ? \n``) 직후를 경계로 사용하며, 단일 문장이
        ``chunk_size`` 를 넘으면 강제 분할한다.
        """
        sentences: list[tuple[int, int]] = []
        cur = 0
        for i, ch in enumerate(chars):
            if ch in _SENTENCE_BOUNDARIES:
                sentences.append((cur, i + 1))
                cur = i + 1
        if cur < len(chars):
            sentences.append((cur, len(chars)))
        if not sentences:
            return [(0, len(chars))]

        chunks: list[tuple[int, int]] = []
        cur_start: int | None = None
        cur_end: int = 0
        for s, e in sentences:
            size = e - s
            if size > chunk_size:
                if cur_start is not None:
                    chunks.append((cur_start, cur_end))
                    cur_start = None
                for sub in range(s, e, chunk_size):
                    chunks.append((sub, min(sub + chunk_size, e)))
                continue
            if cur_start is None:
                cur_start, cur_end = s, e
            elif (cur_end - cur_start) + size <= chunk_size:
                cur_end = e
            else:
                chunks.append((cur_start, cur_end))
                cur_start, cur_end = s, e
        if cur_start is not None:
            chunks.append((cur_start, cur_end))
        return chunks

    def _bridge_sp_tokens(
        self,
        chars: list[str],
        labels: list[tuple[str, float]],
    ) -> None:
        """``[SP]`` 위치가 ``O`` 인데 양쪽이 같은 엔티티면 ``I-`` 로 보정."""
        limit = min(len(chars), len(labels))
        for ci in range(1, limit - 1):
            if chars[ci] != "[SP]":
                continue
            if labels[ci][0] != "O":
                continue
            prev_label = labels[ci - 1][0]
            next_label = labels[ci + 1][0]
            if prev_label == "O" or next_label == "O":
                continue
            prev_type = _strip_bio_prefix(prev_label)
            next_type = _strip_bio_prefix(next_label)
            if prev_type != next_type:
                continue
            bridge_score = min(labels[ci - 1][1], labels[ci + 1][1])
            labels[ci] = (f"I-{prev_type}", bridge_score)

    def _decode_bio(
        self,
        text: str,
        labels: list[tuple[str, float]],
    ) -> list[dict[str, Any]]:
        """글자별 BIO 라벨을 엔티티 스팬 dict 리스트로 디코딩.

        스팬 ``score`` 는 내부 글자 점수의 최솟값(가장 보수적)을 쓰고,
        ``word`` 는 원본 텍스트에서 잘라낸 슬라이스를 그대로 사용해
        ``[SP]`` 가 아닌 실제 공백을 보존한다.
        """
        entities: list[dict[str, Any]] = []
        cur_type: str | None = None
        cur_start: int = 0
        cur_score: float = 1.0
        cur_len: int = 0

        def _flush() -> None:
            if cur_type is None:
                return
            end = cur_start + cur_len
            entities.append(
                {
                    "entity": cur_type,
                    "word": text[cur_start:end],
                    "start": cur_start,
                    "score": round(cur_score, 4),
                }
            )

        for i, (label, score) in enumerate(labels):
            if label == "O" or not label:
                _flush()
                cur_type = None
                cur_len = 0
                continue
            ent_type = _strip_bio_prefix(label)
            is_begin = label.startswith("B-") or cur_type != ent_type
            if is_begin:
                _flush()
                cur_type = ent_type
                cur_start = i
                cur_score = float(score)
                cur_len = 1
            else:
                cur_score = min(cur_score, float(score))
                cur_len += 1
        _flush()
        return entities

    def predict(self, text: str) -> list[dict[str, Any]]:
        """입력 텍스트에 대한 엔티티 리스트를 반환한다.

        Args:
            text: 분석 대상 텍스트.

        Returns:
            ``{"entity", "word", "start", "score"}`` 키를 가진 dict 목록.
        """
        chars = self._text_to_chars(text)
        if not chars:
            return []

        chunk_size = max(1, int(self._max_length * _CHUNK_RATIO))
        if len(chars) <= chunk_size:
            chunk_ranges = [(0, len(chars))]
        else:
            chunk_ranges = self._split_chars_into_chunks(chars, chunk_size)

        all_labels: list[tuple[str, float]] = []
        for s, e in chunk_ranges:
            chunk = chars[s:e]
            try:
                chunk_labels = self._predict_chunk(chunk)
            except Exception as exc:
                # 추론 실패 시 해당 청크는 모두 O 로 취급 (fail-open)
                logger.debug(
                    "charlevel _predict_chunk 실패, 청크 fail-open: %s",
                    exc,
                )
                chunk_labels = [("O", 0.0)] * len(chunk)
            # 길이가 어긋나면 짧은 쪽에 맞춰 자르거나 O 로 패딩
            if len(chunk_labels) < len(chunk):
                chunk_labels = list(chunk_labels) + [("O", 0.0)] * (
                    len(chunk) - len(chunk_labels)
                )
            elif len(chunk_labels) > len(chunk):
                chunk_labels = list(chunk_labels)[: len(chunk)]
            all_labels.extend(chunk_labels)

        self._bridge_sp_tokens(chars, all_labels)
        return self._decode_bio(text, all_labels)


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
        # NER 어댑터 (None 이면 fail-open)
        self._adapter: _HFPipelineAdapter | _HFCharLevelAdapter | None = None
        self._ner_model: Any = self._load_ner_model(model_name)

    def _load_ner_model(self, model_name: str) -> Any:
        """NER 어댑터와 ``pii_labels.json`` 스펙을 로드한다.

        처리 순서:
            1. ``pii_labels.json`` 존재 여부 확인
               - 있으면 JSON 파싱 → 스펙 반영 → ``adapter`` 필드로 분기
               - 파싱 실패 시 NER 비활성화(fail-open)
               - 없으면 ``hf-pipeline`` 강제 (글자 단위 모델은 폴백 불가)
            2. 어댑터 인스턴스 생성 (실패 시 fail-open)
            3. JSON 부재 폴백 시 id2label 로 스펙 재구성

        Args:
            model_name: 모델 폴더명.

        Returns:
            어댑터의 내부 모델 핸들 또는 ``None`` (fail-open).
        """
        model_path = _MODEL_BASE_DIR / model_name
        spec_path = model_path / "pii_labels.json"

        need_fallback = False
        spec: dict[str, Any] = {}
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
                self._adapter = None
                return None
            self._apply_spec(spec)
            adapter_kind = str(spec.get("adapter", "hf-pipeline"))
        else:
            need_fallback = True
            # 글자 단위 학습 모델은 폴백 불가 — 무조건 hf-pipeline 강제
            adapter_kind = "hf-pipeline"
            logger.warning(
                "pii_labels.json 없음, 폴백 동작 —"
                " 범용 NER 모델은 오탐 위험이 큼: %s",
                spec_path,
            )

        adapter: _HFPipelineAdapter | _HFCharLevelAdapter | None
        try:
            if adapter_kind == "hf-pipeline":
                adapter = _HFPipelineAdapter(model_path, spec)
            elif adapter_kind == "hf-charlevel":
                adapter = _HFCharLevelAdapter(model_path, spec)
            else:
                logger.debug(
                    "알 수 없는 adapter 값, fail-open: %s",
                    adapter_kind,
                )
                self._adapter = None
                return None
        except Exception as exc:
            logger.debug(
                "NER 어댑터 로드 실패, fail-open: %s (%s)",
                model_path,
                exc,
            )
            self._adapter = None
            return None

        if need_fallback:
            self._apply_fallback_spec(model_path, adapter.model)

        self._adapter = adapter
        return adapter.model

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

    def _apply_fallback_spec(
        self,
        model_path: Path,
        ner_model: Any,
    ) -> None:
        """``pii_labels.json`` 부재 시 id2label 로 스펙을 구성한다.

        모델 폴더의 ``config.json`` 을 우선 읽고, 실패하면 어댑터의
        내부 모델에서 ``config.id2label`` 을 시도한다.
        """
        id2label: dict[Any, Any] = {}
        config_path = model_path / "config.json"
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            id2label = dict(config.get("id2label", {}))
        except OSError, json.JSONDecodeError:
            try:
                id2label = dict(ner_model.model.config.id2label)
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
        """NER 어댑터로 엔티티를 추론한다.

        Args:
            text: 분석 대상 텍스트.

        Returns:
            엔티티 리스트. 각 항목은 어댑터의 정규화 형식을 따른다.
        """
        if self._adapter is None:
            return []
        return self._adapter.predict(text)

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
