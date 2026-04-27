"""L5 가드레일 레이어: PII/민감정보 2단계 탐지.

1단계 Regex(기본 + extra_patterns)로 정형 PII를 탐지하고,
2단계 NER 모델로 PII 엔티티를 탐지한다.
NER 판정 로직은 모델 폴더 내 ``pii_labels.json`` 스펙에서 읽어
데이터 드리븐으로 결정하며, JSON 이 없으면 ``config.json`` 의
``id2label`` 로 관대 폴백한다.
모델 학습 방식별 로딩·추론 차이는 ``_HFPipelineAdapter`` /
``_HFCharLevelAdapter`` / ``_GLinerAdapter`` 어댑터 클래스로
캡슐화하며, ``pii_labels.json`` 의 ``adapter`` 필드로 분기한다.
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

# GLiNER 어댑터 기본 설정값
_GLINER_DEFAULT_PRE_THRESHOLD: float = 0.4
_GLINER_DEFAULT_THRESHOLD: float = 0.75
_GLINER_DEFAULT_TEXT_WINDOW_OVERLAP: int = 64
_GLINER_DEFAULT_MAX_TYPES: int = 10

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


# ──────────────────────────────────────────────
# GLiNER 후처리 오탐 필터 — 한국어 PII 특화 정규식
# ──────────────────────────────────────────────

# PERSON 으로 잡혔지만 사람이 아닌 패턴 (조직 접미사/일반명사/단위어 등)
_PERSON_NOT_RE = re.compile(
    r"^\d|^[가-힣][실관층호]$|^[가-힣]+에서$|^[가-힣]{1}$"
    r"|[클컨센](?:럽|터|트리)$"
    r"|(?:주식회사|재단|법인|협회|학교|대학|병원|은행)$"
    r"|^(?:박사|석사|이사|감사|위원|간사|총장|학장|교장|원장)$"
    r"|^(?:기술|기관|기업|기획|기간|기사|기록|기준|기타|배송|배달|배치|배경"
    r"|최근|최초|최대|최소|최고|최저|최종|최신|최적|최선|최상|최악"
    r"|선고|선정|선택|선발|성과|성명|성별|성공"
    r"|원본|원칙|원인|원금|원래|원리)$"
)

# PERSON 뒤에 붙는 한국어 조사/어미 — trim 대상
_PERSON_TRIM_SUFFIX_RE = re.compile(
    r"^([가-힣]{2,4})"
    r"(?:이지|이야|이다|이고|이랑|이는|이가|이를|이에게|이한테|이의"
    r"|에게|한테|은|는|이|가|를|을|의|도|만|와|과|랑|씩|께"
    r"|입니다|입니까|이요|이며|이라고|이라는|이라서|이니까|이잖아)$"
)

# ADDRESS 단독 광역 지명 — 주소로 보기에 부족
_STANDALONE_PLACE_RE = re.compile(
    r"^(?:한국|대한민국|서울|부산|대구|인천|광주|대전|울산|세종"
    r"|경기|강원|충북|충남|전북|전남|경북|경남|제주)$"
)

# ORGANIZATION 으로 잡혔지만 일반명사 / 단독 단어 등 → 거름
_NOT_ORG_RE = re.compile(
    r"^(?:우리|하나|국민|신한|농협|기업)$"
    r"|^[가-힣]{1}$"
    r"|^(?:회사|기관|단체|부서|팀|조직|기업|사업|업무|서비스|시스템|프로그램)$"
)

# JOB_TITLE 끝에 조사가 붙은 케이스 — 거름
_JOB_TITLE_JOSA_RE = re.compile(r"[를을은는이가의도]$")

# 공통 — 특수문자/공백만 → 거름
_ONLY_SPECIAL_CHARS_RE = re.compile(r"^[\s\W]+$")

# JOB_TITLE 에 포함되면 안 되는 보조 문자 (괄호류, 따옴표류, "이하")
# 풀폭 괄호와 스마트 따옴표는 RUF001 경고 회피를 위해 unicode escape 로 명시.
_JOB_TITLE_FORBIDDEN_RE = re.compile(
    "[()\uff08\uff09\"'\u201c\u201d\u2018\u2019]|이하",
)

# 라벨별 최소 길이 — 너무 짧은 매칭은 오탐 가능성이 높다
_MIN_VALUE_LENGTH: dict[str, int] = {
    "person": 2,
    "address": 5,
    "organization": 2,
    "job_title": 2,
    "location": 2,
    "transaction": 3,
    "loan": 3,
    "income_property": 3,
    "it_system": 3,
    "credit_rating": 3,
}


def _trim_person_suffix(ent: dict[str, Any]) -> dict[str, Any]:
    """PERSON 엔티티 끝의 한국어 조사/어미를 잘라낸다."""
    word = str(ent.get("word", ""))
    match = _PERSON_TRIM_SUFFIX_RE.match(word)
    if match is None:
        return ent
    name = match.group(1)
    new_ent = dict(ent)
    new_ent["word"] = name
    start = int(ent.get("start", 0))
    new_ent["end"] = start + len(name)
    return new_ent


def _is_false_positive(
    ent: dict[str, Any],
    normalized_label: str,
) -> bool:
    """엔티티가 라벨별 정책상 오탐인지 판별한다."""
    val = str(ent.get("word", "")).strip()

    # 공통 — 특수문자/공백만으로 구성된 값은 오탐
    if _ONLY_SPECIAL_CHARS_RE.match(val):
        return True

    # 라벨별 최소 길이 미달은 오탐 (정책 상 선언된 라벨에만 적용)
    min_len = _MIN_VALUE_LENGTH.get(normalized_label, 1)
    if len(val) < min_len:
        return True

    if normalized_label == "person":
        # 사람 이름이 5글자를 넘는 경우는 한국어 환경에서 매우 드물다
        if len(val) > 5:
            return True
        if _PERSON_NOT_RE.search(val):
            return True

    if normalized_label == "address" and _STANDALONE_PLACE_RE.match(val):
        return True

    if normalized_label == "organization" and _NOT_ORG_RE.match(val):
        return True

    if normalized_label == "job_title":
        if _JOB_TITLE_JOSA_RE.search(val):
            return True
        if _JOB_TITLE_FORBIDDEN_RE.search(val):
            return True

    return False


def _post_filter_gliner(
    entities: list[dict[str, Any]],
    label_map: dict[str, str],
) -> list[dict[str, Any]]:
    """GLiNER 출력에 한국어 PII 특화 오탐 필터를 적용한다.

    Args:
        entities: 어댑터 정규화 형식의 엔티티 리스트. ``entity`` 키는
            이미 정규화된 PII 타입 또는 원본 라벨이어도 동일하게 동작
            한다(``label_map`` self-key 미존재 시 fallback).
        label_map: 모델 라벨(``entity``) → 정규화 PII 타입 매핑.

    Returns:
        필터를 통과한 엔티티 리스트.
    """
    out: list[dict[str, Any]] = []
    for ent in entities:
        raw_label = str(ent.get("entity", ""))
        normalized = label_map.get(raw_label, raw_label).lower()
        if normalized == "person":
            ent = _trim_person_suffix(ent)
        if _is_false_positive(ent, normalized):
            continue
        out.append(ent)
    return out


# ──────────────────────────────────────────────
# DeBERTa-v3 tokenizer 호환 레이어 (idempotent 패치)
# ──────────────────────────────────────────────

_BASE_GLINER_TOKENIZER_PATCHED: bool = False


def _patch_base_gliner_tokenizer_loader() -> None:
    """``BaseGLiNER._load_tokenizer`` 를 PreTrainedTokenizerFast 우회로 교체.

    DeBERTa-v3 한국어 tokenizer 가 transformers/tokenizers 호환 이슈로
    ``AutoTokenizer`` 경유 시 로드 실패할 수 있어, 직접
    ``PreTrainedTokenizerFast`` 로 우회 로드한다. idempotent — 이미
    패치돼 있으면 중복 적용하지 않는다.
    """
    global _BASE_GLINER_TOKENIZER_PATCHED
    if _BASE_GLINER_TOKENIZER_PATCHED:
        return
    from gliner.model import BaseGLiNER
    from transformers import PreTrainedTokenizerFast

    def _patched_load(
        cls: Any,
        config: Any,
        model_dir: Any,
        cache_dir: Any = None,
    ) -> Any:
        return PreTrainedTokenizerFast.from_pretrained(str(model_dir))

    BaseGLiNER._load_tokenizer = classmethod(_patched_load)
    _BASE_GLINER_TOKENIZER_PATCHED = True


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
        except (AttributeError, TypeError):
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


class _GLinerAdapter:
    """GLiNER (zero-shot NER) 모델 전용 어댑터.

    원본 ``korean_pii.detection.HybridPIIDetector`` 의 운영 패턴을
    어댑터로 통합한다. 6 개선안:
        1. ``inference_labels`` 가 ``max_types`` 를 초과하면 라벨 청크
           단위로 ``predict_entities`` 를 분할 호출.
        2. 카테고리별 차등 임계값(``category_thresholds``) 과
           ``default_threshold`` 적용.
        3. 이중 단계 임계값 — 1차 ``pre_threshold`` 로 후보를 모으고,
           2차 카테고리 cut 으로 다시 거른다.
        4. 후처리 오탐 필터(:func:`_post_filter_gliner`) 로 한국어
           PII 특화 오탐을 제거.
        5. 슬라이딩 윈도우 텍스트 청크 — 윈도우별 추론 후 전역 좌표
           으로 매핑.
        6. 윈도우 결과 ``(start, end)`` span dedup — 최고 score 라벨만
           남긴다.
    """

    def __init__(self, model_path: Path, spec: dict[str, Any]) -> None:
        """GLiNER 모델을 즉시 로드한다.

        Args:
            model_path: 모델 폴더 경로.
            spec: ``pii_labels.json`` 파싱 결과.

        Raises:
            ValueError: ``inference_labels`` 가 비었거나 누락된 경우.
            Exception: GLiNER 로드 실패 시 그대로 전파(fail-open 처리는
                상위 ``_load_ner_model`` 이 담당).
        """
        labels = spec.get("inference_labels")
        if not labels:
            msg = "GLiNER 어댑터: inference_labels 가 비어 있거나 누락됨"
            raise ValueError(msg)

        self._inference_labels: list[str] = list(labels)
        self._pre_threshold: float = float(
            spec.get("pre_threshold", _GLINER_DEFAULT_PRE_THRESHOLD),
        )
        self._default_threshold: float = float(
            spec.get("default_threshold", _GLINER_DEFAULT_THRESHOLD),
        )
        self._category_thresholds: dict[str, float] = {
            str(k): float(v)
            for k, v in dict(spec.get("category_thresholds", {})).items()
        }
        self._max_length: int = int(spec.get("max_length", 256))
        self._text_window_max_len: int = int(
            spec.get("text_window_max_len", self._max_length),
        )
        self._text_window_overlap: int = int(
            spec.get(
                "text_window_overlap",
                _GLINER_DEFAULT_TEXT_WINDOW_OVERLAP,
            ),
        )
        self._max_types: int = self._read_max_types(model_path)
        self._label_map: dict[str, str] = dict(spec.get("label_map", {}))

        # DeBERTa-v3 호환 레이어를 모델 로드 전에 설치
        _patch_base_gliner_tokenizer_loader()

        from gliner import GLiNER

        self._model: Any = GLiNER.from_pretrained(
            str(model_path),
            local_files_only=True,
        )

        # words_splitter override (선택)
        splitter_kind = spec.get("words_splitter")
        if splitter_kind:
            from gliner.data_processing import WordsSplitter

            try:
                self._model.data_processor.words_splitter = WordsSplitter(
                    splitter_kind,
                )
            except Exception as exc:
                # splitter 교체 실패는 추론 자체를 막을 정도는 아니다
                logger.debug(
                    "words_splitter override 실패 (%s): %s",
                    splitter_kind,
                    exc,
                )

        # L5Layer 의 ``_ner_model`` 호환성 유지를 위한 내부 모델 핸들
        self.model: Any = self._model

    @staticmethod
    def _read_max_types(model_path: Path) -> int:
        """``gliner_config.json`` 의 ``max_types`` 를 읽는다.

        파일이 없거나 파싱 실패 시 기본값 10 을 반환한다.
        """
        config_path = model_path / "gliner_config.json"
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            value = int(data.get("max_types", _GLINER_DEFAULT_MAX_TYPES))
            return max(1, value)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return _GLINER_DEFAULT_MAX_TYPES

    @staticmethod
    def _split_into_text_windows(
        text: str,
        max_len: int,
        overlap: int,
    ) -> list[tuple[int, int]]:
        """긴 입력을 max_len + overlap 슬라이딩 윈도우로 분할.

        Args:
            text: 분할 대상 텍스트.
            max_len: 윈도우 최대 길이.
            overlap: 인접 윈도우가 겹치는 글자 수.

        Returns:
            ``(start, end)`` 튜플 리스트. ``len(text) <= max_len`` 이면
            ``[(0, len(text))]`` 단일 윈도우.
        """
        if len(text) <= max_len:
            return [(0, len(text))]
        # overlap 이 max_len 이상이면 무한 루프 방지를 위해 1 보장
        step = max(1, max_len - overlap)
        windows: list[tuple[int, int]] = []
        start = 0
        while start < len(text):
            end = min(start + max_len, len(text))
            windows.append((start, end))
            if end == len(text):
                break
            start += step
        return windows

    def _predict_chunk_labels(
        self,
        chunk_text: str,
    ) -> list[dict[str, Any]]:
        """단일 텍스트 청크에 대한 GLiNER 추론 (라벨 청크 폴백 포함).

        ``len(inference_labels) <= max_types`` 이면 한 번에 호출하고,
        아니면 ``max_types`` 단위로 나눠 여러 번 호출해 결과를 합친다.
        """
        if len(self._inference_labels) <= self._max_types:
            return list(
                self._model.predict_entities(
                    chunk_text,
                    labels=self._inference_labels,
                    threshold=self._pre_threshold,
                ),
            )
        merged: list[dict[str, Any]] = []
        for i in range(0, len(self._inference_labels), self._max_types):
            sub_labels = self._inference_labels[i : i + self._max_types]
            merged.extend(
                self._model.predict_entities(
                    chunk_text,
                    labels=sub_labels,
                    threshold=self._pre_threshold,
                ),
            )
        return merged

    def _collect_raw_entities(
        self,
        text: str,
        windows: list[tuple[int, int]],
    ) -> list[dict[str, Any]]:
        """모든 윈도우에 대한 raw 엔티티 수집 (전역 좌표 매핑 포함).

        윈도우 단위 fail-open: ``predict_entities`` 가 예외를 던지면
        해당 윈도우만 스킵하고 다른 윈도우는 계속 처리한다.
        """
        raw_all: list[dict[str, Any]] = []
        for ws, we in windows:
            chunk_text = text[ws:we]
            try:
                raw_chunk = self._predict_chunk_labels(chunk_text)
            except Exception as exc:
                logger.debug(
                    "GLiNER predict_entities 실패, 윈도우 fail-open: %s",
                    exc,
                )
                continue
            for ent in raw_chunk:
                raw_all.append(
                    {
                        "label": str(ent.get("label", "")),
                        "text": str(ent.get("text", "")),
                        "start": int(ent.get("start", 0)) + ws,
                        "end": int(ent.get("end", 0)) + ws,
                        "score": float(ent.get("score", 0.0)),
                    },
                )
        return raw_all

    def _apply_category_cuts(
        self,
        raw_entities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """라벨별 차등 임계값(2차 cut) 을 적용한다."""
        kept: list[dict[str, Any]] = []
        for ent in raw_entities:
            label_norm = self._label_map.get(ent["label"], ent["label"])
            cut = self._category_thresholds.get(
                label_norm,
                self._default_threshold,
            )
            if ent["score"] >= cut:
                kept.append(ent)
        return kept

    @staticmethod
    def _dedup_by_span(
        entities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """``(start, end)`` 가 같은 엔티티 중 최고 score 만 남긴다."""
        by_span: dict[tuple[int, int], dict[str, Any]] = {}
        for ent in entities:
            key = (int(ent["start"]), int(ent["end"]))
            existing = by_span.get(key)
            if existing is None or ent["score"] > existing["score"]:
                by_span[key] = ent
        return list(by_span.values())

    def predict(self, text: str) -> list[dict[str, Any]]:
        """슬라이딩 윈도우 + 6 개선안을 통합 적용해 엔티티를 반환한다.

        Args:
            text: 분석 대상 텍스트.

        Returns:
            ``{"entity", "word", "start", "end", "score"}`` 키를 가진
            dict 목록 (후처리 오탐 필터 적용 후).
        """
        windows = self._split_into_text_windows(
            text,
            self._text_window_max_len,
            self._text_window_overlap,
        )
        raw_all = self._collect_raw_entities(text, windows)
        filtered = self._apply_category_cuts(raw_all)
        deduped = self._dedup_by_span(filtered)

        # entity 키는 정규화된 PII 타입을 노출한다(매핑 부재 시 raw 그대로).
        normalized: list[dict[str, Any]] = [
            {
                "entity": self._label_map.get(ent["label"], ent["label"]),
                "word": ent["text"],
                "start": ent["start"],
                "end": ent["end"],
                "score": round(ent["score"], 4),
            }
            for ent in deduped
        ]
        return _post_filter_gliner(normalized, label_map=self._label_map)


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
        *,
        min_score: float | None = None,
        label_map: dict[str, str] | None = None,
        block_singletons: list[str] | None = None,
        aggregation_strategy: str | None = None,
    ) -> None:
        """L5Layer 초기화.

        Args:
            model_name: NER 모델 폴더명(``model/`` 하위).
            extra_patterns: 추가 차단 정규식 리스트.
            min_score: NER 엔티티 신뢰도 임계값. ``None`` 이면
                ``pii_labels.json`` 의 값을 사용하고, 값이 주어지면
                JSON 스펙을 override 한다.
            label_map: 모델 라벨을 정규화 PII 타입으로 매핑하는 규칙.
                ``None`` 이면 ``pii_labels.json`` 의 값을 사용한다.
            block_singletons: 단일 검출로 차단할 정규화 타입 목록.
                ``None`` 이면 ``pii_labels.json`` 의 값을 사용한다.
            aggregation_strategy: HuggingFace NER aggregation 전략.
                ``None`` 이면 ``pii_labels.json`` 의 값을 사용한다.
        """
        self.model_name = model_name
        self.extra_patterns: list[str] = (
            extra_patterns if extra_patterns is not None else []
        )
        # 생성자 override 값(로딩 후 스펙에 최우선 적용)
        self._min_score_override: float | None = min_score
        self._label_map_override: dict[str, str] | None = label_map
        self._block_singletons_override: list[str] | None = block_singletons
        self._aggregation_strategy_override: str | None = aggregation_strategy
        # pii_labels 스펙 속성(로딩 과정에서 채워짐)
        self._label_map: dict[str, str] = {}
        self._block_singletons: list[str] = []
        self._block_combinations: list[list[str]] = []
        self._min_score: float = 0.0
        self._aggregation_strategy: str = "simple"
        # NER 어댑터 (None 이면 fail-open)
        self._adapter: (
            _HFPipelineAdapter | _HFCharLevelAdapter | _GLinerAdapter | None
        ) = None
        self._ner_model: Any = self._load_ner_model(model_name)

    @property
    def min_score(self) -> float:
        """현재 NER 스코어 컷오프."""
        return self._min_score

    @min_score.setter
    def min_score(self, value: float) -> None:
        self._min_score = float(value)

    @property
    def label_map(self) -> dict[str, str]:
        """현재 라벨 정규화 맵."""
        return self._label_map

    @label_map.setter
    def label_map(self, value: dict[str, str]) -> None:
        self._label_map = dict(value)

    @property
    def block_singletons(self) -> list[str]:
        """단일 검출만으로 차단할 PII 타입 목록."""
        return self._block_singletons

    @block_singletons.setter
    def block_singletons(self, value: list[str]) -> None:
        self._block_singletons = list(value)

    @property
    def aggregation_strategy(self) -> str:
        """현재 HuggingFace NER aggregation 전략."""
        return self._aggregation_strategy

    @aggregation_strategy.setter
    def aggregation_strategy(self, value: str) -> None:
        self._aggregation_strategy = str(value)

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

        adapter: (
            _HFPipelineAdapter | _HFCharLevelAdapter | _GLinerAdapter | None
        )
        try:
            if adapter_kind == "hf-pipeline":
                adapter = _HFPipelineAdapter(model_path, spec)
            elif adapter_kind == "hf-charlevel":
                adapter = _HFCharLevelAdapter(model_path, spec)
            elif adapter_kind == "gliner":
                adapter = _GLinerAdapter(model_path, spec)
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
        self._label_map = dict(
            spec.get("label_map", {})
            if self._label_map_override is None
            else self._label_map_override,
        )
        self._block_singletons = list(
            spec.get("block_singletons", [])
            if self._block_singletons_override is None
            else self._block_singletons_override,
        )
        self._block_combinations = [
            list(rule) for rule in spec.get("block_combinations", [])
        ]
        if self._min_score_override is not None:
            self._min_score = float(self._min_score_override)
        else:
            self._min_score = float(spec.get("min_score", 0.0))
        self._aggregation_strategy = str(
            spec.get("aggregation_strategy", "simple")
            if self._aggregation_strategy_override is None
            else self._aggregation_strategy_override,
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
        except (OSError, json.JSONDecodeError):
            try:
                id2label = dict(ner_model.model.config.id2label)
            except (AttributeError, TypeError):
                id2label = {}

        label_map: dict[str, str] = {}
        for raw_label in id2label.values():
            clean = _strip_bio_prefix(str(raw_label))
            if not clean or clean == "O":
                continue
            label_map[clean] = clean

        self._label_map = (
            label_map
            if self._label_map_override is None
            else dict(self._label_map_override)
        )
        self._block_singletons = (
            list(label_map.keys())
            if self._block_singletons_override is None
            else list(self._block_singletons_override)
        )
        self._block_combinations = []
        if self._min_score_override is not None:
            self._min_score = float(self._min_score_override)
        else:
            self._min_score = 0.0
        self._aggregation_strategy = (
            "simple"
            if self._aggregation_strategy_override is None
            else str(self._aggregation_strategy_override)
        )

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
            # 어댑터 출력이 정규화된 entity 키를 노출할 수도 있으므로
            # label_map 미존재 시 clean_label 자체를 정규화 타입으로 사용.
            mapped = self._label_map.get(clean_label)
            if mapped is not None:
                pii_type: str = mapped
            elif clean_label in self._block_singletons or any(
                clean_label in rule for rule in self._block_combinations
            ):
                pii_type = clean_label
            else:
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
