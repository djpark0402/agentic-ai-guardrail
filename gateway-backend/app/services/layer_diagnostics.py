"""각 가드레일 레이어의 모델 로드 상태와 실제 동작 가능 여부를 진단한다.

docker 로 배포된 컨테이너 안에서 L1~L6 각 레이어가 단순히 모델을
로드하는 것을 넘어, 실제로 BLOCK 판정을 낼 수 있는 상태인지까지
확인하기 위한 헬퍼. 기존 fail-open 정책을 유지하면서
(a) 앱 기동 시 요약 로그, (b) ``/v1/layers/status`` HTTP 엔드포인트의
단일 진실 공급원(single source of truth) 으로 사용된다.

core-secure-layer 의 각 레이어는 로드 신호와 "실제로 판정을 낼 수 있는
상태" 의 조건이 서로 다르다:

- L2 는 `_model_loaded` 플래그만 True 면 충분.
- L3 는 chromadb 컬렉션에 공격 패턴이 실제로 적재되어 있어야 매칭이 일어남.
- L4 는 NLI 모델이 로드되었어도 `_nli_rules` 가 비어 있으면 NLI 단계
  자체를 스킵하고, `_llm` 이 없으면 최종 LLM 판정 단계를 스킵한다.
  즉 "로드 성공 != 실제 BLOCK 가능".
- L5 는 NER 모델 로드에 더해 규칙 기반 regex 경로도 존재한다.
- L6 은 `_model_loaded` 플래그만 True 면 충분.

gateway-backend 쪽에서 레이어 인덱스별 probe 함수를 매핑하는 방식으로
이 차이를 흡수한다. core-secure-layer 는 수정하지 않는다.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.layer_registry import _LAYER_MAP

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LayerStatus:
    """단일 레이어의 모델 로드/동작 진단 결과."""

    index: int
    name: str
    class_name: str
    model_loaded: bool
    # loaded 와 별개로, 이 레이어가 지금 상태에서 실제로 BLOCK 판정을
    # 낼 수 있는지. False 이면 호출되더라도 조용히 PASS.
    effective: bool
    # 레이어별 런타임 보조 상태 (rules 개수, collection count, llm 연결
    # 여부 등). 엔드포인트 응답과 로그에서 투명하게 노출된다.
    signals: dict[str, Any] = field(default_factory=dict)
    model_paths: list[str] = field(default_factory=list)
    detail: str | None = None


def _layer_base_dir(layer: Any) -> Path | None:
    """레이어 클래스가 정의된 파이썬 파일의 디렉터리를 반환한다.

    Args:
        layer: core-secure-layer BaseLayer 인스턴스.

    Returns:
        해당 레이어 모듈의 디렉터리 경로. 실패 시 ``None``.
    """
    try:
        file = inspect.getfile(layer.__class__)
    except TypeError:
        return None
    return Path(file).resolve().parent


def _safe_count(collection: Any) -> int | None:
    """Chromadb collection 의 레코드 수를 안전하게 조회한다.

    Args:
        collection: ``_collection`` 속성. None 이면 ``None`` 반환.

    Returns:
        count 값. 조회 실패/예외 시 ``None``.
    """
    if collection is None:
        return None
    try:
        return int(collection.count())
    except Exception:
        return None


def _probe_l1(layer: Any) -> LayerStatus:
    """L1 은 규칙 기반이라 항상 loaded/effective=True."""
    return LayerStatus(
        index=1,
        name="L1",
        class_name=type(layer).__name__,
        model_loaded=True,
        effective=True,
        signals={"rule_based": True},
        model_paths=[],
        detail="규칙 기반, 모델 없음",
    )


def _probe_l2(layer: Any) -> LayerStatus:
    """L2: `_model_loaded` 만 True 면 동작 가능."""
    loaded = bool(getattr(layer, "_model_loaded", False))
    model_path = getattr(layer, "model_path", None)
    paths = [str(model_path)] if model_path else []
    return LayerStatus(
        index=2,
        name="L2",
        class_name=type(layer).__name__,
        model_loaded=loaded,
        effective=loaded,
        signals={"perplexity_ready": loaded},
        model_paths=paths,
        detail=None if loaded else f"_model_loaded=False path={model_path}",
    )


def _probe_l3(layer: Any) -> LayerStatus:
    """L3: 임베딩 모델 + chromadb 공격 패턴 컬렉션이 있어야 매칭 가능."""
    loaded = bool(getattr(layer, "_model_loaded", False))
    collection = getattr(layer, "_collection", None)
    count = _safe_count(collection)

    signals: dict[str, Any] = {
        "embedding_ready": loaded,
        "attack_patterns_collection": collection is not None,
        "attack_patterns_count": count,
    }
    effective = loaded and collection is not None and (count or 0) > 0

    model_path = getattr(layer, "model_path", None)
    paths = [str(model_path)] if model_path else []
    detail_parts = []
    if not loaded:
        detail_parts.append("_model_loaded=False")
    if collection is None:
        detail_parts.append("_collection=None")
    elif (count or 0) == 0:
        detail_parts.append("attack_patterns_count=0")
    detail = " ".join(detail_parts) if detail_parts else None

    return LayerStatus(
        index=3,
        name="L3",
        class_name=type(layer).__name__,
        model_loaded=loaded,
        effective=effective,
        signals=signals,
        model_paths=paths,
        detail=detail,
    )


def _probe_l4(layer: Any) -> LayerStatus:
    """L4: NLI 3종 모델 + nli_rules + policy collection + llm.

    BLOCK 을 낼 수 있는 경로는 두 가지:

    - NLI 단계: ``_nli_model`` 로드 + ``_nli_rules`` 비어 있지 않음.
    - 벡터 → LLM 단계: ``_embed_model`` + ``_collection`` (policy chunks)
      + ``_reranker_model`` + ``_llm`` 전부 존재.

    둘 중 하나라도 완전하지 않으면 해당 경로는 조용히 PASS 된다.
    두 경로 모두 스킵되면 ``effective=False``.
    """
    nli = getattr(layer, "_nli_model", None)
    embed = getattr(layer, "_embed_model", None)
    reranker = getattr(layer, "_reranker_model", None)
    llm = getattr(layer, "_llm", None)
    rules = getattr(layer, "_nli_rules", None) or []
    collection = getattr(layer, "_collection", None)

    all_models_loaded = all(m is not None for m in (nli, embed, reranker))
    rules_count = len(rules) if hasattr(rules, "__len__") else 0
    policy_count = _safe_count(collection)

    nli_path_ok = nli is not None and rules_count > 0
    vector_path_ok = (
        embed is not None
        and reranker is not None
        and collection is not None
        and (policy_count or 0) > 0
        and llm is not None
    )
    effective = nli_path_ok or vector_path_ok

    signals: dict[str, Any] = {
        "nli_model_loaded": nli is not None,
        "embed_model_loaded": embed is not None,
        "reranker_model_loaded": reranker is not None,
        "nli_rules_count": rules_count,
        "policy_collection_count": policy_count,
        "llm_attached": llm is not None,
        "nli_path_ok": nli_path_ok,
        "vector_llm_path_ok": vector_path_ok,
    }

    base = _layer_base_dir(layer)
    paths = [str(base / "model")] if base is not None else []

    detail_parts = []
    if not all_models_loaded:
        detail_parts.append(
            "models="
            f"nli={'OK' if nli else 'None'}"
            f"/embed={'OK' if embed else 'None'}"
            f"/reranker={'OK' if reranker else 'None'}"
        )
    if not effective:
        if rules_count == 0:
            detail_parts.append("nli_rules=0(NLI 스킵)")
        if llm is None:
            detail_parts.append("llm=None(LLM 판단 스킵)")
        if collection is None or (policy_count or 0) == 0:
            detail_parts.append("policy_collection 비어 있음")

    return LayerStatus(
        index=4,
        name="L4",
        class_name=type(layer).__name__,
        model_loaded=all_models_loaded,
        effective=effective,
        signals=signals,
        model_paths=paths,
        detail=" ".join(detail_parts) if detail_parts else None,
    )


def _probe_l5(layer: Any) -> LayerStatus:
    """L5: NER 모델이 로드됐거나 regex 경로가 살아 있으면 동작 가능.

    L5 는 ``_check_regex`` 와 ``_check_ner`` 를 순차로 호출하므로,
    NER 모델이 없더라도 regex 규칙만으로 일부 PII 는 잡을 수 있다.
    """
    ner = getattr(layer, "_ner_model", None)
    ner_loaded = ner is not None

    # _check_regex 는 항상 존재하는 메서드이므로 regex 경로는 사실상
    # 언제나 살아 있음 — 실제 룰 개수까지 들여다보는 것은 공개 API 가
    # 아니라 over-engineering. 여기서는 메서드 존재 여부만 체크.
    regex_ready = callable(getattr(layer, "_check_regex", None))

    effective = ner_loaded or regex_ready

    signals: dict[str, Any] = {
        "ner_model_loaded": ner_loaded,
        "regex_ready": regex_ready,
        "model_name": getattr(layer, "model_name", None),
    }

    base = _layer_base_dir(layer)
    paths: list[str] = []
    if base is not None:
        name = getattr(layer, "model_name", "")
        target = base / "model" / name if name else base / "model"
        paths.append(str(target))

    detail = None if ner_loaded else "_ner_model=None (regex 만 동작)"
    return LayerStatus(
        index=5,
        name="L5",
        class_name=type(layer).__name__,
        model_loaded=ner_loaded,
        effective=effective,
        signals=signals,
        model_paths=paths,
        detail=detail,
    )


def _probe_l6(layer: Any) -> LayerStatus:
    """L6: `_model_loaded` 플래그 하나로 충분."""
    loaded = bool(getattr(layer, "_model_loaded", False))
    signals = {
        "safety_model_loaded": loaded,
        "model_name": getattr(layer, "model_name", None),
    }

    base = _layer_base_dir(layer)
    paths: list[str] = []
    if base is not None:
        name = getattr(layer, "model_name", "")
        target = base / "model" / name if name else base / "model"
        paths.append(str(target))

    return LayerStatus(
        index=6,
        name="L6",
        class_name=type(layer).__name__,
        model_loaded=loaded,
        effective=loaded,
        signals=signals,
        model_paths=paths,
        detail=None if loaded else "_model_loaded=False",
    )


_ProbeFn = Callable[[Any], LayerStatus]

_PROBES: dict[int, _ProbeFn] = {
    1: _probe_l1,
    2: _probe_l2,
    3: _probe_l3,
    4: _probe_l4,
    5: _probe_l5,
    6: _probe_l6,
}


def collect_layer_statuses(
    layer_map: dict[int, Any] | None = None,
) -> list[LayerStatus]:
    """레이어 매핑을 순회하며 로드/동작 상태를 수집한다.

    Args:
        layer_map: 인덱스→레이어 인스턴스 매핑. 기본값은
            ``app.services.layer_registry._LAYER_MAP``. 테스트에서
            가짜 레이어를 주입할 때 사용.

    Returns:
        정책 인덱스 오름차순으로 정렬된 ``LayerStatus`` 리스트.
    """
    source = layer_map if layer_map is not None else _LAYER_MAP
    statuses: list[LayerStatus] = []
    for index in sorted(source):
        layer = source[index]
        probe = _PROBES.get(index)
        if probe is None:
            statuses.append(
                LayerStatus(
                    index=index,
                    name=f"L{index}",
                    class_name=type(layer).__name__,
                    model_loaded=False,
                    effective=False,
                    signals={},
                    model_paths=[],
                    detail="probe 미정의",
                )
            )
            continue
        statuses.append(probe(layer))
    return statuses


def _format_signals(signals: dict[str, Any]) -> str:
    """로그 한 줄에 들어갈 간결한 `key=value` 포맷."""
    if not signals:
        return ""
    return " signals={" + " ".join(f"{k}={v}" for k, v in signals.items()) + "}"


def log_layer_statuses(statuses: list[LayerStatus]) -> None:
    """수집된 상태를 INFO / WARNING 으로 한 줄씩 출력한다.

    - ``effective=True`` 이면 INFO.
    - ``effective=False`` 이면 WARNING. 운영자는 ``grep "effective=False"``
      한 번으로 "로드는 됐지만 실제로는 판정을 못 내는 레이어" 를 잡을 수
      있다.
    """
    logger.info("레이어 로드 상태 요약:")
    for status in statuses:
        path_str = (
            f" path={status.model_paths[0]}" if status.model_paths else ""
        )
        detail_str = f" detail={status.detail}" if status.detail else ""
        signals_str = _format_signals(status.signals)
        template = "  %s %s loaded=%s effective=%s%s%s%s"
        args = (
            status.name,
            status.class_name,
            status.model_loaded,
            status.effective,
            signals_str,
            path_str,
            detail_str,
        )
        if status.effective:
            logger.info(template, *args)
        else:
            logger.warning(template, *args)
