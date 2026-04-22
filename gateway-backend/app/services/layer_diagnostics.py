"""각 가드레일 레이어의 모델 로드 상태를 진단/보고한다.

docker 로 배포된 컨테이너 안에서 L1~L6 각 레이어가 실제로 모델 파일을
정상 로드했는지 확인하기 위한 헬퍼. 기존 fail-open 정책을 유지하면서
(a) 앱 기동 시 요약 로그, (b) HTTP 엔드포인트에서 조회 가능한
단일 진실 공급원(single source of truth) 으로 사용된다.

core-secure-layer 의 각 레이어는 `"로드됨"` 을 표현하는 방식이
서로 다르므로(L2/L3/L6 는 `_model_loaded` 플래그, L4 는 세 개의
`_nli_model`/`_embed_model`/`_reranker_model`, L5 는 `_ner_model`),
gateway-backend 쪽에서 레이어 인덱스별 probe 함수를 매핑하는 방식으로
차이를 흡수한다. core-secure-layer 는 수정하지 않는다.
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
    """단일 레이어의 모델 로드 진단 결과."""

    index: int
    name: str
    class_name: str
    model_loaded: bool
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


def _probe_l1(layer: Any) -> LayerStatus:
    """L1 은 규칙 기반이라 항상 loaded 로 간주한다."""
    return LayerStatus(
        index=1,
        name="L1",
        class_name=type(layer).__name__,
        model_loaded=True,
        model_paths=[],
        detail="규칙 기반, 모델 없음",
    )


def _probe_flag_model_path(layer: Any, index: int) -> LayerStatus:
    """L2, L3 처럼 `_model_loaded` + `model_path` 를 공유하는 케이스.

    Args:
        layer: 레이어 인스턴스.
        index: 레이어 정책 인덱스.

    Returns:
        LayerStatus.
    """
    loaded = bool(getattr(layer, "_model_loaded", False))
    model_path = getattr(layer, "model_path", None)
    paths = [str(model_path)] if model_path else []
    detail = None if loaded else f"_model_loaded=False path={model_path}"
    return LayerStatus(
        index=index,
        name=f"L{index}",
        class_name=type(layer).__name__,
        model_loaded=loaded,
        model_paths=paths,
        detail=detail,
    )


def _probe_l4(layer: Any) -> LayerStatus:
    """L4 는 NLI/Embed/Reranker 세 모델이 모두 로드되어야 loaded."""
    nli = getattr(layer, "_nli_model", None)
    embed = getattr(layer, "_embed_model", None)
    reranker = getattr(layer, "_reranker_model", None)
    loaded = all(m is not None for m in (nli, embed, reranker))

    base = _layer_base_dir(layer)
    paths: list[str] = []
    if base is not None:
        paths.append(str(base / "model"))

    parts = [
        f"nli={'OK' if nli is not None else 'None'}",
        f"embed={'OK' if embed is not None else 'None'}",
        f"reranker={'OK' if reranker is not None else 'None'}",
    ]
    detail = None if loaded else " ".join(parts)
    return LayerStatus(
        index=4,
        name="L4",
        class_name=type(layer).__name__,
        model_loaded=loaded,
        model_paths=paths,
        detail=detail,
    )


def _probe_l5(layer: Any) -> LayerStatus:
    """L5 는 `_ner_model` 이 None 이 아니면 loaded."""
    ner = getattr(layer, "_ner_model", None)
    loaded = ner is not None

    base = _layer_base_dir(layer)
    paths: list[str] = []
    if base is not None:
        name = getattr(layer, "model_name", "")
        target = base / "model" / name if name else base / "model"
        paths.append(str(target))

    detail = None if loaded else "_ner_model=None"
    return LayerStatus(
        index=5,
        name="L5",
        class_name=type(layer).__name__,
        model_loaded=loaded,
        model_paths=paths,
        detail=detail,
    )


def _probe_l6(layer: Any) -> LayerStatus:
    """L6 는 `_model_loaded` 플래그를 사용하고 `model_path` 속성이 없다."""
    loaded = bool(getattr(layer, "_model_loaded", False))

    base = _layer_base_dir(layer)
    paths: list[str] = []
    if base is not None:
        name = getattr(layer, "model_name", "")
        target = base / "model" / name if name else base / "model"
        paths.append(str(target))

    detail = None if loaded else "_model_loaded=False"
    return LayerStatus(
        index=6,
        name="L6",
        class_name=type(layer).__name__,
        model_loaded=loaded,
        model_paths=paths,
        detail=detail,
    )


_ProbeFn = Callable[[Any], LayerStatus]

_PROBES: dict[int, _ProbeFn] = {
    1: _probe_l1,
    2: lambda layer: _probe_flag_model_path(layer, 2),
    3: lambda layer: _probe_flag_model_path(layer, 3),
    4: _probe_l4,
    5: _probe_l5,
    6: _probe_l6,
}


def collect_layer_statuses(
    layer_map: dict[int, Any] | None = None,
) -> list[LayerStatus]:
    """레이어 매핑을 순회하며 로드 상태를 수집한다.

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
                    model_paths=[],
                    detail="probe 미정의",
                )
            )
            continue
        statuses.append(probe(layer))
    return statuses


def log_layer_statuses(statuses: list[LayerStatus]) -> None:
    """수집된 상태를 INFO / WARNING 으로 한 줄씩 출력한다.

    전부 loaded 인 경우 INFO, 하나라도 실패한 경우 해당 라인만
    WARNING 으로 올려 운영자가 ``grep "loaded=False"`` 로
    바로 잡아낼 수 있게 한다.
    """
    logger.info("레이어 로드 상태 요약:")
    for status in statuses:
        path_str = (
            f" path={status.model_paths[0]}" if status.model_paths else ""
        )
        detail_str = f" detail={status.detail}" if status.detail else ""
        template = "  %s %s loaded=%s%s%s"
        args = (
            status.name,
            status.class_name,
            status.model_loaded,
            path_str,
            detail_str,
        )
        if status.model_loaded:
            logger.info(template, *args)
        else:
            logger.warning(template, *args)
