"""core-secure-layer 레이어 인스턴스 레지스트리.

policy 인덱스(1~6)를 core-secure-layer 의 레이어 싱글턴에 직접 매핑한다.
"""

from functools import lru_cache

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.l1.l1 import L1Layer
from core_secure_layer.layers.l2.l2 import L2Layer
from core_secure_layer.layers.l3.l3 import L3Layer
from core_secure_layer.layers.l4.l4 import L4Layer
from core_secure_layer.layers.l5.l5 import L5Layer
from core_secure_layer.layers.l6.l6 import L6Layer

_LAYER_MAP: dict[int, BaseLayer] = {
    1: L1Layer(),
    2: L2Layer(),
    3: L3Layer(),
    4: L4Layer(),
    5: L5Layer(),
    6: L6Layer(),
}


@lru_cache(maxsize=16)
def _get_configured_l5_layer(
    model_name: str | None,
    threshold: float | None,
) -> L5Layer:
    """정책 설정별 L5Layer 인스턴스를 생성해 재사용한다.

    Args:
        model_name: L5 모델 폴더명. None 이면 L5Layer 기본 모델을 쓴다.
        threshold: NER score 컷오프. None 이면 모델 계약 파일 값을 쓴다.

    Returns:
        설정에 맞게 생성된 L5Layer.
    """
    kwargs: dict[str, object] = {}
    if model_name:
        kwargs["model_name"] = model_name
    if threshold is not None:
        kwargs["min_score"] = threshold
    return L5Layer(**kwargs)


def get_layer(layer_index: int) -> BaseLayer | None:
    """정책 인덱스에 해당하는 core-secure-layer 인스턴스를 반환한다.

    Args:
        layer_index: 레이어 인덱스 (1~6).

    Returns:
        매핑된 BaseLayer 인스턴스, 매핑이 없으면 None.
    """
    return _LAYER_MAP.get(layer_index)


def get_l5_layer(
    *,
    model_name: str | None,
    threshold: float | None,
) -> BaseLayer:
    """ADMIN L5 정책 설정에 맞는 L5Layer 인스턴스를 반환한다.

    설정이 전혀 없으면 기존 레지스트리의 기본 L5 싱글턴을 그대로 반환해
    하위 호환성을 유지한다.

    Args:
        model_name: L5 모델 폴더명.
        threshold: L5 NER score 컷오프.

    Returns:
        기본 또는 설정별 캐시 L5Layer 인스턴스.
    """
    if model_name is None and threshold is None:
        return _LAYER_MAP[5]
    return _get_configured_l5_layer(model_name, threshold)
