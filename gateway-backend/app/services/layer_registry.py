"""core-secure-layer 레이어 인스턴스 레지스트리.

policy 인덱스(1~6)를 core-secure-layer 의 레이어 싱글턴에 직접 매핑한다.
"""

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


def get_layer(layer_index: int) -> BaseLayer | None:
    """정책 인덱스에 해당하는 core-secure-layer 인스턴스를 반환한다.

    Args:
        layer_index: 레이어 인덱스 (1~6).

    Returns:
        매핑된 BaseLayer 인스턴스, 매핑이 없으면 None.
    """
    return _LAYER_MAP.get(layer_index)
