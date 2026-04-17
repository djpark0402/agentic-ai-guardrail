"""layer_registry 모듈 테스트."""

from core_secure_layer.layers.l1.l1 import L1Layer
from core_secure_layer.layers.l6.l6 import L6Layer

from app.services.layer_registry import get_layer


def test_get_layer_returns_l1_for_index_1():
    """policy index 1은 L1Layer 인스턴스를 반환한다."""
    layer = get_layer(1)
    assert isinstance(layer, L1Layer)


def test_get_layer_returns_l6_for_index_6():
    """policy index 6은 L6Layer 인스턴스를 반환한다."""
    layer = get_layer(6)
    assert isinstance(layer, L6Layer)


def test_get_layer_returns_none_for_index_0():
    """policy index 0은 매핑이 없으므로 None을 반환한다."""
    assert get_layer(0) is None


def test_get_layer_returns_none_for_out_of_range():
    """범위를 벗어난 index 7은 None을 반환한다."""
    assert get_layer(7) is None


def test_get_layer_returns_same_instance_on_repeated_calls():
    """동일 index에 대해 매번 같은 싱글턴 인스턴스를 반환한다."""
    assert get_layer(1) is get_layer(1)
