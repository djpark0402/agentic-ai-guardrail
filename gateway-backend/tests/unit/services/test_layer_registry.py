"""layer_registry 모듈 테스트."""

from core_secure_layer.layers.l1.l1 import L1Layer
from core_secure_layer.layers.l5.l5 import L5Layer
from core_secure_layer.layers.l6.l6 import L6Layer

from app.services.layer_registry import get_l5_layer, get_layer


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


def test_get_l5_layer_returns_default_singleton_without_policy_setting():
    """L5 정책 설정이 없으면 기존 기본 싱글턴을 사용한다."""
    assert get_l5_layer(model_name=None, threshold=None) is get_layer(5)


def test_get_l5_layer_caches_same_model_and_threshold(mocker):
    """같은 L5 model/threshold 조합은 같은 인스턴스로 재사용한다."""
    mocker.patch.object(L5Layer, "_load_ner_model", return_value=None)

    first = get_l5_layer(model_name="pii_model_v11", threshold=0.82)
    second = get_l5_layer(model_name="pii_model_v11", threshold=0.82)

    assert first is second
    assert first.model_name == "pii_model_v11"
    assert first.min_score == 0.82


def test_get_l5_layer_uses_distinct_cache_keys(mocker):
    """모델명 또는 threshold 가 달라지면 별도 L5 인스턴스를 사용한다."""
    mocker.patch.object(L5Layer, "_load_ner_model", return_value=None)

    first = get_l5_layer(model_name="pii_model_v11", threshold=0.82)
    second = get_l5_layer(model_name="ner-ko", threshold=0.82)
    third = get_l5_layer(model_name="pii_model_v11", threshold=0.7)

    assert first is not second
    assert first is not third
