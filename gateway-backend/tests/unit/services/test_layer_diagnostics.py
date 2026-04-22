"""layer_diagnostics 모듈 테스트.

실제 core-secure-layer 인스턴스를 사용하지 않고, 각 레이어의 속성 구조만
흉내낸 더미 객체(fake)에 probe 함수를 적용해 ``LayerStatus`` 결과를 검증한다.
layer_map DI 를 통해 실제 `_LAYER_MAP` 로딩을 우회한다.
"""

from __future__ import annotations

import inspect
import logging
from pathlib import Path
from typing import Any

import pytest

from app.services import layer_diagnostics
from app.services.layer_diagnostics import (
    LayerStatus,
    collect_layer_statuses,
    log_layer_statuses,
)


class _FakeLayer:
    """레이어 속성을 자유롭게 부착할 수 있는 더미 베이스.

    ``inspect.getfile`` 이 사용하는 `__class__` 파일 경로는 테스트 대상
    모듈 파일로 해석되는데, 이는 probe 가 base_dir 을 계산할 수 있음을
    확인하기에 충분하다.
    """

    def __init__(self, **attrs: Any) -> None:
        for key, value in attrs.items():
            setattr(self, key, value)


class _FakeL1(_FakeLayer):
    pass


class _FakeL2(_FakeLayer):
    pass


class _FakeL3(_FakeLayer):
    pass


class _FakeL4(_FakeLayer):
    pass


class _FakeL5(_FakeLayer):
    pass


class _FakeL6(_FakeLayer):
    pass


# ---------- 개별 probe 검증 ----------


def test_l1_probe_always_loaded() -> None:
    """L1 은 모델이 없으므로 항상 loaded=True."""
    status = collect_layer_statuses({1: _FakeL1()})[0]
    assert status.index == 1
    assert status.name == "L1"
    assert status.model_loaded is True
    assert status.model_paths == []
    assert status.detail == "규칙 기반, 모델 없음"


def test_l2_probe_loaded_flag_true() -> None:
    """L2 _model_loaded=True + model_path 가 주어지면 loaded=True."""
    fake = _FakeL2(_model_loaded=True, model_path="/app/.../l2/model/gpt2")
    status = collect_layer_statuses({2: fake})[0]
    assert status.index == 2
    assert status.name == "L2"
    assert status.model_loaded is True
    assert status.model_paths == ["/app/.../l2/model/gpt2"]
    assert status.detail is None


def test_l3_probe_loaded_flag_false() -> None:
    """L3 _model_loaded=False 인 경우 detail 에 path 가 포함된다."""
    fake = _FakeL3(_model_loaded=False, model_path="/app/.../l3/model/mini")
    status = collect_layer_statuses({3: fake})[0]
    assert status.model_loaded is False
    assert "/app/.../l3/model/mini" in (status.detail or "")
    assert status.model_paths == ["/app/.../l3/model/mini"]


def test_l3_probe_missing_attributes_treated_as_unloaded() -> None:
    """속성이 아예 없어도 loaded=False 로 안전하게 처리된다."""
    status = collect_layer_statuses({3: _FakeL3()})[0]
    assert status.model_loaded is False
    assert status.model_paths == []


def test_l4_probe_all_three_models_required() -> None:
    """L4 는 세 모델 중 하나라도 None 이면 loaded=False."""
    loaded_fake = _FakeL4(
        _nli_model=object(),
        _embed_model=object(),
        _reranker_model=object(),
    )
    partial_fake = _FakeL4(
        _nli_model=object(),
        _embed_model=None,
        _reranker_model=object(),
    )

    ok_status = collect_layer_statuses({4: loaded_fake})[0]
    partial_status = collect_layer_statuses({4: partial_fake})[0]

    assert ok_status.model_loaded is True
    assert ok_status.detail is None

    assert partial_status.model_loaded is False
    assert "embed=None" in (partial_status.detail or "")
    assert "nli=OK" in (partial_status.detail or "")
    assert "reranker=OK" in (partial_status.detail or "")


def test_l5_probe_uses_ner_model_attribute() -> None:
    """L5 는 `_ner_model` 이 None 이 아니면 loaded."""
    fake_loaded = _FakeL5(_ner_model=object(), model_name="ner-ko")
    fake_unloaded = _FakeL5(_ner_model=None, model_name="ner-ko")

    ok = collect_layer_statuses({5: fake_loaded})[0]
    bad = collect_layer_statuses({5: fake_unloaded})[0]

    assert ok.model_loaded is True
    assert any("ner-ko" in p for p in ok.model_paths)
    assert bad.model_loaded is False
    assert bad.detail == "_ner_model=None"


def test_l6_probe_uses_model_loaded_flag() -> None:
    """L6 는 `_model_loaded` + `model_name` 조합."""
    fake = _FakeL6(_model_loaded=True, model_name="kanana-safeguard-8b")
    status = collect_layer_statuses({6: fake})[0]
    assert status.model_loaded is True
    assert any("kanana-safeguard-8b" in p for p in status.model_paths)


def test_unknown_layer_index_produces_not_defined_status() -> None:
    """probe 가 등록되지 않은 인덱스는 loaded=False 로 안전하게 리포트한다."""
    statuses = collect_layer_statuses({99: _FakeLayer()})
    assert statuses[0].model_loaded is False
    assert statuses[0].detail == "probe 미정의"


# ---------- collect_layer_statuses 통합 동작 ----------


def test_collect_sorts_statuses_by_index() -> None:
    """수집 결과는 인덱스 오름차순으로 정렬된다."""
    layer_map = {
        3: _FakeL3(_model_loaded=True, model_path="/p3"),
        1: _FakeL1(),
        2: _FakeL2(_model_loaded=True, model_path="/p2"),
    }
    statuses = collect_layer_statuses(layer_map)
    assert [s.index for s in statuses] == [1, 2, 3]


def test_collect_uses_layer_registry_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """layer_map 을 주지 않으면 `_LAYER_MAP` 을 사용한다."""
    sentinel_map = {1: _FakeL1()}
    monkeypatch.setattr(layer_diagnostics, "_LAYER_MAP", sentinel_map)
    result = collect_layer_statuses()
    assert len(result) == 1
    assert result[0].index == 1
    assert result[0].model_loaded is True


# ---------- log_layer_statuses 출력 레벨 ----------


def test_log_layer_statuses_uses_info_when_all_loaded(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """모든 레이어 loaded=True 이면 WARNING 이 발생하지 않는다."""
    statuses = [
        LayerStatus(
            index=1,
            name="L1",
            class_name="L1Layer",
            model_loaded=True,
            model_paths=[],
            detail=None,
        ),
        LayerStatus(
            index=2,
            name="L2",
            class_name="L2Layer",
            model_loaded=True,
            model_paths=["/x"],
            detail=None,
        ),
    ]
    with caplog.at_level(
        logging.DEBUG, logger="app.services.layer_diagnostics"
    ):
        log_layer_statuses(statuses)
    levels = {rec.levelno for rec in caplog.records}
    assert logging.WARNING not in levels
    assert logging.INFO in levels


def test_log_layer_statuses_raises_warning_on_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """하나라도 loaded=False 면 그 줄만 WARNING 레벨로 출력된다."""
    statuses = [
        LayerStatus(
            index=2,
            name="L2",
            class_name="L2Layer",
            model_loaded=False,
            model_paths=["/missing"],
            detail="_model_loaded=False path=/missing",
        ),
    ]
    with caplog.at_level(
        logging.DEBUG, logger="app.services.layer_diagnostics"
    ):
        log_layer_statuses(statuses)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "loaded=False" in warnings[0].getMessage()


# ---------- _layer_base_dir helper ----------


def test_layer_base_dir_returns_module_directory() -> None:
    """inspect 가 클래스 파일을 찾을 수 있는 경우 디렉터리를 반환한다."""
    base = layer_diagnostics._layer_base_dir(_FakeLayer())
    assert isinstance(base, Path)
    expected = Path(inspect.getfile(_FakeLayer)).resolve().parent
    assert base == expected


def test_layer_base_dir_returns_none_for_builtin() -> None:
    """`inspect.getfile` 이 실패하는 경우 None 을 반환한다."""
    with pytest.raises(TypeError):
        inspect.getfile(object)
    assert layer_diagnostics._layer_base_dir(object()) is None
