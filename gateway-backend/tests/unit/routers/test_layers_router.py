"""/v1/layers/status 라우터 테스트.

실제 core-secure-layer 모델 로드 결과가 아닌, ``collect_layer_statuses``
반환값을 monkeypatch 로 교체해 엔드포인트 응답 스키마와 ``all_loaded``
계산 로직을 검증한다.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import layers as layers_router
from app.services.layer_diagnostics import LayerStatus

client = TestClient(app)


def _make_fake_statuses(with_failure: bool) -> list[LayerStatus]:
    """테스트용 가짜 LayerStatus 리스트를 만든다."""
    ok = [
        LayerStatus(
            index=1,
            name="L1",
            class_name="L1Layer",
            model_loaded=True,
            model_paths=[],
            detail="규칙 기반, 모델 없음",
        ),
        LayerStatus(
            index=2,
            name="L2",
            class_name="L2Layer",
            model_loaded=True,
            model_paths=["/app/.../l2/model/gpt2"],
            detail=None,
        ),
    ]
    if with_failure:
        ok.append(
            LayerStatus(
                index=3,
                name="L3",
                class_name="L3Layer",
                model_loaded=False,
                model_paths=["/app/.../l3/model/mini"],
                detail="_model_loaded=False path=/app/.../l3/model/mini",
            )
        )
    return ok


def test_layers_status_returns_all_loaded_true_when_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """모든 레이어 loaded=True 면 all_loaded=true."""
    monkeypatch.setattr(
        layers_router,
        "collect_layer_statuses",
        lambda: _make_fake_statuses(with_failure=False),
    )
    response = client.get("/v1/layers/status")
    assert response.status_code == 200
    body = response.json()
    assert body["all_loaded"] is True
    assert len(body["layers"]) == 2
    assert body["layers"][0]["name"] == "L1"
    assert body["layers"][0]["model_loaded"] is True


def test_layers_status_returns_all_loaded_false_on_any_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """하나라도 loaded=False 면 all_loaded=false."""
    monkeypatch.setattr(
        layers_router,
        "collect_layer_statuses",
        lambda: _make_fake_statuses(with_failure=True),
    )
    response = client.get("/v1/layers/status")
    assert response.status_code == 200
    body = response.json()
    assert body["all_loaded"] is False
    failing = [layer for layer in body["layers"] if not layer["model_loaded"]]
    assert len(failing) == 1
    assert failing[0]["name"] == "L3"
    assert "loaded=False" in (failing[0]["detail"] or "")


def test_layers_status_schema_exposes_required_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """응답 각 항목이 index/name/class_name/model_loaded 등 필수 필드를 포함."""
    monkeypatch.setattr(
        layers_router,
        "collect_layer_statuses",
        lambda: _make_fake_statuses(with_failure=False),
    )
    body = client.get("/v1/layers/status").json()
    required_keys = {
        "index",
        "name",
        "class_name",
        "model_loaded",
        "model_paths",
        "detail",
    }
    for layer in body["layers"]:
        assert required_keys.issubset(layer.keys())


def test_layers_status_empty_layer_map_returns_all_loaded_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """레이어가 하나도 수집되지 않으면 all_loaded=false (안전 기본값)."""
    monkeypatch.setattr(
        layers_router,
        "collect_layer_statuses",
        lambda: [],
    )
    body = client.get("/v1/layers/status").json()
    assert body["all_loaded"] is False
    assert body["layers"] == []


def test_layers_status_exposed_in_openapi_schema() -> None:
    """엔드포인트가 OpenAPI 문서에 등록된다."""
    openapi = client.get("/openapi.json").json()
    assert "/v1/layers/status" in openapi["paths"]
    operation = openapi["paths"]["/v1/layers/status"]["get"]
    assert "meta" in operation["tags"]
