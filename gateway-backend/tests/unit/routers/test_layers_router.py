"""/v1/layers/status 라우터 테스트.

실제 core-secure-layer 모델 로드 결과가 아닌, ``collect_layer_statuses``
반환값을 monkeypatch 로 교체해 엔드포인트 응답 스키마와 ``all_loaded`` /
``all_effective`` 계산 로직을 검증한다.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import layers as layers_router
from app.services.layer_diagnostics import LayerStatus

client = TestClient(app)


def _statuses(*, l4_effective: bool) -> list[LayerStatus]:
    """테스트용 가짜 LayerStatus 리스트를 만든다."""
    return [
        LayerStatus(
            index=1,
            name="L1",
            class_name="L1Layer",
            model_loaded=True,
            effective=True,
            signals={"rule_based": True},
        ),
        LayerStatus(
            index=4,
            name="L4",
            class_name="L4Layer",
            model_loaded=True,
            effective=l4_effective,
            signals={
                "nli_rules_count": 20 if l4_effective else 0,
                "policy_collection_count": 35,
                "llm_attached": l4_effective,
                "nli_path_ok": l4_effective,
                "vector_llm_path_ok": l4_effective,
            },
            detail=None
            if l4_effective
            else "nli_rules=0(NLI 스킵) llm=None(LLM 판단 스킵)",
        ),
    ]


def test_endpoint_returns_all_effective_true_when_each_effective(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        layers_router,
        "collect_layer_statuses",
        lambda: _statuses(l4_effective=True),
    )
    body = client.get("/v1/layers/status").json()
    assert body["all_loaded"] is True
    assert body["all_effective"] is True


def test_endpoint_all_effective_false_when_any_layer_ineffective(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """모든 모델은 로드됐지만 L4 의 rules/llm 이 비어 있는 실제 상황 재현."""
    monkeypatch.setattr(
        layers_router,
        "collect_layer_statuses",
        lambda: _statuses(l4_effective=False),
    )
    body = client.get("/v1/layers/status").json()
    assert body["all_loaded"] is True  # 모델은 다 로드됐다
    assert body["all_effective"] is False  # 하지만 실제로는 동작 안 한다
    l4 = next(x for x in body["layers"] if x["name"] == "L4")
    assert l4["signals"]["nli_rules_count"] == 0
    assert l4["signals"]["llm_attached"] is False
    assert "NLI 스킵" in l4["detail"]


def test_endpoint_exposes_all_required_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        layers_router,
        "collect_layer_statuses",
        lambda: _statuses(l4_effective=True),
    )
    body = client.get("/v1/layers/status").json()
    required_keys = {
        "index",
        "name",
        "class_name",
        "model_loaded",
        "effective",
        "signals",
        "model_paths",
        "detail",
    }
    for layer in body["layers"]:
        assert required_keys.issubset(layer.keys())


def test_endpoint_empty_layer_map_returns_all_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        layers_router,
        "collect_layer_statuses",
        lambda: [],
    )
    body = client.get("/v1/layers/status").json()
    assert body["all_loaded"] is False
    assert body["all_effective"] is False
    assert body["layers"] == []


def test_endpoint_exposed_in_openapi_schema() -> None:
    openapi = client.get("/openapi.json").json()
    assert "/v1/layers/status" in openapi["paths"]
    operation = openapi["paths"]["/v1/layers/status"]["get"]
    assert "meta" in operation["tags"]
