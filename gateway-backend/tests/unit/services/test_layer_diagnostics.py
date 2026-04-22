"""layer_diagnostics 모듈 테스트.

실제 core-secure-layer 인스턴스를 사용하지 않고, 각 레이어의 속성 구조만
흉내낸 더미 객체(fake)에 probe 함수를 적용해 ``LayerStatus`` 결과를 검증한다.
``loaded`` 와 ``effective`` 가 별개로 계산되는지, ``signals`` 에 레이어별
상태가 실제로 담기는지 확인한다.
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
    """레이어 속성을 자유롭게 부착할 수 있는 더미 베이스."""

    def __init__(self, **attrs: Any) -> None:
        for key, value in attrs.items():
            setattr(self, key, value)


class _FakeCollection:
    """chromadb ``_collection`` 을 흉내내는 더미. ``count()`` 만 구현."""

    def __init__(self, n: int | Exception) -> None:
        self._n = n

    def count(self) -> int:
        if isinstance(self._n, Exception):
            raise self._n
        return self._n


class _FakeL1(_FakeLayer):
    pass


class _FakeL2(_FakeLayer):
    pass


class _FakeL3(_FakeLayer):
    pass


class _FakeL4(_FakeLayer):
    pass


class _FakeL5(_FakeLayer):
    def _check_regex(self, text: str) -> None:
        return None


class _FakeL6(_FakeLayer):
    pass


# ---------- L1 ----------


def test_l1_probe_always_loaded_and_effective() -> None:
    status = collect_layer_statuses({1: _FakeL1()})[0]
    assert status.model_loaded is True
    assert status.effective is True
    assert status.signals == {"rule_based": True}
    assert status.detail == "규칙 기반, 모델 없음"


# ---------- L2 ----------


def test_l2_loaded_and_effective_tracked_together() -> None:
    fake = _FakeL2(_model_loaded=True, model_path="/app/.../l2/model/gpt2")
    status = collect_layer_statuses({2: fake})[0]
    assert status.model_loaded is True
    assert status.effective is True
    assert status.signals == {"perplexity_ready": True}
    assert status.detail is None


def test_l2_unloaded_means_not_effective() -> None:
    fake = _FakeL2(_model_loaded=False, model_path="/p")
    status = collect_layer_statuses({2: fake})[0]
    assert status.model_loaded is False
    assert status.effective is False


# ---------- L3 ----------


def test_l3_effective_requires_model_and_non_empty_collection() -> None:
    fake = _FakeL3(
        _model_loaded=True,
        model_path="/p",
        _collection=_FakeCollection(210),
    )
    status = collect_layer_statuses({3: fake})[0]
    assert status.effective is True
    assert status.signals["attack_patterns_count"] == 210
    assert status.signals["embedding_ready"] is True


def test_l3_loaded_but_empty_collection_is_not_effective() -> None:
    fake = _FakeL3(
        _model_loaded=True,
        model_path="/p",
        _collection=_FakeCollection(0),
    )
    status = collect_layer_statuses({3: fake})[0]
    assert status.model_loaded is True
    assert status.effective is False
    assert status.signals["attack_patterns_count"] == 0
    assert "attack_patterns_count=0" in (status.detail or "")


def test_l3_missing_collection_is_not_effective() -> None:
    fake = _FakeL3(_model_loaded=True, _collection=None)
    status = collect_layer_statuses({3: fake})[0]
    assert status.effective is False
    assert status.signals["attack_patterns_collection"] is False


def test_l3_collection_count_exception_is_surfaced_as_none() -> None:
    fake = _FakeL3(
        _model_loaded=True,
        _collection=_FakeCollection(RuntimeError("boom")),
    )
    status = collect_layer_statuses({3: fake})[0]
    assert status.signals["attack_patterns_count"] is None
    assert status.effective is False


# ---------- L4 (핵심) ----------


def _l4_with(**overrides: Any) -> _FakeL4:
    """L4 의 모든 속성을 기본 "정상 상태" 로 채운 뒤 일부만 override."""
    defaults = {
        "_nli_model": object(),
        "_embed_model": object(),
        "_reranker_model": object(),
        "_llm": object(),
        "_nli_rules": [("cat", "rule1"), ("cat", "rule2")],
        "_collection": _FakeCollection(35),
    }
    defaults.update(overrides)
    return _FakeL4(**defaults)


def test_l4_fully_configured_is_effective() -> None:
    status = collect_layer_statuses({4: _l4_with()})[0]
    assert status.effective is True
    assert status.signals["nli_path_ok"] is True
    assert status.signals["vector_llm_path_ok"] is True
    assert status.signals["llm_attached"] is True
    assert status.signals["nli_rules_count"] == 2
    assert status.signals["policy_collection_count"] == 35


def test_l4_empty_nli_rules_disables_nli_path() -> None:
    """현재 배포 컨테이너에서 관측된 증상 재현: rules 가 0 개."""
    status = collect_layer_statuses({4: _l4_with(_nli_rules=[])})[0]
    # 벡터+LLM 경로가 살아 있으면 effective 는 True.
    assert status.signals["nli_path_ok"] is False
    assert status.signals["vector_llm_path_ok"] is True
    assert status.signals["nli_rules_count"] == 0
    assert status.effective is True
    # effective=True 일 때 detail 은 None (signals 로 충분히 드러남).
    assert status.detail is None


def test_l4_no_llm_disables_llm_path() -> None:
    """layer_registry.py 에서 L4Layer() 로 llm 없이 생성된 케이스."""
    status = collect_layer_statuses({4: _l4_with(_llm=None)})[0]
    assert status.signals["llm_attached"] is False
    assert status.signals["vector_llm_path_ok"] is False
    # nli_rules 는 살아 있으므로 nli 경로로 여전히 effective.
    assert status.effective is True


def test_l4_no_rules_and_no_llm_makes_layer_ineffective() -> None:
    """두 경로 모두 막힌, 현재 컨테이너에서 관측된 실제 상태."""
    status = collect_layer_statuses({4: _l4_with(_nli_rules=[], _llm=None)})[0]
    assert status.model_loaded is True  # 모델 자체는 다 로드됨
    assert status.effective is False  # 하지만 실제로 BLOCK 은 못 낸다
    assert status.signals["nli_path_ok"] is False
    assert status.signals["vector_llm_path_ok"] is False


def test_l4_model_missing_breaks_both_paths() -> None:
    status = collect_layer_statuses({4: _l4_with(_nli_model=None)})[0]
    assert status.model_loaded is False
    # nli_path 는 불가, vector_llm 경로는 embed/reranker/col/llm 이 있으므로 OK
    assert status.signals["nli_path_ok"] is False
    assert status.signals["vector_llm_path_ok"] is True
    assert status.effective is True


# ---------- L5 ----------


def test_l5_ner_loaded_and_regex_ready_is_effective() -> None:
    fake = _FakeL5(_ner_model=object(), model_name="ner-ko")
    status = collect_layer_statuses({5: fake})[0]
    assert status.model_loaded is True
    assert status.effective is True
    assert status.signals["ner_model_loaded"] is True
    assert status.signals["regex_ready"] is True


def test_l5_ner_missing_still_effective_via_regex() -> None:
    """NER 모델이 없어도 regex 경로가 살아 있으면 effective=True."""
    fake = _FakeL5(_ner_model=None, model_name="ner-ko")
    status = collect_layer_statuses({5: fake})[0]
    assert status.model_loaded is False
    assert status.effective is True
    assert status.signals["ner_model_loaded"] is False
    assert status.signals["regex_ready"] is True
    assert "regex" in (status.detail or "")


# ---------- L6 ----------


def test_l6_loaded_flag_drives_effective() -> None:
    fake = _FakeL6(_model_loaded=True, model_name="kanana-safeguard-8b")
    status = collect_layer_statuses({6: fake})[0]
    assert status.effective is True
    assert status.signals["safety_model_loaded"] is True


def test_l6_unloaded_is_not_effective() -> None:
    fake = _FakeL6(_model_loaded=False, model_name="kanana-safeguard-8b")
    status = collect_layer_statuses({6: fake})[0]
    assert status.effective is False
    assert any("kanana-safeguard-8b" in p for p in status.model_paths)


# ---------- 일반 ----------


def test_unknown_layer_index_produces_ineffective_status() -> None:
    statuses = collect_layer_statuses({99: _FakeLayer()})
    assert statuses[0].model_loaded is False
    assert statuses[0].effective is False
    assert statuses[0].detail == "probe 미정의"


def test_collect_sorts_statuses_by_index() -> None:
    layer_map = {
        3: _FakeL3(_model_loaded=True, _collection=_FakeCollection(1)),
        1: _FakeL1(),
        2: _FakeL2(_model_loaded=True),
    }
    statuses = collect_layer_statuses(layer_map)
    assert [s.index for s in statuses] == [1, 2, 3]


def test_collect_uses_layer_registry_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel_map = {1: _FakeL1()}
    monkeypatch.setattr(layer_diagnostics, "_LAYER_MAP", sentinel_map)
    result = collect_layer_statuses()
    assert len(result) == 1
    assert result[0].effective is True


# ---------- log_layer_statuses ----------


def test_log_uses_info_only_when_all_effective(
    caplog: pytest.LogCaptureFixture,
) -> None:
    statuses = [
        LayerStatus(
            index=1,
            name="L1",
            class_name="L1Layer",
            model_loaded=True,
            effective=True,
            signals={"rule_based": True},
        ),
    ]
    with caplog.at_level(
        logging.DEBUG, logger="app.services.layer_diagnostics"
    ):
        log_layer_statuses(statuses)
    assert all(r.levelno == logging.INFO for r in caplog.records)
    # 요약 라인 + 레이어 라인이 모두 찍혀야 하므로 최소 2건.
    assert len(caplog.records) >= 2
    summary = caplog.records[0].getMessage()
    assert "정상 동작 준비가 완료" in summary


def test_log_warns_on_ineffective_layer(
    caplog: pytest.LogCaptureFixture,
) -> None:
    statuses = [
        LayerStatus(
            index=4,
            name="L4",
            class_name="L4Layer",
            model_loaded=True,
            effective=False,
            signals={"nli_rules_count": 0, "llm_attached": False},
            detail="nli_rules=0 llm=None",
        ),
    ]
    with caplog.at_level(
        logging.DEBUG, logger="app.services.layer_diagnostics"
    ):
        log_layer_statuses(statuses)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    # 요약 라인 + 해당 레이어 라인이 모두 WARNING.
    assert len(warnings) == 2
    layer_msg = warnings[1].getMessage()
    assert "실패했습니다" in layer_msg
    # signals 키 이름은 운영자 grep 호환성을 위해 유지.
    assert "nli_rules_count=0" in layer_msg
    assert "llm_attached=False" in layer_msg


def test_log_success_uses_korean_verdict(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """effective=True 레이어 로그에 한국어 성공 문구가 들어가고,
    기존 영문 key=value 형식 판정 표현은 사라진다."""
    statuses = [
        LayerStatus(
            index=2,
            name="L2",
            class_name="L2Layer",
            model_loaded=True,
            effective=True,
            signals={"perplexity_ready": True},
            model_paths=["/app/core-secure-layer/.../l2/model/gpt2"],
        ),
    ]
    with caplog.at_level(
        logging.DEBUG, logger="app.services.layer_diagnostics"
    ):
        log_layer_statuses(statuses)
    layer_msg = caplog.records[1].getMessage()
    assert "로드 성공했습니다" in layer_msg
    assert "모델 경로: /app/core-secure-layer/.../l2/model/gpt2" in layer_msg
    # 기존 판정 표현은 제거.
    assert "loaded=True effective=True" not in layer_msg


def test_log_failure_explains_loaded_but_ineffective(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """loaded=True & effective=False 케이스는 '모델 파일은 로드되었지만'
    이라는 한국어 설명을 포함한다."""
    statuses = [
        LayerStatus(
            index=4,
            name="L4",
            class_name="L4Layer",
            model_loaded=True,
            effective=False,
            signals={"nli_rules_count": 0, "llm_attached": False},
            detail="nli_rules=0(NLI 스킵) llm=None(LLM 판단 스킵)",
        ),
    ]
    with caplog.at_level(
        logging.DEBUG, logger="app.services.layer_diagnostics"
    ):
        log_layer_statuses(statuses)
    layer_msg = caplog.records[1].getMessage()
    assert "실패했습니다" in layer_msg
    assert "모델 파일은 로드되었지만" in layer_msg


def test_log_failure_explains_load_failure_with_model_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """loaded=False & effective=False 케이스에 model_name signal 이
    있으면 고유명이 실패 사유에 노출된다."""
    statuses = [
        LayerStatus(
            index=6,
            name="L6",
            class_name="L6Layer",
            model_loaded=False,
            effective=False,
            signals={
                "safety_model_loaded": False,
                "model_name": "kanana-safeguard-8b",
            },
            model_paths=["/app/.../l6/model/kanana-safeguard-8b"],
            detail="_model_loaded=False",
        ),
    ]
    with caplog.at_level(
        logging.DEBUG, logger="app.services.layer_diagnostics"
    ):
        log_layer_statuses(statuses)
    layer_msg = caplog.records[1].getMessage()
    assert "실패했습니다" in layer_msg
    assert "모델 파일(kanana-safeguard-8b)" in layer_msg
    assert "호출되더라도 조용히 PASS" in layer_msg


def test_log_l4_partial_path_hint_when_only_nli_ok(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """L4 effective=True 지만 NLI 경로만 살아 있는 부분 가용 상태면,
    어느 경로로 동작 중이고 어느 경로가 비활성인지 설명 문장이 붙는다."""
    statuses = [
        LayerStatus(
            index=4,
            name="L4",
            class_name="L4Layer",
            model_loaded=True,
            effective=True,
            signals={
                "nli_model_loaded": True,
                "embed_model_loaded": True,
                "reranker_model_loaded": True,
                "nli_rules_count": 21,
                "policy_collection_count": 35,
                "llm_attached": False,
                "nli_path_ok": True,
                "vector_llm_path_ok": False,
            },
        ),
    ]
    with caplog.at_level(
        logging.DEBUG, logger="app.services.layer_diagnostics"
    ):
        log_layer_statuses(statuses)
    layer_msg = caplog.records[1].getMessage()
    assert "로드 성공했습니다" in layer_msg
    assert "NLI 규칙 기반 경로(규칙 21건)" in layer_msg
    assert "벡터+LLM 경로는 비활성" in layer_msg


def test_log_empty_statuses_emits_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """빈 리스트 입력시 레이어 부재를 알리는 WARNING 한 줄."""
    with caplog.at_level(
        logging.DEBUG, logger="app.services.layer_diagnostics"
    ):
        log_layer_statuses([])
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert (
        "레이어가 하나도 등록되지 않았습니다" in caplog.records[0].getMessage()
    )


# ---------- helpers ----------


def test_layer_base_dir_returns_module_directory() -> None:
    base = layer_diagnostics._layer_base_dir(_FakeLayer())
    assert isinstance(base, Path)
    expected = Path(inspect.getfile(_FakeLayer)).resolve().parent
    assert base == expected


def test_layer_base_dir_returns_none_for_builtin() -> None:
    with pytest.raises(TypeError):
        inspect.getfile(object)
    assert layer_diagnostics._layer_base_dir(object()) is None


def test_safe_count_handles_none_and_exception() -> None:
    assert layer_diagnostics._safe_count(None) is None
    assert layer_diagnostics._safe_count(_FakeCollection(7)) == 7
    assert (
        layer_diagnostics._safe_count(_FakeCollection(RuntimeError("x")))
        is None
    )
