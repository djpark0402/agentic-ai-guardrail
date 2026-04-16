"""Request/Response 타입 단위 테스트."""

from dataclasses import FrozenInstanceError

import pytest

from core_secure_layer.layers.types import (
    CheckPhase,
    GuardrailRequest,
    GuardrailResponse,
    LayerResult,
    Severity,
)


class TestSeverityEnum:
    """Severity 열거형 테스트."""

    def test_values(self) -> None:
        assert Severity.NONE == "none"
        assert Severity.LOW == "low"
        assert Severity.MEDIUM == "medium"
        assert Severity.HIGH == "high"
        assert Severity.CRITICAL == "critical"

    def test_ordering(self) -> None:
        ordered = sorted(Severity, key=list(Severity).index)
        assert ordered == [
            Severity.NONE,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def test_str_serialization(self) -> None:
        assert str(Severity.CRITICAL) == "critical"
        assert Severity.CRITICAL.value == "critical"


class TestCheckPhaseEnum:
    """CheckPhase 열거형 테스트."""

    def test_values(self) -> None:
        assert CheckPhase.PRE_LLM == "pre_llm"
        assert CheckPhase.POST_LLM == "post_llm"

    def test_members_count(self) -> None:
        assert len(CheckPhase) == 2


class TestGuardrailRequest:
    """GuardrailRequest 데이터클래스 테스트."""

    def test_required_field(self) -> None:
        req = GuardrailRequest(user_input="hello")
        assert req.user_input == "hello"

    def test_optional_defaults(self) -> None:
        req = GuardrailRequest(user_input="hello")
        assert req.session_id is None
        assert req.metadata is None

    def test_all_fields(self) -> None:
        req = GuardrailRequest(
            user_input="hello",
            session_id="sess-123",
            metadata={"model": "gpt-4"},
        )
        assert req.session_id == "sess-123"
        assert req.metadata == {"model": "gpt-4"}

    def test_frozen(self) -> None:
        req = GuardrailRequest(user_input="hello")
        with pytest.raises(FrozenInstanceError):
            req.user_input = "changed"  # type: ignore[misc]


class TestLayerResult:
    """LayerResult 데이터클래스 테스트."""

    def test_minimal_construction(self) -> None:
        result = LayerResult(name="L1", allowed=True)
        assert result.name == "L1"
        assert result.allowed is True
        assert result.reason is None

    def test_backward_compatible_defaults(self) -> None:
        result = LayerResult(name="L1", allowed=True)
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0
        assert result.execution_time_ms is None
        assert result.tags == []

    def test_full_construction(self) -> None:
        result = LayerResult(
            name="L3",
            allowed=False,
            reason="injection detected",
            severity=Severity.CRITICAL,
            confidence=0.95,
            execution_time_ms=12.5,
            tags=["injection", "xss"],
        )
        assert result.severity == Severity.CRITICAL
        assert result.confidence == 0.95
        assert result.execution_time_ms == 12.5
        assert result.tags == ["injection", "xss"]

    def test_tags_independent_per_instance(self) -> None:
        r1 = LayerResult(name="L1", allowed=True)
        r2 = LayerResult(name="L2", allowed=True)
        r1.tags.append("test")
        assert r2.tags == []

    def test_confidence_rule_based_block(self) -> None:
        result = LayerResult(
            name="L1",
            allowed=False,
            confidence=0.0,
        )
        assert result.confidence == 0.0


class TestGuardrailResponse:
    """GuardrailResponse 데이터클래스 테스트."""

    def test_allowed_response(self) -> None:
        resp = GuardrailResponse(
            user_input="hello",
            allowed=True,
        )
        assert resp.allowed is True
        assert resp.results == []
        assert resp.blocked_by is None
        assert resp.severity == Severity.NONE
        assert resp.phase == CheckPhase.PRE_LLM

    def test_blocked_response(self) -> None:
        layer_result = LayerResult(
            name="L1",
            allowed=False,
            reason="forbidden token",
            severity=Severity.HIGH,
        )
        resp = GuardrailResponse(
            user_input="<script>alert(1)</script>",
            allowed=False,
            results=[layer_result],
            blocked_by="L1",
            reason="forbidden token",
            severity=Severity.HIGH,
        )
        assert resp.blocked_by == "L1"
        assert len(resp.results) == 1
        assert resp.severity == Severity.HIGH

    def test_total_time(self) -> None:
        resp = GuardrailResponse(
            user_input="hello",
            allowed=True,
            total_time_ms=45.2,
        )
        assert resp.total_time_ms == 45.2

    def test_post_llm_phase(self) -> None:
        resp = GuardrailResponse(
            user_input="hello",
            allowed=True,
            phase=CheckPhase.POST_LLM,
        )
        assert resp.phase == CheckPhase.POST_LLM

    def test_results_independent(self) -> None:
        r1 = GuardrailResponse(user_input="a", allowed=True)
        r2 = GuardrailResponse(user_input="b", allowed=True)
        r1.results.append(LayerResult(name="L1", allowed=True))
        assert r2.results == []


class TestBaseLayerRun:
    """BaseLayer.run() 타이밍 래퍼 테스트."""

    async def test_run_measures_time(self) -> None:
        from core_secure_layer.layers.base import BaseLayer

        class StubLayer(BaseLayer):
            name = "STUB"

            async def check(
                self,
                request: GuardrailRequest,
            ) -> LayerResult:
                return LayerResult(name=self.name, allowed=True)

        layer = StubLayer()
        req = GuardrailRequest(user_input="test")
        result = await layer.run(req)
        assert result.allowed is True
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_run_preserves_result_fields(
        self,
    ) -> None:
        from core_secure_layer.layers.base import BaseLayer

        class DetailedLayer(BaseLayer):
            name = "DETAIL"

            async def check(
                self,
                request: GuardrailRequest,
            ) -> LayerResult:
                return LayerResult(
                    name=self.name,
                    allowed=False,
                    reason="blocked",
                    severity=Severity.HIGH,
                    confidence=0.0,
                    tags=["test"],
                )

        layer = DetailedLayer()
        req = GuardrailRequest(user_input="test")
        result = await layer.run(req)
        assert result.allowed is False
        assert result.reason == "blocked"
        assert result.severity == Severity.HIGH
        assert result.confidence == 0.0
        assert result.tags == ["test"]
        assert result.execution_time_ms is not None
