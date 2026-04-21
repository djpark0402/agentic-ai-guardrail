"""Guardrail 검사 결과 Pydantic 모델."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CheckStatus(StrEnum):
    """보안 검사 결과 상태 열거형.

    Attributes:
        PASS: 검사 통과.
        BLOCK: 검사 차단.
    """

    PASS = "pass"  # noqa: S105
    BLOCK = "block"


class GuardrailResult(BaseModel):
    """보안 레이어 검사 결과 모델.

    Attributes:
        status: 검사 결과 상태 (PASS 또는 BLOCK).
        reason: 차단 이유 (차단 시에만 존재).
        layer: 차단한 레이어 이름 (차단 시에만 존재).
        severity: core-secure-layer Severity enum 이름 문자열
            ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"). 레거시 호출
            경로에서는 None.
        confidence: 레이어 판정 신뢰도 (0.0~1.0). 레거시 호출 경로에서는
            None.
        tags: 분류 태그 목록. 기본 빈 리스트.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "status": "pass",
                    "reason": None,
                    "layer": "L1",
                    "severity": None,
                    "confidence": None,
                    "tags": [],
                },
                {
                    "status": "block",
                    "reason": "prompt injection detected",
                    "layer": "L2",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "tags": ["injection"],
                },
            ]
        }
    )

    status: CheckStatus
    reason: str | None = None
    layer: str | None = None
    severity: str | None = None
    confidence: float | None = None
    tags: list[str] = Field(default_factory=list)
