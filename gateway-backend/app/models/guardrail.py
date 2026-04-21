"""Guardrail 검사 결과 Pydantic 모델."""

from enum import StrEnum

from pydantic import BaseModel


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
    """

    status: CheckStatus
    reason: str | None = None
    layer: str | None = None
