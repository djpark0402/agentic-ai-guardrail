"""가드레일 레이어 공용 데이터 모델."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CheckPhase(StrEnum):
    """가드레일 검사가 실행되는 시점."""

    PRE_LLM = "pre_llm"
    POST_LLM = "post_llm"


class Severity(StrEnum):
    """레이어 차단 판정의 심각도 수준."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class GuardrailRequest:
    """가드레일 체인에 전달되는 불변 요청 객체.

    Attributes:
        user_input: 사용자가 제출한 원본 프롬프트.
        session_id: 멀티턴 대화 세션 식별자.
        metadata: API 키, 모델명 등 추가 컨텍스트.
    """

    user_input: str
    session_id: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class LayerResult:
    """단일 가드레일 레이어의 검사 결과.

    Attributes:
        name: 레이어 식별자 (예: ``"L1"``).
        allowed: 요청의 계속 진행 허용 여부.
        reason: ``allowed`` 가 ``False`` 일 때의 사유.
        severity: 차단 판정의 심각도 수준.
        confidence: 판정 신뢰도 (0.0~1.0).
        execution_time_ms: 레이어 실행 소요 시간(밀리초).
        tags: 분류 태그 (예: ``["xss", "injection"]``).
    """

    name: str
    allowed: bool
    reason: str | None = None
    severity: Severity = Severity.NONE
    confidence: float = 1.0
    execution_time_ms: float | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class GuardrailResponse:
    """가드레일 체인의 최종 집계 응답.

    Attributes:
        user_input: 원본 사용자 입력.
        allowed: 최종 허용 여부.
        results: 실행된 모든 레이어의 결과 목록.
        blocked_by: 차단한 레이어의 이름.
        reason: 차단 사유.
        severity: 체인에서의 최고 심각도.
        total_time_ms: 체인 전체 실행 시간(밀리초).
        phase: 검사가 실행된 시점.
    """

    user_input: str
    allowed: bool
    results: list[LayerResult] = field(
        default_factory=list,
    )
    blocked_by: str | None = None
    reason: str | None = None
    severity: Severity = Severity.NONE
    total_time_ms: float | None = None
    phase: CheckPhase = CheckPhase.PRE_LLM
