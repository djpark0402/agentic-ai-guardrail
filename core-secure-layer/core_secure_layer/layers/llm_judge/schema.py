"""LLM 보강 판정 응답 스키마."""

from pydantic import BaseModel, ConfigDict, Field


class JudgeOutput(BaseModel):
    """LLM 이 반환해야 하는 판정 결과의 스키마.

    시스템이 system_prompt 끝에 출력 형식 instruction 을 자동으로 append
    하므로, 운영자가 작성한 prompt 본문과 무관하게 LLM 응답은 이 스키마를
    따라야 한다.  스키마 위반(필드 누락·타입 오류 등) 시 호출 측은
    ``ValidationError`` 를 잡아 fail-open 으로 처리한다.

    Attributes:
        allowed: 입력 통과 허용 여부. ``False`` 일 때만 차단.
        reason: 차단/허용 사유 (사람이 읽는 자연어).
        severity: 차단 심각도 — ``none``/``low``/``medium``/``high``/
            ``critical`` 중 하나.  알 수 없는 값은 호출 측에서
            ``Severity.NONE`` 으로 디그레이드.
        categories: LLM 이 자유롭게 분류한 위협 카테고리 라벨 (예:
            ``["jailbreak", "pii_leak"]``).  ``LayerResult.tags`` 로 매핑.
        confidence: 판정 신뢰도 (``0.0~1.0``).  호출 측이 클램프한다.
    """

    model_config = ConfigDict(extra="ignore")

    allowed: bool
    reason: str = ""
    severity: str = "none"
    categories: list[str] = Field(default_factory=list)
    confidence: float = 0.0
