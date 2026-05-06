"""LLM 기반 보강 판정 레이어 (``LlmJudgeLayer``).

L1~L6 휴리스틱 검사를 모두 통과한 입력에 대해, 운영자가 직접 주입한
system_prompt 와 단일 LLM 호출로 통합 판정을 수행한다.  설계 상세는
``core-secure-layer/docs/llm-judge-design.md`` 참고.

이 레이어의 모든 실패 경로(LLM 예외·JSON 파싱 실패·스키마 검증 실패·
클라이언트 미초기화)는 ``LayerResult(allowed=True)`` 로 fail-open 한다.
core-secure-layer 의 글로벌 원칙(미탐 허용·오탐 절대 불허) 과 일치.
"""

import json
import logging
import re

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import ValidationError

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.llm_judge.schema import JudgeOutput
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

logger = logging.getLogger(__name__)

_OUTPUT_FORMAT_INSTRUCTION = (
    "\n\n"
    "You MUST respond with a single JSON object and nothing else.\n"
    "The JSON object must have these exact keys:\n"
    '  - "allowed": boolean\n'
    '  - "reason": string (empty string if allowed=true)\n'
    '  - "severity": one of "none", "low", "medium", "high", "critical"\n'
    '  - "categories": array of short string labels (empty array if allowed=true)\n'  # noqa: E501
    '  - "confidence": number between 0.0 and 1.0\n'
    "Do NOT include any text outside of the JSON. Do NOT wrap the JSON in"
    " code fences."
)

_CODE_FENCE_RE = re.compile(
    r"```(?:json)?\s*([\s\S]+?)\s*```",
    re.IGNORECASE,
)


class LlmJudgeLayer(BaseLayer):
    """단일 LLM 호출로 통합 보강 판정을 수행하는 레이어.

    운영자가 ``system_prompt`` 인자로 정책 본문을 직접 주입하고, 시스템은
    출력 형식 instruction 을 자동으로 append 한 뒤 ``llm.ainvoke`` 를
    호출한다.  응답은 ``JudgeOutput`` 스키마로 파싱되어 ``LayerResult``
    필드에 매핑된다.

    Attributes:
        name: ``LayerResult.name`` 으로 사용되는 레이어 식별자.
    """

    def __init__(
        self,
        *,
        llm: BaseChatModel | None,
        system_prompt: str,
        layer_id: str = "llm_judge",
    ) -> None:
        """레이어를 초기화한다.

        Args:
            llm: LangChain ``BaseChatModel`` 인스턴스.  ``None`` 이면 모든
                호출이 fail-open 된다 (CLI 가 API 키 누락 시 ``None`` 을
                넘기는 케이스).
            system_prompt: 운영자가 작성한 정책/판단 기준 본문.  시스템이
                끝에 출력 형식 instruction 을 자동 append 한다.
            layer_id: ``LayerResult.name`` 으로 사용할 식별자.
        """
        self._llm = llm
        self._operator_prompt = system_prompt
        self._system_prompt = system_prompt + _OUTPUT_FORMAT_INSTRUCTION
        self.name = layer_id

    async def _check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """LLM 을 호출해 판정 결과를 ``LayerResult`` 로 매핑한다.

        모든 실패 경로(클라이언트 None·LLM 예외·JSON 파싱 실패·스키마
        검증 실패) 는 ``LayerResult(allowed=True)`` 로 fail-open.

        Args:
            request: 검사 대상 요청.

        Returns:
            LLM 응답을 매핑한 LayerResult, 또는 fail-open 결과.
        """
        if self._llm is None:
            return self._fail_open()

        try:
            messages = [
                SystemMessage(content=self._system_prompt),
                HumanMessage(content=request.user_input),
            ]
            response = await self._llm.ainvoke(messages)
        except Exception:
            logger.exception("llm_judge: LLM ainvoke failed; fail-open")
            return self._fail_open()

        content = self._response_text(response)
        logger.debug("llm_judge raw response: %s", content)
        verdict = self._parse_verdict(content)
        if verdict is None:
            logger.warning(
                "llm_judge: failed to parse verdict; fail-open content=%r",
                content,
            )
            return self._fail_open()

        return self._to_layer_result(verdict)

    def _fail_open(self) -> LayerResult:
        """모호한 모든 경우의 통일된 fail-open 결과를 반환한다."""
        return LayerResult(name=self.name, allowed=True)

    def _to_layer_result(self, verdict: JudgeOutput) -> LayerResult:
        """``JudgeOutput`` 을 ``LayerResult`` 로 매핑한다.

        Args:
            verdict: 파싱이 성공한 LLM 판정 결과.

        Returns:
            매핑된 LayerResult.  ``allowed=True`` 인 경우 reason 은 ``None``.
        """
        allowed = bool(verdict.allowed)
        return LayerResult(
            name=self.name,
            allowed=allowed,
            reason=verdict.reason if not allowed else None,
            severity=_to_severity(verdict.severity),
            confidence=_clamp_unit(verdict.confidence),
            tags=list(verdict.categories),
        )

    @staticmethod
    def _response_text(response: object) -> str:
        """LangChain 응답에서 평면 텍스트 콘텐츠를 추출한다.

        Args:
            response: ``BaseChatModel.ainvoke`` 의 반환값.

        Returns:
            응답 텍스트.  multi-modal 응답이면 텍스트 파트만 join.
        """
        content = getattr(response, "content", response)
        if isinstance(content, list):
            parts: list[str] = []
            for part in content:
                if isinstance(part, dict):
                    parts.append(str(part.get("text", "")))
                else:
                    parts.append(str(part))
            return "".join(parts)
        return str(content)

    @staticmethod
    def _parse_verdict(text: str) -> JudgeOutput | None:
        """응답 텍스트에서 첫 번째 valid JSON 객체를 추출해 검증한다.

        코드 펜스(```json … ```), 추가 prose 등으로 감싸진 응답도 robust 하게
        처리한다.  실패하면 ``None`` 을 돌려 호출 측이 fail-open 하도록 한다.

        Args:
            text: LLM 이 반환한 raw 텍스트.

        Returns:
            검증된 ``JudgeOutput``, 또는 파싱 실패 시 ``None``.
        """
        candidates = _candidate_payloads(text)
        decoder = json.JSONDecoder()
        for candidate in candidates:
            stripped = candidate.strip()
            for idx, ch in enumerate(stripped):
                if ch != "{":
                    continue
                try:
                    obj, _ = decoder.raw_decode(stripped[idx:])
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                try:
                    return JudgeOutput.model_validate(obj)
                except ValidationError:
                    continue
        return None


def _candidate_payloads(text: str) -> list[str]:
    """JSON 추출 후보 문자열 목록을 우선순위로 반환한다.

    Args:
        text: 원본 응답 텍스트.

    Returns:
        먼저 코드 펜스 내용, 그 다음 원본 텍스트 자체 순.
    """
    candidates = [m.group(1) for m in _CODE_FENCE_RE.finditer(text)]
    candidates.append(text)
    return candidates


def _to_severity(value: str) -> Severity:
    """문자열을 ``Severity`` enum 으로 안전하게 매핑한다.

    Args:
        value: LLM 이 채운 severity 문자열.

    Returns:
        대응되는 Severity, 알 수 없는 값이면 ``Severity.NONE``.
    """
    try:
        return Severity(value.lower())
    except ValueError, AttributeError:
        return Severity.NONE


def _clamp_unit(value: float) -> float:
    """값을 ``[0.0, 1.0]`` 범위로 클램프한다.

    Args:
        value: 클램프할 값.

    Returns:
        클램프된 값.
    """
    try:
        return max(0.0, min(1.0, float(value)))
    except TypeError, ValueError:
        return 0.0
