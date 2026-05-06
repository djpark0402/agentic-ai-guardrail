"""security-layer 보안 검사 서비스."""

import logging
import time

from core_secure_layer.layers.base import BaseLayer

from app.models.chat import Message
from app.models.guardrail import CheckStatus, GuardrailResult
from app.models.policy import GuardrailPolicy
from app.services.guardrail_converter import (
    content_to_request,
    layer_result_to_guardrail_result,
    messages_to_request,
)
from app.services.layer_registry import get_l5_layer, get_layer
from app.services.llm_layer_guard import LLMLayerGuardService

logger = logging.getLogger(__name__)

_LAYER_LABELS: dict[str, str] = {
    "L1": "인코딩 검사",
    "L2": "혼란도/이상 탐지",
    "L3": "공격 패턴 유사도",
    "L4": "정책 위반 검사",
    "L5": "개인정보 탐지",
    "L6": "안전성 모델 검사",
}


def _stage_label(stage: str) -> str:
    """로그 표시에 사용할 단계 한글명을 반환한다."""
    return "입력" if stage == "input" else "출력"


def format_layer_display_name(layer_name: str) -> str:
    """콘솔 로그에서 사용할 레이어 표시명을 반환한다."""
    label = _LAYER_LABELS.get(layer_name)
    if label is None:
        return layer_name
    return f"{layer_name}({label})"


def _record_layer_timing(
    timings: dict[str, float] | None,
    prefix: str,
    layer_idx: int,
    started_at: float,
) -> None:
    """요청 요약 로그용 레이어별 실행 시간을 기록한다."""
    if timings is None:
        return
    timings[f"{prefix}_L{layer_idx}"] = (
        time.perf_counter() - started_at
    ) * 1000


def _log_layer_result(
    stage: str,
    result: GuardrailResult,
    *,
    layer_name: str,
    note: str | None = None,
) -> None:
    """레이어 실행 결과를 구조화된 한 줄 로그로 남긴다.

    Args:
        stage: 입력/출력 구분값.
        result: 레이어 실행 결과.
        layer_name: 로그에 강제로 표시할 레이어 이름.
        note: PASS 처리 사유 같은 보조 설명.
    """
    fields = [
        f"layer={format_layer_display_name(layer_name)}",
        f"status={result.status.value}",
    ]
    if result.reason:
        fields.append(f"reason={result.reason}")
    if note:
        fields.append(f"note={note}")
    if result.severity:
        fields.append(f"severity={result.severity}")
    if result.confidence is not None:
        fields.append(f"confidence={result.confidence:.2f}")
    if result.tags:
        fields.append(f"tags={list(result.tags)}")

    log_fn = (
        logger.warning
        if result.status is CheckStatus.BLOCK
        else logger.info
    )
    log_fn(
        "%s 레이어 결과: %s",
        _stage_label(stage),
        " ".join(fields),
    )


def _get_policy_layer(
    layer_idx: int,
    policy: GuardrailPolicy | None,
) -> BaseLayer | None:
    """정책 설정을 반영한 core-secure-layer 인스턴스를 반환한다."""
    if layer_idx != 5:
        return get_layer(layer_idx)

    setting = policy.l5_setting if policy is not None else None
    model_name = setting.model if setting is not None else None
    threshold = setting.threshold if setting is not None else None
    logger.info(
        "L5 정책 설정 적용: model=%s threshold=%s",
        model_name or "(default)",
        threshold if threshold is not None else "(default)",
    )
    return get_l5_layer(model_name=model_name, threshold=threshold)


def _with_layer_name(
    result: GuardrailResult,
    layer_idx: int,
) -> GuardrailResult:
    """결과에 `layer` 가 비어 있으면 `L{idx}` 로 보강한 사본을 돌려준다.

    관찰 모드 응답에서 레이어별 판정을 순서대로 식별하기 위해 필요하다.
    PASS/미구현/미매핑 레이어는 `layer` 가 비어 있을 수 있으므로 여기서 메운다.
    """
    if result.layer:
        return result
    return result.model_copy(update={"layer": f"L{layer_idx}"})


class SecurityLayerService:
    """core-secure-layer 를 통한 L1~L6 보안 검사 서비스.

    policy 에서 활성화된 레이어(`lN == True`)만 순차적으로
    실행한다. 미구현 레이어(``NotImplementedError``)는 PASS 로
    처리하여 구현 완료된 레이어만 실제 검사를 수행한다.
    """

    def __init__(
        self,
        *,
        llm_layer_guard: LLMLayerGuardService | None = None,
        llm_layer_replacement_layers: frozenset[int] | None = None,
    ) -> None:
        """SecurityLayerService 를 초기화한다.

        Args:
            llm_layer_guard: LLM 레이어 대체 서비스. None 이면 모든 레이어가
                기존 core-secure-layer 경로로 실행된다.
            llm_layer_replacement_layers: LLM 으로 대체 실행할 레이어 인덱스.
        """
        self._llm_layer_guard = llm_layer_guard
        self._llm_layer_replacement_layers = (
            llm_layer_replacement_layers or frozenset()
        )

    def _should_use_llm_layer(self, layer_idx: int) -> bool:
        """해당 레이어를 LLM 대체 경로로 실행해야 하는지 반환한다."""
        replacement_layers = getattr(
            self,
            "_llm_layer_replacement_layers",
            frozenset(),
        )
        return layer_idx in replacement_layers

    async def check_input(
        self,
        messages: list[Message],
        policy: GuardrailPolicy,
        timings: dict[str, float] | None = None,
    ) -> GuardrailResult:
        """활성 레이어에 한해 입력 메시지 보안 검사를 수행한다.

        Args:
            messages: 사용자 입력 메시지 목록.
            policy: 적용할 보안 정책.
            timings: 요청 요약 로그에 누적할 단계별 소요 시간.

        Returns:
            모든 활성 레이어 통과 시 PASS, 하나라도 차단 시 BLOCK.
        """
        enabled = policy.enabled_layers()
        logger.info(
            "입력 보안 검사 시작: 메시지 수=%d enabled_layers=%s",
            len(messages),
            enabled,
        )
        for layer_idx in enabled:
            t0 = time.perf_counter()
            result = await self._run_layer_input(layer_idx, messages, policy)
            _record_layer_timing(timings, "input_guardrail", layer_idx, t0)
            if result.status is CheckStatus.BLOCK:
                return result
        return GuardrailResult(status=CheckStatus.PASS)

    async def check_output(
        self,
        content: str,
        policy: GuardrailPolicy,
        timings: dict[str, float] | None = None,
    ) -> GuardrailResult:
        """활성 레이어에 한해 출력 콘텐츠 보안 검사를 수행한다.

        Args:
            content: LLM 응답 텍스트.
            policy: 적용할 보안 정책.
            timings: 요청 요약 로그에 누적할 단계별 소요 시간.

        Returns:
            모든 활성 레이어 통과 시 PASS, 하나라도 차단 시 BLOCK.
        """
        enabled = policy.enabled_layers()
        logger.info(
            "출력 보안 검사 시작: content_len=%d enabled_layers=%s",
            len(content),
            enabled,
        )
        for layer_idx in enabled:
            t0 = time.perf_counter()
            result = await self._run_layer_output(layer_idx, content, policy)
            _record_layer_timing(timings, "output_guardrail", layer_idx, t0)
            if result.status is CheckStatus.BLOCK:
                return result
        return GuardrailResult(status=CheckStatus.PASS)

    async def check_input_all(
        self,
        messages: list[Message],
        policy: GuardrailPolicy,
        timings: dict[str, float] | None = None,
    ) -> list[GuardrailResult]:
        """활성 레이어 전부를 순차 실행하고 각 결과를 수집한다.

        관찰(데모) 모드 전용 경로로, BLOCK 판정이 나와도 후속 레이어 실행을
        중단하지 않는다. 각 결과에는 `layer` 필드가 `"L{idx}"` 형식으로
        보강되어, 정책 순서에 따른 레이어별 판정 내역을 클라이언트에 그대로
        노출할 수 있다.

        Args:
            messages: 사용자 입력 메시지 목록.
            policy: 적용할 보안 정책.
            timings: 요청 요약 로그에 누적할 단계별 소요 시간.

        Returns:
            활성 레이어 개수만큼의 `GuardrailResult` 리스트. 순서는
            `policy.enabled_layers()` 와 일치한다.
        """
        enabled = policy.enabled_layers()
        logger.info(
            "입력 보안 검사(관찰 모드) 시작: 메시지 수=%d enabled_layers=%s",
            len(messages),
            enabled,
        )
        results: list[GuardrailResult] = []
        for layer_idx in enabled:
            t0 = time.perf_counter()
            result = await self._run_layer_input(layer_idx, messages, policy)
            _record_layer_timing(timings, "input_guardrail", layer_idx, t0)
            results.append(_with_layer_name(result, layer_idx))
        return results

    async def check_output_all(
        self,
        content: str,
        policy: GuardrailPolicy,
        timings: dict[str, float] | None = None,
    ) -> list[GuardrailResult]:
        """활성 레이어 전부를 순차 실행하고 각 출력 결과를 수집한다.

        관찰(데모) 모드 전용 경로. `check_input_all` 과 대칭.

        Args:
            content: LLM 응답 텍스트.
            policy: 적용할 보안 정책.
            timings: 요청 요약 로그에 누적할 단계별 소요 시간.

        Returns:
            활성 레이어 개수만큼의 `GuardrailResult` 리스트.
        """
        enabled = policy.enabled_layers()
        logger.info(
            "출력 보안 검사(관찰 모드) 시작: content_len=%d enabled_layers=%s",
            len(content),
            enabled,
        )
        results: list[GuardrailResult] = []
        for layer_idx in enabled:
            t0 = time.perf_counter()
            result = await self._run_layer_output(layer_idx, content, policy)
            _record_layer_timing(timings, "output_guardrail", layer_idx, t0)
            results.append(_with_layer_name(result, layer_idx))
        return results

    async def _run_layer_input(
        self,
        layer_idx: int,
        messages: list[Message],
        policy: GuardrailPolicy | None = None,
    ) -> GuardrailResult:
        """core-secure-layer 를 통해 입력 레이어를 실행한다.

        Args:
            layer_idx: 실행할 레이어 인덱스 (1~6).
            messages: 검사 대상 메시지 목록.
            policy: L5 설정을 포함한 현재 요청 정책. None 이면 기본 레이어
                설정을 사용한다.

        Returns:
            레이어 실행 결과. 미구현·미매핑 레이어는 PASS.
        """
        if self._should_use_llm_layer(layer_idx):
            llm_guard = getattr(self, "_llm_layer_guard", None)
            if llm_guard is None:
                result = GuardrailResult(
                    status=CheckStatus.BLOCK,
                    reason="LLM 레이어 대체 서비스가 설정되지 않았습니다.",
                    layer=f"L{layer_idx}",
                    severity="HIGH",
                    confidence=1.0,
                    tags=["llm_layer_misconfigured"],
                )
            else:
                request = messages_to_request(messages)
                result = await llm_guard.check(
                    layer_idx=layer_idx,
                    surface="input",
                    content=request.user_input,
                )
            _log_layer_result(
                "input",
                result,
                layer_name=result.layer or f"L{layer_idx}",
                note="LLM 대체",
            )
            return result

        layer = _get_policy_layer(layer_idx, policy)
        if layer is None:
            result = GuardrailResult(
                status=CheckStatus.PASS,
                layer=f"L{layer_idx}",
            )
            _log_layer_result(
                "input",
                result,
                layer_name=f"L{layer_idx}",
                note="매핑 없음",
            )
            return result

        request = messages_to_request(messages)
        try:
            core_result = await layer.check(request)
        except NotImplementedError:
            result = GuardrailResult(
                status=CheckStatus.PASS,
                layer=layer.name,
            )
            _log_layer_result(
                "input",
                result,
                layer_name=layer.name,
                note="미구현",
            )
            return result

        result = _with_layer_name(
            layer_result_to_guardrail_result(core_result),
            layer_idx,
        )
        _log_layer_result(
            "input",
            result,
            layer_name=result.layer or f"L{layer_idx}",
        )
        return result

    async def _run_layer_output(
        self,
        layer_idx: int,
        content: str,
        policy: GuardrailPolicy | None = None,
    ) -> GuardrailResult:
        """core-secure-layer 를 통해 출력 레이어를 실행한다.

        Args:
            layer_idx: 실행할 레이어 인덱스 (1~6).
            content: 검사 대상 응답 텍스트.
            policy: L5 설정을 포함한 현재 요청 정책. None 이면 기본 레이어
                설정을 사용한다.

        Returns:
            레이어 실행 결과. 미구현·미매핑 레이어는 PASS.
        """
        if self._should_use_llm_layer(layer_idx):
            llm_guard = getattr(self, "_llm_layer_guard", None)
            if llm_guard is None:
                result = GuardrailResult(
                    status=CheckStatus.BLOCK,
                    reason="LLM 레이어 대체 서비스가 설정되지 않았습니다.",
                    layer=f"L{layer_idx}",
                    severity="HIGH",
                    confidence=1.0,
                    tags=["llm_layer_misconfigured"],
                )
            else:
                result = await llm_guard.check(
                    layer_idx=layer_idx,
                    surface="output",
                    content=content,
                )
            _log_layer_result(
                "output",
                result,
                layer_name=result.layer or f"L{layer_idx}",
                note="LLM 대체",
            )
            return result

        layer = _get_policy_layer(layer_idx, policy)
        if layer is None:
            result = GuardrailResult(
                status=CheckStatus.PASS,
                layer=f"L{layer_idx}",
            )
            _log_layer_result(
                "output",
                result,
                layer_name=f"L{layer_idx}",
                note="매핑 없음",
            )
            return result

        request = content_to_request(content)
        try:
            core_result = await layer.check(request)
        except NotImplementedError:
            result = GuardrailResult(
                status=CheckStatus.PASS,
                layer=layer.name,
            )
            _log_layer_result(
                "output",
                result,
                layer_name=layer.name,
                note="미구현",
            )
            return result

        result = _with_layer_name(
            layer_result_to_guardrail_result(core_result),
            layer_idx,
        )
        _log_layer_result(
            "output",
            result,
            layer_name=result.layer or f"L{layer_idx}",
        )
        return result
