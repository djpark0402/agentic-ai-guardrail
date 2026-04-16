"""가드레일 레이어 인터랙티브 CLI 테스트 도구."""

import asyncio

from core_secure_layer.layers.types import (
    GuardrailRequest,
    Severity,
)


def _severity_color(severity: Severity) -> str:
    """심각도별 ANSI 컬러 코드를 반환한다.

    Args:
        severity: 심각도 수준.

    Returns:
        ANSI 컬러 이스케이프 시퀀스.
    """
    colors = {
        Severity.NONE: "\033[32m",
        Severity.LOW: "\033[33m",
        Severity.MEDIUM: "\033[33m",
        Severity.HIGH: "\033[31m",
        Severity.CRITICAL: "\033[91m",
    }
    return colors.get(severity, "\033[0m")


_RESET = "\033[0m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def _build_layers() -> list[tuple[str, object]]:
    """사용 가능한 레이어 인스턴스를 생성한다.

    Returns:
        (레이어명, 인스턴스) 튜플 리스트.
    """
    layers: list[tuple[str, object]] = []

    from core_secure_layer.layers.l1.l1 import L1Layer

    layers.append(("L1", L1Layer()))

    from core_secure_layer.layers.l2.l2 import L2Layer

    layers.append(("L2", L2Layer()))

    from core_secure_layer.layers.l3.l3 import L3Layer

    layers.append(("L3", L3Layer()))

    from core_secure_layer.layers.l4.l4 import L4Layer

    layers.append(("L4", L4Layer()))

    from core_secure_layer.layers.l5.l5 import L5Layer

    layers.append(("L5", L5Layer()))

    from core_secure_layer.layers.l6.l6 import L6Layer

    layers.append(("L6", L6Layer()))

    return layers


async def _run_layers(
    text: str,
    layers: list[tuple[str, object]],
) -> None:
    """모든 레이어에 입력을 전달하고 결과를 출력한다.

    Args:
        text: 사용자 입력 텍스트.
        layers: (레이어명, 인스턴스) 리스트.
    """
    request = GuardrailRequest(user_input=text)
    print()

    for name, layer in layers:
        result = await layer.check(request)
        time_str = (
            f"{result.execution_time_ms:.1f}ms"
            if result.execution_time_ms is not None
            else "N/A"
        )

        if result.allowed:
            print(
                f"  {_GREEN}[{name}] ALLOW{_DIM} ({time_str}){_RESET}",
            )
        else:
            color = _severity_color(result.severity)
            print(
                f"  {color}[{name}] BLOCK"
                f" — {result.reason}"
                f"{_DIM} ({time_str}){_RESET}",
            )
            print(
                f"         {_DIM}"
                f"severity={result.severity.value}"
                f" confidence={result.confidence}"
                f" tags={result.tags}"
                f"{_RESET}",
            )

    print()


def main() -> None:
    """CLI 메인 루프를 실행한다."""
    print(f"\n{_BOLD}=== 가드레일 레이어 테스트 CLI ==={_RESET}")
    print(f"{_DIM}종료: Ctrl+C 또는 빈 입력{_RESET}\n")

    layers = _build_layers()

    loaded = [
        name for name, layer in layers if getattr(layer, "_model_loaded", True)
    ]
    not_loaded = [
        name
        for name, layer in layers
        if not getattr(layer, "_model_loaded", True)
    ]

    if loaded:
        print(
            f"  {_GREEN}활성{_RESET}: {', '.join(loaded)}",
        )
    if not_loaded:
        print(
            f"  {_DIM}모델 미로드 (fail-open){_RESET}: {', '.join(not_loaded)}",
        )
    print()

    while True:
        try:
            text = input(f"{_BOLD}입력> {_RESET}")
        except KeyboardInterrupt, EOFError:
            print(f"\n{_DIM}종료{_RESET}")
            break

        if not text.strip():
            print(f"{_DIM}종료{_RESET}")
            break

        asyncio.run(_run_layers(text, layers))


if __name__ == "__main__":
    main()
