"""llm_judge 레이어 단독 인터랙티브 시연 스크립트.

L1~L6 휴리스틱을 모두 건너뛰고 ``LlmJudgeLayer`` 만 호출해 응답을 확인한다.
운영자가 작성한 system_prompt 를 빠르게 시연·튜닝할 때 사용한다.

사용 예::

    uv run python scripts/try_llm_judge.py
    uv run python scripts/try_llm_judge.py --prompt "직접 작성한 정책 본문"
    LLM_JUDGE_TEST_PROMPT="..." uv run python scripts/try_llm_judge.py

종료: 빈 입력 또는 ``Ctrl+C``.
"""

import argparse
import asyncio
import os

from core_secure_layer.cli import (
    _LLM_JUDGE_DEFAULT_PROMPT,
    _build_solar_llm,
    _emit_result,
)
from core_secure_layer.layers.llm_judge import LlmJudgeLayer
from core_secure_layer.layers.types import GuardrailRequest


def _resolve_prompt(cli_prompt: str | None) -> str:
    """CLI 인자 → 환경변수 → cli 기본값 순으로 prompt 를 결정한다.

    Args:
        cli_prompt: ``--prompt`` 인자로 전달된 값 (없으면 ``None``).

    Returns:
        사용할 system_prompt 본문.
    """
    if cli_prompt:
        return cli_prompt
    return os.getenv("LLM_JUDGE_TEST_PROMPT", _LLM_JUDGE_DEFAULT_PROMPT)


async def _check_once(judge: LlmJudgeLayer, text: str) -> None:
    """단일 입력으로 judge 를 한 번 호출해 결과를 표준 포맷으로 출력한다.

    Args:
        judge: 검사에 사용할 LlmJudgeLayer 인스턴스.
        text: 사용자 입력 텍스트.
    """
    request = GuardrailRequest(user_input=text)
    result = await judge.check(request)
    _emit_result(judge.name, result)


def main() -> None:
    """단독 인터랙티브 루프 진입점."""
    parser = argparse.ArgumentParser(
        description="llm_judge 단독 인터랙티브 시연",
    )
    parser.add_argument(
        "--prompt",
        default=None,
        help="system_prompt 본문을 직접 주입 (지정 안 하면 cli 기본값 사용)",
    )
    args = parser.parse_args()

    llm = _build_solar_llm()
    system_prompt = _resolve_prompt(args.prompt)
    judge = LlmJudgeLayer(llm=llm, system_prompt=system_prompt)

    print("\n=== llm_judge 단독 인터랙티브 시연 ===")
    if llm is None:
        print(
            "[경고] SOLAR_API_KEY 미설정 — fail-open 으로만 동작합니다."
            " .env 에 키를 채운 뒤 다시 실행하세요."
        )
    else:
        print("Solar 클라이언트 활성")
    print(f"system_prompt 길이: {len(system_prompt)}자")
    print("종료: 빈 입력 또는 Ctrl+C\n")

    while True:
        try:
            text = input("입력> ")
        except KeyboardInterrupt, EOFError:
            print("\n종료")
            break

        if not text.strip():
            print("종료")
            break

        asyncio.run(_check_once(judge, text))


if __name__ == "__main__":
    main()
