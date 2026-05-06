"""llm_judge 레이어 단독 인터랙티브 시연 스크립트.

L1~L6 휴리스틱을 모두 건너뛰고 ``LlmJudgeLayer`` 만 호출해 응답을 확인한다.
운영자가 작성한 system_prompt 를 빠르게 시연·튜닝할 때 사용한다.

사용 예::

    uv run python scripts/try_llm_judge.py
    uv run python scripts/try_llm_judge.py --prompt "직접 작성한 정책 본문"
    LLM_JUDGE_TEST_PROMPT="..." uv run python scripts/try_llm_judge.py

종료: 빈 입력 또는 ``Ctrl+C``.

부작용: ``llm_judge`` 의 raw LLM 응답을 ``[llm_raw]`` 접두로 stdout 에
함께 출력한다 (디버그 로거를 명시적으로 활성화).
"""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

# scripts/ 에서 직접 실행 시 core_secure_layer 패키지를 찾을 수 있도록
# 프로젝트 루트(core-secure-layer/) 를 sys.path 에 추가한다.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core_secure_layer.cli import (  # noqa: E402
    _LLM_JUDGE_DEFAULT_PROMPT,
    _build_solar_llm,
    _emit_result,
)
from core_secure_layer.layers.llm_judge import LlmJudgeLayer  # noqa: E402
from core_secure_layer.layers.types import GuardrailRequest  # noqa: E402


def _setup_raw_response_logging() -> None:
    """llm_judge 의 raw LLM 응답을 stdout 으로 흘리는 디버그 로거 설정.

    ``core_secure_layer.layers.llm_judge`` 로거만 ``DEBUG`` 레벨로 올리고
    별도 핸들러로 stdout 에 ``[llm_raw]`` 접두를 붙여 찍는다.
    다른 모듈의 로깅은 영향받지 않는다.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("  [llm_raw] %(message)s"))
    logger = logging.getLogger("core_secure_layer.layers.llm_judge")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.propagate = False


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

    _setup_raw_response_logging()

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
