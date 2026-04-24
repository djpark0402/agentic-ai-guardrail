"""L5 NER 모델 수동 smoke test 스크립트.

한 줄씩 입력을 받아 L5Layer 의 판정 결과와 원시 NER 엔티티를 출력한다.
새 NER 모델을 ``model/<name>/`` 에 드롭인한 직후
``pii_labels.json`` 설정이 의도대로 동작하는지 눈으로 확인하기 위한
개발용 도구이다.

사용 예::

    # 한 번만 판정
    uv run python scripts/smoke_l5_model.py \
        --model pii_model_v11 \
        --text "제 이름은 김철수입니다"

    # REPL 루프 (한 줄씩 입력, 빈 줄이면 종료)
    uv run python scripts/smoke_l5_model.py --model ner-ko

    # min_score 생성자 override 로 임계값 튜닝
    uv run python scripts/smoke_l5_model.py \
        --model ner-ko --min-score 0.0
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

# scripts/ 에서 실행 시 core_secure_layer 패키지를 찾을 수 있도록
# 프로젝트 루트(core-secure-layer/) 를 sys.path 에 추가한다.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core_secure_layer.layers.l5.l5 import L5Layer  # noqa: E402
from core_secure_layer.layers.types import GuardrailRequest  # noqa: E402


def _print_layer_spec(layer: L5Layer) -> None:
    """로드된 L5 스펙 속성을 사람이 읽기 좋게 출력한다."""
    print("=" * 60)
    print(f"[model_name]         {layer.model_name}")
    print(f"[model_loaded]       {layer._ner_model is not None}")
    print(f"[label_map]          {layer._label_map}")
    print(f"[block_singletons]   {layer._block_singletons}")
    print(f"[block_combinations] {layer._block_combinations}")
    print(f"[min_score]          {layer._min_score}")
    print(f"[aggregation]        {layer._aggregation_strategy}")
    print("=" * 60)


def _format_entities(entities: list[dict[str, Any]]) -> str:
    """원시 NER 엔티티 리스트를 한 줄짜리 요약 문자열로 포맷한다."""
    if not entities:
        return "(없음)"
    parts: list[str] = []
    for ent in entities:
        label = ent.get("entity_group") or ent.get("entity") or "?"
        word = ent.get("word", "")
        score = float(ent.get("score", 0.0))
        start = ent.get("start", "?")
        parts.append(f"{label}({score:.4f},{word!r}@{start})")
    return ", ".join(parts)


def _judge_once(layer: L5Layer, text: str) -> None:
    """텍스트 한 개에 대한 L5 판정과 원시 NER 결과를 같이 출력한다."""
    raw = layer._ner_predict(text) if layer._ner_model is not None else []
    result = asyncio.run(
        layer._check(GuardrailRequest(user_input=text)),
    )
    mark = "ALLOW" if result.allowed else "BLOCK"
    print(f"  [{mark}] {text!r}")
    print(f"         raw NER: {_format_entities(raw)}")
    if result.reason:
        print(f"         reason:  {result.reason}")
        print(f"         tags:    {result.tags}")


def _run_repl(layer: L5Layer) -> None:
    """Stdin 에서 한 줄씩 읽어 판정 루프."""
    print("문장 입력 후 Enter (빈 줄 입력 시 종료).")
    try:
        while True:
            line = input("> ").strip()
            if not line:
                break
            _judge_once(layer, line)
    except (EOFError, KeyboardInterrupt):
        print()


def main() -> None:
    """CLI 진입점."""
    parser = argparse.ArgumentParser(
        description="L5 NER 모델 수동 smoke test",
    )
    parser.add_argument(
        "--model",
        required=True,
        help="model/ 하위 폴더명 (예: ner-ko, pii_model_v11)",
    )
    parser.add_argument(
        "--text",
        default=None,
        help="판정할 문장. 생략 시 stdin REPL 모드",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        help="생성자 min_score override (JSON 값을 덮어씀)",
    )
    args = parser.parse_args()

    layer = L5Layer(model_name=args.model, min_score=args.min_score)
    _print_layer_spec(layer)

    if args.text is not None:
        _judge_once(layer, args.text)
        return

    _run_repl(layer)


if __name__ == "__main__":
    sys.exit(main())
