#!/bin/bash
# core-secure-layer 내 .py 파일이 Edit/Write 될 때마다
# ruff format + ruff check --fix 자동 실행.
# 자동 수정 불가 에러가 남으면 Claude에게 차단 메시지 전달.

INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_response.filePath // .tool_input.file_path // empty' 2>/dev/null)

[ -z "$FILE" ] && exit 0

# core-secure-layer 내부의 .py 파일만 대상.
# bash `case` 글롭에서 `*`는 슬래시도 매치하므로 중첩 디렉토리까지 자연히 포괄된다.
case "$FILE" in
  */core-secure-layer/*.py) ;;
  *) exit 0 ;;
esac

# 모듈 디렉토리로 이동
PROJECT_DIR="${FILE%%/core-secure-layer/*}/core-secure-layer"
[ -d "$PROJECT_DIR" ] || exit 0
cd "$PROJECT_DIR" || exit 0

# 1) 자동 포맷 (실패해도 최종 check로 판단하므로 무시)
uv run --quiet ruff format "$FILE" >/dev/null 2>&1

# 2) 자동 수정 가능한 lint 에러 수정
uv run --quiet ruff check --fix "$FILE" >/dev/null 2>&1

# 3) 최종 check — 종료 코드로 lint / infra 구분
#    ruff check 종료 코드:
#      0 = 위반 없음
#      1 = lint 위반 발견 (→ Claude 차단)
#      2+ = ruff 내부 에러 / 설정 에러 / uv·ruff 부트스트랩 실패 등 (→ 경고만)
REMAINING=$(uv run --quiet ruff check "$FILE" 2>&1)
RUFF_EXIT=$?

if [ "$RUFF_EXIT" -eq 0 ]; then
  exit 0
fi

if [ "$RUFF_EXIT" -eq 1 ]; then
  jq -n --arg err "$REMAINING" '{
    decision: "block",
    reason: ("ruff에 자동 수정 불가능한 lint 에러가 남아있습니다. 수정 후 진행하세요:\n\n" + $err)
  }'
else
  jq -n --arg err "$REMAINING" --arg code "$RUFF_EXIT" '{
    systemMessage: ("⚠️  ruff 실행 실패 (exit " + $code + "). uv/ruff 환경을 확인하세요. Claude 차단은 하지 않습니다:\n" + $err)
  }'
fi

exit 0
