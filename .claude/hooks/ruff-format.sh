#!/bin/bash
# core-secure-layer 내 .py 파일이 Edit/Write 될 때마다
# ruff format + ruff check --fix 자동 실행.
# 자동 수정 불가 에러가 남으면 Claude에게 차단 메시지 전달.

INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_response.filePath // .tool_input.file_path // empty' 2>/dev/null)

[ -z "$FILE" ] && exit 0

# core-secure-layer 내부의 .py 파일만 대상
case "$FILE" in
  */core-secure-layer/**/*.py) ;;
  *) exit 0 ;;
esac

# 모듈 디렉토리로 이동
PROJECT_DIR="${FILE%%/core-secure-layer/*}/core-secure-layer"
[ -d "$PROJECT_DIR" ] || exit 0
cd "$PROJECT_DIR" || exit 0

# 1) 자동 포맷
uv run --quiet ruff format "$FILE" >/dev/null 2>&1

# 2) 자동 수정 가능한 lint 에러 수정
uv run --quiet ruff check --fix "$FILE" >/dev/null 2>&1

# 3) 남아있는 (수정 불가) 에러 확인
REMAINING=$(uv run --quiet ruff check "$FILE" 2>&1)
RUFF_EXIT=$?

if [ $RUFF_EXIT -ne 0 ] && [ -n "$REMAINING" ]; then
  jq -n --arg err "$REMAINING" '{
    decision: "block",
    reason: ("ruff에 자동 수정 불가능한 lint 에러가 남아있습니다. 수정 후 진행하세요:\n\n" + $err)
  }'
fi

exit 0
