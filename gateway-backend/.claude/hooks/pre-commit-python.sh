#!/bin/bash
# Claude가 git commit을 실행하려 할 때만 동작.
# ruff check + pytest 모두 통과해야 커밋을 허용한다.

INPUT=$(cat)
TOOL_INPUT=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

# git commit 명령이 아니면 통과
echo "$TOOL_INPUT" | grep -q "git commit" || exit 0

PROJECT_DIR="$CLAUDE_PROJECT_DIR"
[ -d "$PROJECT_DIR" ] || exit 0
cd "$PROJECT_DIR" || exit 0

# pyproject.toml이 없으면 Python 프로젝트 아님 → 통과
[ -f "pyproject.toml" ] || exit 0

# ── 1) Ruff lint 검사 ──────────────────────────────────────────
LINT_OUTPUT=$(uv run --quiet ruff check . 2>&1)
LINT_EXIT=$?

if [ $LINT_EXIT -ne 0 ]; then
  jq -n --arg err "$LINT_OUTPUT" '{
    decision: "block",
    reason: ("❌ Ruff lint 검사 실패. 수정 후 다시 커밋하세요:\n\n" + $err)
  }'
  exit 0
fi

# ── 2) Pytest 실행 ─────────────────────────────────────────────
# tests/ 디렉터리가 없으면 건너뜀
if [ ! -d "tests" ]; then
  exit 0
fi

TEST_OUTPUT=$(uv run --quiet pytest tests/ -x --tb=short -q 2>&1)
TEST_EXIT=$?

if [ $TEST_EXIT -ne 0 ]; then
  jq -n --arg err "$TEST_OUTPUT" '{
    decision: "block",
    reason: ("❌ 테스트 실패. 수정 후 다시 커밋하세요:\n\n" + $err)
  }'
  exit 0
fi

echo "✅ Lint + 테스트 모두 통과. 커밋을 진행합니다." >&2
exit 0
