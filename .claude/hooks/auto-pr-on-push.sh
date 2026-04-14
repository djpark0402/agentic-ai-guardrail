#!/bin/bash
# git push가 feature/core-secure-layer/dev 브랜치에서 실행되면
# develop 브랜치로 PR을 자동 생성.
# - 기존 열린 PR이 있으면 스킵 (push만으로 기존 PR이 갱신됨)
# - gh CLI 미설치 시 안내만 하고 통과

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

# git push 명령만 대상 (모든 변형 포함)
case "$COMMAND" in
  *"git push"*) ;;
  *) exit 0 ;;
esac

# 현재 브랜치가 feature/core-secure-layer/dev인지 확인
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null)
if [ "$CURRENT_BRANCH" != "feature/core-secure-layer/dev" ]; then
  exit 0
fi

# gh CLI 확인
if ! command -v gh >/dev/null 2>&1; then
  jq -n '{ systemMessage: "⚠️  gh CLI가 설치되지 않아 PR 자동 생성을 건너뜁니다. `brew install gh && gh auth login` 후 재시도하세요." }'
  exit 0
fi

# 기존 열린 PR 확인 (있으면 push로 자동 갱신되므로 스킵)
EXISTING_JSON=$(gh pr list --head feature/core-secure-layer/dev --base develop --state open --json number,url 2>/dev/null)
EXISTING_NUM=$(echo "$EXISTING_JSON" | jq -r '.[0].number // empty' 2>/dev/null)

if [ -n "$EXISTING_NUM" ]; then
  EXISTING_URL=$(echo "$EXISTING_JSON" | jq -r '.[0].url')
  jq -n --arg url "$EXISTING_URL" --arg num "$EXISTING_NUM" \
    '{ systemMessage: ("ℹ️  기존 PR #" + $num + " 이 push로 갱신됨: " + $url) }'
  exit 0
fi

# develop 대비 커밋 수집
COMMITS=$(git log origin/develop..feature/core-secure-layer/dev --format='- %s' 2>/dev/null)
if [ -z "$COMMITS" ]; then
  jq -n '{ systemMessage: "ℹ️  develop 대비 새 커밋 없음 — PR 생성 생략" }'
  exit 0
fi

# 제목: [core-secure-layer] 최신 커밋 메시지, 70자 제한
LATEST=$(git log origin/develop..feature/core-secure-layer/dev --format='%s' -1)
TITLE="[core-secure-layer] ${LATEST}"
if [ ${#TITLE} -gt 70 ]; then
  TITLE="${TITLE:0:67}..."
fi

# 변경 파일 통계
STAT=$(git diff --stat origin/develop..feature/core-secure-layer/dev 2>/dev/null)

# 본문 조립
BODY=$(cat <<PRBODY
## 변경 요약

${COMMITS}

## 변경 파일

\`\`\`
${STAT}
\`\`\`

## 체크리스트

- [ ] \`uv run pytest\` 통과
- [ ] \`uv run ruff check\` 통과
- [ ] \`uv run ruff format --check\` 통과
- [ ] CLAUDE.md 작업 규칙 준수

---
🤖 Claude Code hook이 자동 생성
PRBODY
)

# PR 생성
PR_OUTPUT=$(gh pr create \
  --base develop \
  --head feature/core-secure-layer/dev \
  --title "$TITLE" \
  --body "$BODY" 2>&1)

if echo "$PR_OUTPUT" | grep -qE 'https?://'; then
  PR_URL=$(echo "$PR_OUTPUT" | grep -oE 'https?://[^ ]+' | head -1)
  jq -n --arg url "$PR_URL" \
    '{ systemMessage: ("✅ develop 브랜치로 PR 자동 생성됨: " + $url) }'
else
  jq -n --arg err "$PR_OUTPUT" \
    '{ systemMessage: ("⚠️  PR 생성 실패:\n" + $err) }'
fi

exit 0
