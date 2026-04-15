#!/bin/bash
# feature/core-secure-layer/dev 브랜치에서 다음을 자동화:
# 1) git merge 성공 시 → 자동 push → PR 생성
# 2) git push 직접 실행 시 → PR 생성 (기존 동작 유지)
#
# "merge 승인 → push → PR 생성"을 하나의 hook으로 묶어 체인을 강제화.
# 기존 열린 PR이 있으면 중복 생성하지 않고 push만으로 PR 갱신.

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

# 현재 브랜치 확인
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null)
if [ "$CURRENT_BRANCH" != "feature/core-secure-layer/dev" ]; then
  exit 0
fi

# git merge 또는 git push 명령만 대상.
# `git -C <path> merge ...` / `git -c <cfg> push ...` 같이 git과 서브커맨드
# 사이에 옵션이 끼는 형태도 포괄하기 위해 "git "와 서브커맨드 사이에 와일드카드를 둔다.
TRIGGER=""
case "$COMMAND" in
  *"git "*"merge"*) TRIGGER="merge" ;;
  *"git "*"push"*)  TRIGGER="push"  ;;
  *) exit 0 ;;
esac

# gh CLI 확인
if ! command -v gh >/dev/null 2>&1; then
  jq -n '{ systemMessage: "⚠️  gh CLI가 설치되지 않아 PR 자동 생성을 건너뜁니다. `brew install gh && gh auth login` 후 재시도하세요." }'
  exit 0
fi

PUSH_MSG=""

# merge 트리거면 자동 push 수행
if [ "$TRIGGER" = "merge" ]; then
  # merge 실패(충돌 등)로 working tree가 더러우면 스킵.
  # .claude/settings.local.json 은 사용자 개인 permissions 파일이라
  # 항상 M 상태로 남을 수 있어 pathspec exclude 로 무시한다.
  DIRTY=$(git status --porcelain -- . ':(exclude).claude/settings.local.json' 2>/dev/null)
  if [ -n "$DIRTY" ]; then
    jq -n '{ systemMessage: "⚠️  merge 후 working tree가 깨끗하지 않음 (충돌 가능) — 자동 push 스킵" }'
    exit 0
  fi

  # 실제로 merge 커밋이 최근에 생겼는지 확인 (단일 parent면 skip)
  PARENT_COUNT=$(git log -1 --format='%P' | wc -w | tr -d ' ')
  if [ "$PARENT_COUNT" -lt 2 ]; then
    # 최신 커밋이 merge 커밋이 아님 — merge가 실제로 일어나지 않았을 수 있음
    exit 0
  fi

  # 자동 push
  PUSH_OUT=$(git push -u origin feature/core-secure-layer/dev 2>&1)
  if [ $? -ne 0 ]; then
    jq -n --arg err "$PUSH_OUT" \
      '{ systemMessage: ("⚠️  자동 push 실패:\n" + $err) }'
    exit 0
  fi
  PUSH_MSG="🚀 feature/core-secure-layer/dev 자동 push 완료"$'\n'
fi

# 기존 열린 PR 확인
EXISTING_JSON=$(gh pr list --head feature/core-secure-layer/dev --base develop --state open --json number,url 2>/dev/null)
EXISTING_NUM=$(echo "$EXISTING_JSON" | jq -r '.[0].number // empty' 2>/dev/null)

if [ -n "$EXISTING_NUM" ]; then
  EXISTING_URL=$(echo "$EXISTING_JSON" | jq -r '.[0].url')
  FINAL_MSG="${PUSH_MSG}ℹ️  기존 PR #${EXISTING_NUM} 갱신됨: ${EXISTING_URL}"
  jq -n --arg msg "$FINAL_MSG" '{ systemMessage: $msg }'
  exit 0
fi

# develop 대비 커밋 수집
COMMITS=$(git log origin/develop..feature/core-secure-layer/dev --format='- %s' 2>/dev/null)
if [ -z "$COMMITS" ]; then
  FINAL_MSG="${PUSH_MSG}ℹ️  develop 대비 새 커밋 없음 — PR 생성 생략"
  jq -n --arg msg "$FINAL_MSG" '{ systemMessage: $msg }'
  exit 0
fi

# 제목: [core-secure-layer] 최신 커밋 메시지 (70자 제한)
LATEST=$(git log origin/develop..feature/core-secure-layer/dev --format='%s' -1)
TITLE="[core-secure-layer] ${LATEST}"
if [ ${#TITLE} -gt 70 ]; then
  TITLE="${TITLE:0:67}..."
fi

# 변경 파일 통계
STAT=$(git diff --stat origin/develop..feature/core-secure-layer/dev 2>/dev/null)

# 본문 조립 — here-doc in $() 는 /tmp 쓰기가 제한된 환경에서
# 실패할 수 있어 literal 문자열 연결로 작성. BODY가 비어 있으면 fail-closed.
BODY="## 변경 요약

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
🤖 Claude Code hook이 자동 생성"

if [ -z "$BODY" ] || [ -z "$TITLE" ]; then
  jq -n '{ systemMessage: "⚠️  PR 본문/제목 생성 실패 — gh pr create 호출을 중단합니다. 수동으로 PR을 생성하세요." }'
  exit 0
fi

# PR 생성
PR_OUT=$(gh pr create \
  --base develop \
  --head feature/core-secure-layer/dev \
  --title "$TITLE" \
  --body "$BODY" 2>&1)

if echo "$PR_OUT" | grep -qE 'https?://'; then
  PR_URL=$(echo "$PR_OUT" | grep -oE 'https?://[^ ]+' | head -1)
  FINAL_MSG="${PUSH_MSG}✅ develop 브랜치로 PR 자동 생성됨: ${PR_URL}"
  jq -n --arg msg "$FINAL_MSG" '{ systemMessage: $msg }'
else
  FINAL_MSG="${PUSH_MSG}⚠️  PR 생성 실패:"$'\n'"${PR_OUT}"
  jq -n --arg msg "$FINAL_MSG" '{ systemMessage: $msg }'
fi

exit 0
