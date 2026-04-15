#!/bin/bash
# Stop hook 안전망:
# 1) core-secure-layer에 미커밋 변경사항이 있으면 커밋 강제
# 2) 자동 생성된 PR이 있으면 의미 있는 제목/본문으로 개선 강제
#
# 단, Claude의 마지막 메시지가 질문(? 로 끝남)이면 hook 건너뜀.

INPUT=$(cat)

# 1) Claude가 사용자에게 질문 중이면 hook 건너뛰기
TRANSCRIPT_PATH=$(echo "$INPUT" | jq -r '.transcript_path // empty' 2>/dev/null)
if [ -n "$TRANSCRIPT_PATH" ] && [ -f "$TRANSCRIPT_PATH" ]; then
  LAST_TEXT=$(jq -rs '
    [.[] | select(.type == "assistant") | .message.content[]? | select(.type == "text") | .text]
    | last // ""
  ' "$TRANSCRIPT_PATH" 2>/dev/null)

  # 마지막 문자가 ? 또는 ?(전각) 이면 질문으로 간주
  TRIMMED=$(echo -n "$LAST_TEXT" | sed -E 's/[[:space:]]+$//')
  LAST_CHAR=$(echo -n "$TRIMMED" | tail -c 3)
  if [[ "$LAST_CHAR" == *"?"* ]] || [[ "$LAST_CHAR" == *"？"* ]]; then
    exit 0
  fi
fi

# 2) 이 프로젝트가 아니면 조용히 통과
if [ ! -d "core-secure-layer" ]; then
  exit 0
fi

# 3) core-secure-layer의 미커밋/미스테이지 변경사항 감지
if [ -n "$(git status --porcelain core-secure-layer/ 2>/dev/null)" ]; then
  cat <<'EOF'
{
  "decision": "block",
  "reason": "core-secure-layer에 미커밋 변경사항이 있습니다. CLAUDE.md 규칙(최소 커밋 단위, 한글 conventional commits, Co-Authored-By 포함)에 따라 즉시 커밋하세요. 푸시는 절대 하지 마세요."
}
EOF
  exit 0
fi

# 4) 자동 생성된 PR이 있으면 개선 강제
#    (hook이 생성한 본문에는 "🤖 Claude Code hook이 자동 생성" 마커가 있음.
#     Claude가 gh pr edit으로 본문을 교체하면 이 마커가 사라져 더 이상 block하지 않음)
if command -v gh >/dev/null 2>&1; then
  PR_JSON=$(gh pr list --head feature/core-secure-layer/dev --base develop --state open --json number,url,body 2>/dev/null)
  if [ -n "$PR_JSON" ] && [ "$PR_JSON" != "[]" ]; then
    PR_NUM=$(echo "$PR_JSON" | jq -r '.[0].number // empty')
    PR_URL=$(echo "$PR_JSON" | jq -r '.[0].url // empty')
    PR_BODY=$(echo "$PR_JSON" | jq -r '.[0].body // empty')

    if echo "$PR_BODY" | grep -q '🤖 Claude Code hook이 자동 생성'; then
      jq -n \
        --arg num "$PR_NUM" \
        --arg url "$PR_URL" \
        '{
          decision: "block",
          reason: ("PR #" + $num + "이 hook의 자동 생성 상태입니다. 커밋 내역을 분석해서 의미 있는 제목과 본문으로 즉시 `gh pr edit " + $num + " --title ... --body ...`을 실행하세요. (" + $url + ")")
        }'
      exit 0
    fi
  fi
fi

exit 0
