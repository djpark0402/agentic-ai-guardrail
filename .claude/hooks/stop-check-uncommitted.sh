#!/bin/bash
# core-secure-layer에 미커밋 변경사항이 있으면 Stop을 차단하고
# Claude에게 커밋하도록 알림. 직접 git commit은 하지 않음.
#
# 단, Claude의 마지막 메시지가 사용자에게 질문하는 형태(? 로 끝남)이면
# 작업이 진행 중이라고 보고 hook을 건너뜀.

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
  if [[ "$LAST_CHAR" == *"?"* ]] || [[ "$LAST_CHAR" == *"?"* ]]; then
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
fi

exit 0
