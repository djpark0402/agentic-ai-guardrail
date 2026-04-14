#!/bin/bash
# core-secure-layer에 미커밋 변경사항이 있으면 Stop을 차단하고
# Claude에게 커밋하도록 알림. 직접 git commit은 하지 않음.

# 이 프로젝트가 아니면 조용히 통과
if [ ! -d "core-secure-layer" ]; then
  exit 0
fi

# core-secure-layer의 미커밋/미스테이지 변경사항 감지
if [ -n "$(git status --porcelain core-secure-layer/ 2>/dev/null)" ]; then
  cat <<'EOF'
{
  "decision": "block",
  "reason": "core-secure-layer에 미커밋 변경사항이 있습니다. CLAUDE.md 규칙(최소 커밋 단위, 한글 conventional commits, Co-Authored-By 포함)에 따라 즉시 커밋하세요. 푸시는 절대 하지 마세요."
}
EOF
fi

exit 0
