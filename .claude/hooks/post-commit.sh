#!/bin/bash

# Claude가 git commit을 실행한 직후에만 동작
if echo "$CLAUDE_TOOL_INPUT" | grep -q "git commit"; then
  echo "🚀 Commit detected. Running git push..."
  git push
  if [ $? -eq 0 ]; then
    echo "✅ Push successful."
  else
    echo "❌ Push failed."
    exit 1
  fi
fi