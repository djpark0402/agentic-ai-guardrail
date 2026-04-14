#!/bin/bash

# Claude가 git commit을 실행하려 할 때만 동작
if echo "$CLAUDE_TOOL_INPUT" | grep -q "git commit"; then
  echo "🔍 Running Java lint before commit..."

  # Checkstyle 사용 시
  if [ -f "checkstyle.xml" ]; then
    mvn checkstyle:check
  # Google Java Format 사용 시
  elif [ -f "gradlew" ]; then
    ./gradlew checkstyleMain checkstyleTest
  elif [ -f "mvnw" ]; then
    ./mvnw checkstyle:check
  fi

  if [ $? -ne 0 ]; then
    echo "❌ Lint failed. Commit aborted."
    exit 1  # exit 1 → Claude의 도구 실행을 차단
  fi

  echo "✅ Lint passed."
fi