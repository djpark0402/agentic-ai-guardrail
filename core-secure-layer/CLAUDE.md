# core-secure-layer

## 기술 스택
- Python + LangChain
- 의존성 관리 및 가상환경은 본 모듈 내에서 독립적으로 구성

## 개발 방법론
- **TDD 필수**: 모든 기능은 실패하는 테스트 작성 → 구현 → 리팩터링 순서로 진행
- 테스트 없이 구현 코드부터 작성하지 말 것
- 테스트는 pytest 기반으로 작성

## 브랜치 및 커밋 규칙
- 통합 브랜치: `feature/core-secure-dev`
- 세부 작업 브랜치: `feature/core-secure-<작업명>` (예: `feature/core-secure-auth`)
- 작업 시작 전 반드시 **브랜치 단위로 작업 계획을 수립**할 것
- 커밋은 **최소 단위**로 분리 (예: 테스트 추가 / 구현 / 리팩터링을 각각 커밋)
- 커밋 메시지는 한글, conventional commits 규칙 준수 (`feat:`, `fix:`, `test:`, `refactor:` 등)
- 모든 커밋에 `Co-Authored-By: Claude <noreply@anthropic.com>` 포함
- **각 단위 작업(테스트/구현/리팩터링)이 완료되면 사용자 확인 없이 즉시 커밋할 것**
- **변경사항이 없으면 커밋 시도하지 말 것** (`git status`로 확인 후 비어있으면 스킵)
- **푸시(`git push`)는 절대 자동으로 하지 말 것 — 사용자가 수동으로 진행**

## 작업 흐름
1. 작업 대상을 브랜치 단위로 쪼개 계획 수립
2. `feature/core-secure-dev`에서 `feature/core-secure-<작업명>` 분기
3. 실패하는 테스트 작성 → 커밋
4. 구현 → 커밋
5. 리팩터링 → 커밋
6. `feature/core-secure-dev`로 머지
