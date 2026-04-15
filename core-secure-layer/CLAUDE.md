# core-secure-layer

## 기술 스택
- Python + LangChain
- 의존성 관리 및 가상환경은 본 모듈 내에서 독립적으로 구성

## 개발 방법론
- **TDD 필수**: 모든 기능은 실패하는 테스트 작성 → 구현 → 리팩터링 순서로 진행
- 테스트 없이 구현 코드부터 작성하지 말 것
- 테스트는 pytest 기반으로 작성

## 코드 품질 (강제)
- **모든 `.py` 파일은 ruff format/check를 통과해야 함**
- `.py` 파일 편집 시 PostToolUse hook이 자동으로 `ruff format` + `ruff check --fix` 실행
- 자동 수정 불가능한 lint 에러가 남으면 hook이 차단하여 Claude가 직접 수정하도록 강제
- **기준: Google Python Style Guide**
- line-length=80, target=py314, Google 스타일 docstring
- 활성화 룰셋: `E, F, I, N, UP, B, SIM, RUF, D, TID, S, G, PT, ANN`
- 주요 강제 사항:
  - 함수/메서드에 타입 힌트 필수 (`ANN`) — `typing.Any`는 허용
  - public 함수/클래스/모듈에 Google 스타일 docstring 필수 (`D`)
  - 상대 import 금지 (`TID252`)
  - `assert`를 런타임 검증에 사용 금지 (`S101`) — 테스트 파일은 예외
  - 로깅은 `logger.info("msg %s", val)` 형태 (`G`)
- 수동 실행: `uv run ruff format .` / `uv run ruff check .`

## 브랜치 및 커밋 규칙
- 통합 브랜치: `feature/core-secure-layer/dev`
- 세부 작업 브랜치: `feature/core-secure-layer/<작업명>` (예: `feature/core-secure-layer/auth`)
- 작업 시작 전 반드시 **브랜치 단위로 작업 계획을 수립**할 것
- 커밋은 **최소 단위**로 분리 (예: 테스트 추가 / 구현 / 리팩터링을 각각 커밋)
- 커밋 메시지는 한글, conventional commits 규칙 준수 (`feat:`, `fix:`, `test:`, `refactor:` 등)
- 모든 커밋에 `Co-Authored-By: Claude <noreply@anthropic.com>` 포함
- **각 단위 작업(테스트/구현/리팩터링)이 완료되면 사용자 확인 없이 즉시 커밋할 것**
- **변경사항이 없으면 커밋 시도하지 말 것** (`git status`로 확인 후 비어있으면 스킵)
- **푸시(`git push`) 기본 원칙**:
  - task 브랜치(`feature/core-secure-layer/<작업명>`)에서는 자동 push 금지 (사용자가 수동으로 진행)
  - 통합 브랜치(`feature/core-secure-layer/dev`)에서는 task 브랜치 머지 직후 자동 push 허용
  - `main`/`develop` 브랜치로의 직접 push는 절대 금지
  - `--force` 계열(`--force`, `--force-with-lease`)은 절대 금지

## 머지 규칙
- **머지는 항상 `--no-ff` 옵션 사용** (fast-forward 금지, 머지 커밋을 명시적으로 생성하여 브랜치 작업 이력 보존)
- **머지 실행 전에는 반드시 사용자에게 확인을 받을 것** — 사전에 계획을 승인받았더라도 실제 `git merge` 명령 직전에 별도 confirmation 필수
- 같은 원칙이 `git reset --hard`, `git rebase` 등 히스토리를 변경하는 작업에도 적용됨

## 레이어 개발 워크플로우 (L1~L8 `check()` 구현)

L1~L8 각 레이어의 `check()` 구현은 반드시 아래 3-에이전트 순차 파이프라인으로 진행한다. 스펙은 `.claude/agents/layer-{tester,implementer,reviewer}.md` 에 정의돼 있으며 Agent tool 로 spawn 한다. **병렬 실행 금지** — 한 번에 한 레이어만.

### 사전 조건
- `feature/core-secure-layer/dev` 가 깨끗하고 origin 과 동기화됨
- 대상 레이어의 **스펙(1~2 문장)** 이 사용자와 합의된 상태
- 의존 레이어가 있다면 그 레이어는 이미 dev 에 머지돼 있음

### 파이프라인 단계
1. **layer-tester spawn** — 레이어 번호 + 스펙 + 의존성 전달
   - 결과: `feature/core-secure-layer/layer-l{N}` 브랜치에 `test: L{N} 실패 테스트 추가` 커밋 1개
2. **layer-implementer spawn** — 동일 레이어 번호 + 스펙 + 브랜치 이름 전달
   - 결과: 같은 브랜치에 `feat: L{N} check() 구현` (+ 선택 `refactor:`) 커밋
3. **layer-reviewer spawn** — 레이어 번호 + 스펙 + 브랜치 이름 전달
   - 결과: `PASS` / `FAIL` verdict + 5개 범주별 findings

### 단계 간 자동 연속 실행
파이프라인 시작이 승인되면 tester → implementer → reviewer 를 **중간 확인 없이 자동 연속 실행** 한다. 각 단계 리포트는 사용자에게 간단히 요약해 보여주되 "다음 단계 진행해도 될까요?" 같은 질문은 하지 말 것.

사용자 승인이 필요한 동기화 지점은 두 개뿐:
1. **파이프라인 시작** — 레이어 스펙 합의 + 실행 승인
2. **최종 머지** — task 브랜치 → dev `--no-ff` 머지 (아래 "머지 규칙" 과 "작업 흐름" 그대로 적용)

reviewer 가 FAIL 을 내거나 중간 단계에서 blocker 가 발생하면 그 시점에 즉시 사용자에게 보고하고 의사결정을 받는다.

### 실패 / blocker 처리
- **tester blocker**: 스펙 모호성이면 사용자와 재협의 후 re-spawn. base.py 변경 같은 범위 초과면 별도 작업으로 분리.
- **implementer blocker**: 5회 시도 후에도 실패하면, 테스트가 부당한지 구현이 부당한지 사용자와 함께 판단. 전자면 tester 재실행, 후자면 implementer 재실행 (프롬프트 개선 후).
- **reviewer FAIL**: findings 를 보고 어떤 단계로 돌아갈지 사용자가 결정. 여러 범주가 동시 FAIL 이면 가장 상류인 tester 부터.

### 머지 이후
reviewer 가 PASS 를 내고 사용자 승인이 떨어지면 아래 "작업 흐름" 섹션의 6~10번 단계(`--no-ff` 머지 → auto push → PR 생성/갱신 → `gh pr edit`) 를 그대로 따른다.

## 작업 흐름
1. 작업 대상을 브랜치 단위로 쪼개 계획 수립
2. `feature/core-secure-layer/dev`에서 `feature/core-secure-layer/<작업명>` 분기
3. 실패하는 테스트 작성 → 커밋
4. 구현 → 커밋
5. 리팩터링 → 커밋
6. `feature/core-secure-layer/dev`로 머지 (`--no-ff`, 사용자 확인 필수)
7. 머지가 성공하면 hook(`auto-pr-on-push.sh`)이 **자동으로**:
   - `git push -u origin feature/core-secure-layer/dev` 실행
   - `develop`로 PR 생성 (`gh pr create --base develop`)
   - 기존 열린 PR이 있으면 push로 자동 갱신 (PR 중복 생성 방지)
   - 제목/본문은 **임시 auto-generated** 상태 (hook은 의미 파악 불가)
8. **Claude는 PR이 자동 생성됨을 인식하는 즉시** `gh pr edit <num> --title ... --body ...`을 실행해 의미 있는 제목과 본문으로 교체할 것
   - 제목 형식: `[core-secure-layer] <변경사항을 포괄하는 한 줄 요약>`
   - 본문: Summary / 주요 변경 / 테스트 / (필요 시) 다음 작업 섹션으로 구성
   - 커밋 메시지를 나열하는 대신, **커밋 내용을 분석해 그룹화**할 것
9. Stop hook이 PR 본문에 hook의 auto-generated 마커(`🤖 Claude Code hook이 자동 생성`)가 남아있으면 응답 종료를 차단하여 8번 단계를 강제함
10. develop 머지는 GitHub 웹에서 사용자가 직접 진행 (Claude는 PR 생성/개선까지만)
