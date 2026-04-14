# admin-frontend

Agentic AI Guardrail Admin Console (React + TypeScript SPA).

## 개발

```bash
npm install
npm run dev      # Vite 개발 서버
npm test         # Vitest 실행 (TDD)
```

## 구조

- `src/pages/` — 화면 컴포넌트 (LoginPage, PoliciesPage, AuditLogPage) — 구현 예정
- `src/__tests__/` — React Testing Library 기반 실패 테스트 (TDD Red 단계)
- `src/test/setup.ts` — jest-dom matcher 확장

## TDD 상태

현재 테스트는 의도적으로 실패합니다 (`src/pages/*`가 존재하지 않음).
후속 구현 태스크(#4)에서 각 페이지 컴포넌트를 작성하여 테스트를 통과시킵니다.
