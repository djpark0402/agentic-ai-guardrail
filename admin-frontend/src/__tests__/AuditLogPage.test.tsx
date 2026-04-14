import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { AuditLogPage } from '@/pages/AuditLogPage';

const mockLogs = {
  items: [
    {
      id: 'a1',
      timestamp: '2026-04-14T10:00:00Z',
      actor: 'admin',
      action: 'POLICY_UPDATE',
      result: 'SUCCESS',
    },
    {
      id: 'a2',
      timestamp: '2026-04-14T10:01:00Z',
      actor: 'agent-1',
      action: 'REQUEST_BLOCKED',
      result: 'BLOCKED',
    },
  ],
  total: 2,
};

describe('AuditLogPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.setItem('admin_token', 'jwt-token');
  });

  const renderPage = () =>
    render(
      <MemoryRouter>
        <AuditLogPage />
      </MemoryRouter>,
    );

  it('감사 로그 테이블을 렌더링한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockLogs), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('POLICY_UPDATE')).toBeInTheDocument();
    expect(screen.getByText('REQUEST_BLOCKED')).toBeInTheDocument();
    expect(screen.getByRole('table')).toBeInTheDocument();
  });

  it('날짜 범위 필터 적용 시 쿼리 파라미터를 포함해 재요청한다', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockLogs), { status: 200 }),
    );
    renderPage();
    await screen.findByText('POLICY_UPDATE');

    await userEvent.type(screen.getByLabelText(/시작|from/i), '2026-04-01');
    await userEvent.type(screen.getByLabelText(/종료|to/i), '2026-04-14');
    await userEvent.click(screen.getByRole('button', { name: /검색|search|적용/i }));

    await waitFor(() => {
      const lastUrl = fetchMock.mock.calls.at(-1)?.[0] as string;
      expect(lastUrl).toContain('from=2026-04-01');
      expect(lastUrl).toContain('to=2026-04-14');
    });
  });

  it('빈 결과일 때 안내 메시지를 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0 }), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText(/없|empty|no data/i)).toBeInTheDocument();
  });

  it('로드 실패 시 오류 메시지를 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('server error', { status: 500 }),
    );
    renderPage();
    expect(await screen.findByText(/오류|error|실패/i)).toBeInTheDocument();
  });
});
