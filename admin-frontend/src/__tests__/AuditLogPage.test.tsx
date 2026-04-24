import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { AuditLogPage } from '@/pages/AuditLogPage';

const mockPage = {
  content: [
    {
      id: 1,
      occurredAt: '2026-04-14T10:00:00Z',
      actionId: 'ADMIN',
      action: 'POLICY_UPDATE',
      success: true,
      detail: 'policy id=1',
    },
    {
      id: 2,
      occurredAt: '2026-04-14T10:01:00Z',
      actionId: 'GATEWAY',
      action: 'POLICY_REQUEST',
      success: false,
      detail: null,
    },
  ],
  totalElements: 2,
  totalPages: 1,
  page: 0,
  size: 20,
};

describe('AuditLogPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const renderPage = () =>
    render(
      <MemoryRouter>
        <AuditLogPage />
      </MemoryRouter>,
    );

  it('마운트 시 자동으로 로그를 조회해 렌더링한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPage), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('POLICY_UPDATE')).toBeInTheDocument();
    expect(screen.getByText('POLICY_REQUEST')).toBeInTheDocument();
  });

  it('호출자 필터 변경 시 actionId 파라미터를 포함한 재요청이 발생한다', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPage), { status: 200 }),
    );
    renderPage();
    await screen.findByText('POLICY_UPDATE');

    await userEvent.selectOptions(screen.getByLabelText('호출자'), 'ADMIN');

    await waitFor(() => {
      const lastUrl = fetchMock.mock.calls.at(-1)?.[0] as string;
      expect(lastUrl).toContain('actionId=ADMIN');
    });
  });

  it('정렬 컬럼 헤더 클릭 시 sort 파라미터가 바뀐다', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPage), { status: 200 }),
    );
    renderPage();
    await screen.findByText('POLICY_UPDATE');

    await userEvent.click(screen.getByRole('columnheader', { name: /액션/ }));

    await waitFor(() => {
      const lastUrl = fetchMock.mock.calls.at(-1)?.[0] as string;
      expect(lastUrl).toContain('sort=action');
    });
  });

  it('날짜 필터 입력 시 ISO 형식으로 from/to 가 포함된다', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPage), { status: 200 }),
    );
    renderPage();
    await screen.findByText('POLICY_UPDATE');

    await userEvent.type(screen.getByLabelText('시작일'), '2026-04-01');
    await userEvent.type(screen.getByLabelText('종료일'), '2026-04-14');

    await waitFor(() => {
      const lastUrl = fetchMock.mock.calls.at(-1)?.[0] as string;
      expect(lastUrl).toContain('from=2026-04-01T00%3A00%3A00Z');
      expect(lastUrl).toContain('to=2026-04-14T23%3A59%3A59Z');
    });
  });

  it('빈 결과일 때 안내 메시지를 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ content: [], totalElements: 0, totalPages: 0, page: 0, size: 20 }), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText(/조회된 로그가 없습니다/)).toBeInTheDocument();
  });

  it('로드 실패 시 오류 메시지를 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('server error', { status: 500 }),
    );
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/오류/);
  });
});
