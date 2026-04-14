import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { PoliciesPage } from '@/pages/PoliciesPage';

const mockPolicies = [
  { id: '1', name: 'PII 차단', enabled: true, action: 'block' },
  { id: '2', name: '욕설 필터', enabled: false, action: 'mask' },
];

describe('PoliciesPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.setItem('admin_token', 'jwt-token');
  });

  const renderPage = () =>
    render(
      <MemoryRouter>
        <PoliciesPage />
      </MemoryRouter>,
    );

  it('마운트 시 정책 목록을 불러와 렌더링한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPolicies), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('PII 차단')).toBeInTheDocument();
    expect(screen.getByText('욕설 필터')).toBeInTheDocument();
  });

  it('정책 활성화 토글을 PATCH로 전송한다', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockPolicies), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    renderPage();
    const toggle = await screen.findByRole('switch', { name: /PII 차단/ });
    await userEvent.click(toggle);
    await waitFor(() => {
      expect(fetchMock).toHaveBeenLastCalledWith(
        expect.stringContaining('/api/admin/policies/1'),
        expect.objectContaining({ method: 'PATCH' }),
      );
    });
  });

  it('새 정책 생성 폼을 제출하면 POST 요청을 보낸다', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockPolicies), { status: 200 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: '3', name: '신규', enabled: true, action: 'block' }), {
          status: 201,
        }),
      );
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: /추가|new|생성/i }));
    await userEvent.type(screen.getByLabelText(/정책명|name/i), '신규');
    await userEvent.click(screen.getByRole('button', { name: /저장|save/i }));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenLastCalledWith(
        expect.stringContaining('/api/admin/policies'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  it('API 호출 시 Authorization 헤더를 포함한다', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPolicies), { status: 200 }),
    );
    renderPage();
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalled();
      const init = fetchMock.mock.calls[0][1] as RequestInit;
      const headers = new Headers(init?.headers);
      expect(headers.get('Authorization')).toBe('Bearer jwt-token');
    });
  });
});
