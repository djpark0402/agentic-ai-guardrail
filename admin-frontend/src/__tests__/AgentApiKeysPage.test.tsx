import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { AgentApiKeysPage } from '@/pages/AgentApiKeysPage';

const mockKeys = [
  {
    id: 1,
    clientName: '고객사A',
    description: '운영',
    keyPrefix: 'ak_AbCdEfGh',
    expiresAt: null,
    revokedAt: null,
    lastUsedAt: '2026-04-14T10:00:00Z',
    createdAt: '2026-04-10T00:00:00Z',
    updatedAt: '2026-04-14T10:00:00Z',
  },
  {
    id: 2,
    clientName: '고객사B (구버전)',
    description: null,
    keyPrefix: 'ak_ZzYyXxWw',
    expiresAt: null,
    revokedAt: '2026-04-12T00:00:00Z',
    lastUsedAt: null,
    createdAt: '2026-04-01T00:00:00Z',
    updatedAt: '2026-04-12T00:00:00Z',
  },
];

describe('AgentApiKeysPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const renderPage = () =>
    render(
      <MemoryRouter>
        <AgentApiKeysPage />
      </MemoryRouter>,
    );

  it('마운트 시 목록을 가져와 렌더링한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockKeys), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('고객사A')).toBeInTheDocument();
    expect(screen.getByText('고객사B (구버전)')).toBeInTheDocument();
  });

  it('활성 키와 폐기된 키를 칩으로 구분한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockKeys), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('활성')).toBeInTheDocument();
    expect(screen.getByText('폐기됨')).toBeInTheDocument();
  });

  it('새 키 발급 시 모달에 apiKey + secret 두 줄을 표시한다', async () => {
    const created = {
      id: 3,
      clientName: '신규고객',
      description: '',
      keyPrefix: 'ak_NnNnNnNn',
      expiresAt: null,
      revokedAt: null,
      lastUsedAt: null,
      createdAt: '2026-04-17T00:00:00Z',
      updatedAt: '2026-04-17T00:00:00Z',
      apiKey: 'ak_NnNnNnNnAaBbCcDdEeFfGgHhIiJjKk',
      secret: 'SsSsSsSsSsSsSsSsSsSsSsSsSsSsSsSsSsSsSsSsSsS',
    };
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockKeys), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(created), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([...mockKeys, created]), { status: 200 }));

    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: /새 키/ }));
    await userEvent.type(screen.getByLabelText('고객사명'), '신규고객');
    await userEvent.click(screen.getByRole('button', { name: '발급' }));

    expect(await screen.findByText(created.apiKey)).toBeInTheDocument();
    expect(screen.getByText(created.secret)).toBeInTheDocument();
    expect(screen.getByText(/다시 볼 수 없습니다/)).toBeInTheDocument();
  });

  it('API Key 복사 버튼은 apiKey를, Secret 복사 버튼은 secret을 클립보드에 쓴다', async () => {
    const created = {
      id: 4,
      clientName: '복사테스트',
      description: null,
      keyPrefix: 'ak_Cccccccc',
      expiresAt: null, revokedAt: null, lastUsedAt: null,
      createdAt: '2026-04-17T00:00:00Z', updatedAt: '2026-04-17T00:00:00Z',
      apiKey: 'ak_CcccccccAPIKEY_full',
      secret: 'SECRET_full_value',
    };
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(created), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([created]), { status: 200 }));

    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: /새 키/ }));
    await userEvent.type(screen.getByLabelText('고객사명'), '복사테스트');
    await userEvent.click(screen.getByRole('button', { name: '발급' }));

    await screen.findByText(created.apiKey);
    await userEvent.click(screen.getByRole('button', { name: 'API Key 복사' }));
    expect(writeText).toHaveBeenLastCalledWith(created.apiKey);

    await userEvent.click(screen.getByRole('button', { name: 'Secret 복사' }));
    expect(writeText).toHaveBeenLastCalledWith(created.secret);
  });

  it('폐기 버튼 클릭 시 confirm을 통과하면 revoke POST를 호출한다', async () => {
    const confirmSpy = vi.spyOn(globalThis, 'confirm').mockReturnValue(true);
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockKeys), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({}), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(mockKeys), { status: 200 }));

    renderPage();
    await screen.findByText('고객사A');
    await userEvent.click(screen.getByRole('button', { name: '고객사A 폐기' }));

    expect(confirmSpy).toHaveBeenCalled();
    await waitFor(() => {
      const revokeCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          typeof url === 'string' &&
          url === '/api/v1/agent-api-keys/1/revoke' &&
          (init as RequestInit | undefined)?.method === 'POST',
      );
      expect(revokeCall).toBeTruthy();
    });
  });

  it('로딩 실패 시 오류 메시지를 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('err', { status: 500 }));
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/불러오지 못했습니다/);
  });
});
