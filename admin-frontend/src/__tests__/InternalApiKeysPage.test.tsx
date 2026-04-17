import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { InternalApiKeysPage } from '@/pages/InternalApiKeysPage';

const mockKeys = [
  {
    id: 1,
    name: 'gw-prod-01',
    description: '운영 Gateway',
    keyPrefix: 'iak_AbCdEfGh',
    expiresAt: null,
    revokedAt: null,
    lastUsedAt: '2026-04-14T10:00:00Z',
    createdAt: '2026-04-10T00:00:00Z',
    updatedAt: '2026-04-14T10:00:00Z',
  },
  {
    id: 2,
    name: 'gw-old',
    description: null,
    keyPrefix: 'iak_ZzYyXxWw',
    expiresAt: null,
    revokedAt: '2026-04-12T00:00:00Z',
    lastUsedAt: null,
    createdAt: '2026-04-01T00:00:00Z',
    updatedAt: '2026-04-12T00:00:00Z',
  },
];

describe('InternalApiKeysPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const renderPage = () =>
    render(
      <MemoryRouter>
        <InternalApiKeysPage />
      </MemoryRouter>,
    );

  it('마운트 시 목록을 가져와 렌더링한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockKeys), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('gw-prod-01')).toBeInTheDocument();
    expect(screen.getByText('gw-old')).toBeInTheDocument();
  });

  it('활성 키와 폐기된 키를 각각의 칩으로 구분해 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockKeys), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('활성')).toBeInTheDocument();
    expect(screen.getByText('폐기됨')).toBeInTheDocument();
  });

  it('새 키 발급 폼 제출 시 POST 호출 + plainKey 모달을 표시한다', async () => {
    const created = {
      id: 3,
      name: '신규',
      description: '',
      keyPrefix: 'iak_NnNnNnNn',
      expiresAt: null,
      revokedAt: null,
      lastUsedAt: null,
      createdAt: '2026-04-17T00:00:00Z',
      updatedAt: '2026-04-17T00:00:00Z',
      plainKey: 'iak_NnNnNnNnAaBbCcDdEeFfGgHhIiJjKk',
    };
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockKeys), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(created), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([...mockKeys, created]), { status: 200 }));

    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: /새 키/ }));
    await userEvent.type(screen.getByLabelText('이름'), '신규');
    await userEvent.click(screen.getByRole('button', { name: '발급' }));

    await waitFor(() => {
      const postCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          typeof url === 'string' &&
          url === '/api/v1/internal-api-keys' &&
          (init as RequestInit | undefined)?.method === 'POST',
      );
      expect(postCall).toBeTruthy();
    });

    expect(await screen.findByText(created.plainKey)).toBeInTheDocument();
    expect(screen.getByText(/다시 볼 수 없습니다/)).toBeInTheDocument();
  });

  it('평문 노출 모달의 복사 버튼은 navigator.clipboard.writeText를 호출한다', async () => {
    const created = {
      id: 4,
      name: 'x',
      description: null,
      keyPrefix: 'iak_Cccccccc',
      expiresAt: null,
      revokedAt: null,
      lastUsedAt: null,
      createdAt: '2026-04-17T00:00:00Z',
      updatedAt: '2026-04-17T00:00:00Z',
      plainKey: 'iak_CcccccccCOPY',
    };
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(created), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([created]), { status: 200 }));

    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: /새 키/ }));
    await userEvent.type(screen.getByLabelText('이름'), 'x');
    await userEvent.click(screen.getByRole('button', { name: '발급' }));

    await screen.findByText('iak_CcccccccCOPY');
    await userEvent.click(screen.getByRole('button', { name: '복사' }));
    expect(writeText).toHaveBeenCalledWith('iak_CcccccccCOPY');
  });

  it('폐기 버튼 클릭 시 confirm을 통과하면 revoke POST를 호출한다', async () => {
    const confirmSpy = vi.spyOn(globalThis, 'confirm').mockReturnValue(true);
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockKeys), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({}), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(mockKeys), { status: 200 }));

    renderPage();
    await screen.findByText('gw-prod-01');
    await userEvent.click(screen.getByRole('button', { name: 'gw-prod-01 폐기' }));

    expect(confirmSpy).toHaveBeenCalled();
    await waitFor(() => {
      const revokeCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          typeof url === 'string' &&
          url === '/api/v1/internal-api-keys/1/revoke' &&
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
