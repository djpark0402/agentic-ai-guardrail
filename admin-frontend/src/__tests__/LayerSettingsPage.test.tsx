import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { LayerSettingsPage } from '@/pages/LayerSettingsPage';

const mockPolicies = [
  {
    id: 1,
    name: 'default-strict',
    description: '기본 엄격',
    l1Enabled: true,
    l2Enabled: true,
    l3Enabled: false,
    l4Enabled: false,
    l5Enabled: true,
    l6Enabled: true,
    isUse: true,
    createdAt: '2026-04-14T00:00:00Z',
    updatedAt: '2026-04-14T00:00:00Z',
  },
  {
    id: 2,
    name: 'dev-lenient',
    description: '개발용',
    l1Enabled: false,
    l2Enabled: false,
    l3Enabled: true,
    l4Enabled: false,
    l5Enabled: false,
    l6Enabled: false,
    isUse: false,
    createdAt: '2026-04-14T01:00:00Z',
    updatedAt: '2026-04-14T01:00:00Z',
  },
];

describe('LayerSettingsPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const renderPage = () =>
    render(
      <MemoryRouter>
        <LayerSettingsPage />
      </MemoryRouter>,
    );

  it('마운트 시 정책 목록을 불러와 렌더링한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPolicies), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('default-strict')).toBeInTheDocument();
    expect(screen.getByText('dev-lenient')).toBeInTheDocument();
  });

  it('활성 정책 행에 활성 칩이 표시된다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPolicies), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('활성')).toBeInTheDocument();
  });

  it('읽기 상태에서는 스위치를 클릭해도 PUT을 보내지 않는다', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPolicies), { status: 200 }),
    );
    renderPage();
    const toggle = await screen.findByRole('switch', { name: /default-strict l3Enabled/ });
    await userEvent.click(toggle);
    expect(fetchMock.mock.calls.some(([, init]) => (init as RequestInit | undefined)?.method === 'PUT')).toBe(false);
  });

  it('수정 버튼 → 스위치 토글 → 저장 시 PUT 요청을 보낸다', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockPolicies), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({}), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(mockPolicies), { status: 200 }));

    renderPage();
    await screen.findByText('default-strict');

    await userEvent.click(screen.getAllByRole('button', { name: '수정' })[0]);
    await userEvent.click(screen.getByRole('switch', { name: /default-strict l3Enabled/ }));
    await userEvent.click(screen.getByRole('button', { name: '저장' }));

    await waitFor(() => {
      const putCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          typeof url === 'string' &&
          url.includes('/api/v1/policies/1') &&
          (init as RequestInit | undefined)?.method === 'PUT',
      );
      expect(putCall).toBeTruthy();
    });
  });

  it('수정 모드 취소 시 PUT이 발생하지 않는다', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockPolicies), { status: 200 }),
    );
    renderPage();
    await screen.findByText('default-strict');

    await userEvent.click(screen.getAllByRole('button', { name: '수정' })[0]);
    await userEvent.click(screen.getByRole('button', { name: '취소' }));

    expect(fetchMock.mock.calls.some(([, init]) => (init as RequestInit | undefined)?.method === 'PUT')).toBe(false);
  });

  it('활성화 버튼 클릭 시 activate 엔드포인트 POST를 호출한다', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockPolicies), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({}), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(mockPolicies), { status: 200 }));

    renderPage();
    await screen.findByText('dev-lenient');
    await userEvent.click(screen.getByRole('button', { name: '활성화' }));

    await waitFor(() => {
      const activateCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          typeof url === 'string' &&
          url.includes('/api/v1/policies/2/activate') &&
          (init as RequestInit | undefined)?.method === 'POST',
      );
      expect(activateCall).toBeTruthy();
    });
  });

  it('새 정책 추가 시 L1~L6 스위치 조작 후 POST가 해당 값으로 전송된다', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockPolicies), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 3 }), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(mockPolicies), { status: 200 }));

    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: /새 정책/ }));
    await userEvent.type(screen.getByLabelText('정책명'), '신규');
    await userEvent.click(screen.getByRole('switch', { name: '새 정책 l1Enabled' }));
    await userEvent.click(screen.getByRole('button', { name: '저장' }));

    await waitFor(() => {
      const postCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          typeof url === 'string' &&
          url === '/api/v1/policies' &&
          (init as RequestInit | undefined)?.method === 'POST',
      );
      expect(postCall).toBeTruthy();
      const body = JSON.parse((postCall![1] as RequestInit).body as string);
      expect(body.name).toBe('신규');
      expect(body.l1Enabled).toBe(false); // 초기 true에서 토글로 false
    });
  });

  it('저장 버튼을 빠르게 연타해도 POST는 한 번만 발생한다', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockPolicies), { status: 200 }))
      .mockImplementation(
        () =>
          new Promise((resolve) =>
            setTimeout(() => resolve(new Response(JSON.stringify({ id: 3 }), { status: 201 })), 50),
          ),
      );

    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: /새 정책/ }));
    await userEvent.type(screen.getByLabelText('정책명'), '중복방지');
    const saveBtn = screen.getByRole('button', { name: '저장' });
    await userEvent.click(saveBtn);
    await userEvent.click(saveBtn);
    await userEvent.click(saveBtn);

    await waitFor(() => {
      const postCount = fetchMock.mock.calls.filter(
        ([url, init]) =>
          typeof url === 'string' &&
          url === '/api/v1/policies' &&
          (init as RequestInit | undefined)?.method === 'POST',
      ).length;
      expect(postCount).toBe(1);
    });
  });

  it('로딩 실패 시 오류 메시지를 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('server error', { status: 500 }),
    );
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/불러오지 못했습니다/);
  });
});
