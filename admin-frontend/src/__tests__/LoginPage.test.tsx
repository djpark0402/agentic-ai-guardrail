import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { LoginPage } from '@/pages/LoginPage';

describe('LoginPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const renderPage = () =>
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    );

  it('아이디/비밀번호 입력 필드와 로그인 버튼을 렌더링한다', () => {
    renderPage();
    expect(screen.getByLabelText(/아이디|username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/비밀번호|password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /로그인|login/i })).toBeInTheDocument();
  });

  it('빈 값으로 제출하면 유효성 오류를 표시한다', async () => {
    renderPage();
    await userEvent.click(screen.getByRole('button', { name: /로그인|login/i }));
    expect(await screen.findByText(/필수|required/i)).toBeInTheDocument();
  });

  it('성공 시 /admin/policies로 이동하며 토큰을 저장한다', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ token: 'jwt-token' }), { status: 200 }),
    );
    renderPage();
    await userEvent.type(screen.getByLabelText(/아이디|username/i), 'admin');
    await userEvent.type(screen.getByLabelText(/비밀번호|password/i), 'secret');
    await userEvent.click(screen.getByRole('button', { name: /로그인|login/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/admin/login'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(localStorage.getItem('admin_token')).toBe('jwt-token');
  });

  it('인증 실패 시 오류 메시지를 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ message: 'invalid' }), { status: 401 }),
    );
    renderPage();
    await userEvent.type(screen.getByLabelText(/아이디|username/i), 'admin');
    await userEvent.type(screen.getByLabelText(/비밀번호|password/i), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: /로그인|login/i }));
    expect(await screen.findByText(/실패|invalid|잘못/i)).toBeInTheDocument();
  });
});
