import { FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';

export function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!username || !password) {
      setError('아이디와 비밀번호는 필수입니다.');
      return;
    }
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        setError('로그인에 실패했습니다. 아이디 또는 비밀번호가 잘못되었습니다.');
        return;
      }
      const data = await res.json();
      localStorage.setItem('admin_token', data.token);
      navigate('/admin/policies');
    } catch {
      setError('로그인에 실패했습니다.');
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      <h1>관리자 로그인</h1>
      <div>
        <label htmlFor="username">아이디</label>
        <input
          id="username"
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </div>
      <div>
        <label htmlFor="password">비밀번호</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      {error && <p role="alert">{error}</p>}
      <button type="submit">로그인</button>
    </form>
  );
}
