import { FormEvent, useEffect, useState } from 'react';

type AuditLog = {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  result: string;
};

type AuditLogResponse = {
  items: AuditLog[];
  total: number;
};

function authHeaders(): HeadersInit {
  const token = localStorage.getItem('admin_token') ?? '';
  return { Authorization: `Bearer ${token}` };
}

export function AuditLogPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');

  async function fetchLogs(fromValue = '', toValue = '') {
    setError(null);
    const params = new URLSearchParams();
    params.set('from', fromValue);
    params.set('to', toValue);
    try {
      const res = await fetch(`/api/admin/audit-logs?${params.toString()}`, {
        method: 'GET',
        headers: authHeaders(),
      });
      if (!res.ok) {
        setError('감사 로그를 불러오는 중 오류가 발생했습니다.');
        setLoaded(true);
        return;
      }
      const data: AuditLogResponse = await res.json();
      setLogs(data.items);
      setTotal(data.total);
      setLoaded(true);
    } catch {
      setError('감사 로그를 불러오는 중 오류가 발생했습니다.');
      setLoaded(true);
    }
  }

  useEffect(() => {
    fetchLogs();
  }, []);

  function handleSearch(e: FormEvent) {
    e.preventDefault();
    fetchLogs(from, to);
  }

  return (
    <div className="sakura-page">
      <h1>감사 로그</h1>
      <form onSubmit={handleSearch}>
        <label htmlFor="from">시작일</label>
        <input id="from" type="text" value={from} onChange={(e) => setFrom(e.target.value)} />
        <label htmlFor="to">종료일</label>
        <input id="to" type="text" value={to} onChange={(e) => setTo(e.target.value)} />
        <button type="submit">검색</button>
      </form>
      {error && <p role="alert">{error}</p>}
      {!error && loaded && total === 0 && <p>조회된 로그가 없습니다.</p>}
      {!error && logs.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>시간</th>
              <th>행위자</th>
              <th>액션</th>
              <th>결과</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id}>
                <td>{log.timestamp}</td>
                <td>{log.actor}</td>
                <td>{log.action}</td>
                <td>{log.result}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
