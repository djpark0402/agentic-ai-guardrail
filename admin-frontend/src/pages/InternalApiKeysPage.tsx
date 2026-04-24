import { FormEvent, useCallback, useEffect, useState } from 'react';

type ApiKey = {
  id: number;
  name: string;
  description: string | null;
  keyPrefix: string;
  expiresAt: string | null;
  revokedAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

type IssuedKey = ApiKey & { plainKey: string };

const API = '/api/v1/internal-api-keys';

function formatDateTime(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function statusChip(key: ApiKey) {
  if (key.revokedAt) {
    return <span className="chip chip--fail">폐기됨</span>;
  }
  if (key.expiresAt && new Date(key.expiresAt) <= new Date()) {
    return <span className="chip">만료</span>;
  }
  return <span className="chip chip--success">활성</span>;
}

export function InternalApiKeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [creating, setCreating] = useState(false);
  const [draftName, setDraftName] = useState('');
  const [draftDesc, setDraftDesc] = useState('');
  const [draftExpires, setDraftExpires] = useState('');

  const [issued, setIssued] = useState<IssuedKey | null>(null);

  const loadKeys = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch(API);
      if (!res.ok) {
        setError('API 키를 불러오지 못했습니다.');
        return;
      }
      setKeys((await res.json()) as ApiKey[]);
    } catch {
      setError('API 키를 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadKeys();
  }, [loadKeys]);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (creating || !draftName.trim()) return;
    setCreating(true);
    try {
      const body: Record<string, unknown> = { name: draftName.trim() };
      if (draftDesc.trim()) body.description = draftDesc.trim();
      if (draftExpires) body.expiresAt = `${draftExpires}T23:59:59Z`;

      const res = await fetch(API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        setError('API 키 발급에 실패했습니다.');
        return;
      }
      const created = (await res.json()) as IssuedKey;
      setIssued(created);
      setShowForm(false);
      setDraftName('');
      setDraftDesc('');
      setDraftExpires('');
      await loadKeys();
    } catch {
      setError('API 키 발급에 실패했습니다.');
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(key: ApiKey) {
    if (!confirm(`이 키를 폐기하면 해당 키로 접속하는 Gateway는 즉시 401을 받습니다.\n진행하시겠습니까?\n\n이름: ${key.name}\nPrefix: ${key.keyPrefix}`)) {
      return;
    }
    try {
      const res = await fetch(`${API}/${key.id}/revoke`, { method: 'POST' });
      if (!res.ok) {
        setError('API 키 폐기에 실패했습니다.');
        return;
      }
      await loadKeys();
    } catch {
      setError('API 키 폐기에 실패했습니다.');
    }
  }

  async function handleCopyPlainKey() {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(issued.plainKey);
    } catch {
      /* 복사 실패 시 조용히 무시 — 사용자는 수동 복사 가능 */
    }
  }

  return (
    <div>
      <h2 className="page-title">Internal API 키</h2>
      <p className="page-subtitle">
        Admin↔Gateway 서비스 간 인증용 키입니다. 발급된 평문 키는 <strong>이 발급 직후에만</strong> 확인할 수 있습니다.
      </p>

      {error && <div className="alert" role="alert">{error}</div>}

      <div className="card">
        <div className="card__header">
          <h3 className="card__title">키 목록</h3>
          <button
            type="button"
            className="btn btn--primary"
            onClick={() => {
              if (showForm) {
                setDraftName('');
                setDraftDesc('');
                setDraftExpires('');
              }
              setShowForm((s) => !s);
            }}
          >
            {showForm ? '취소' : '+ 새 키'}
          </button>
        </div>

        {showForm && (
          <form onSubmit={handleCreate} className="inline-form" aria-label="새 API 키">
            <div className="filter-field">
              <label htmlFor="key-name">이름</label>
              <input
                id="key-name"
                type="text"
                value={draftName}
                onChange={(e) => setDraftName(e.target.value)}
                required
                disabled={creating}
              />
            </div>
            <div className="filter-field" style={{ flex: 1, minWidth: 200 }}>
              <label htmlFor="key-desc">설명</label>
              <input
                id="key-desc"
                type="text"
                value={draftDesc}
                onChange={(e) => setDraftDesc(e.target.value)}
                disabled={creating}
              />
            </div>
            <div className="filter-field">
              <label htmlFor="key-expires">만료일 (선택)</label>
              <input
                id="key-expires"
                type="date"
                value={draftExpires}
                onChange={(e) => setDraftExpires(e.target.value)}
                disabled={creating}
              />
            </div>
            <button type="submit" className="btn btn--primary" disabled={creating}>
              {creating ? '발급 중...' : '발급'}
            </button>
          </form>
        )}

        {loading ? (
          <p className="empty-message">불러오는 중...</p>
        ) : keys.length === 0 ? (
          <p className="empty-message">발급된 키가 없습니다.</p>
        ) : (
          <table aria-label="API 키 목록">
            <thead>
              <tr>
                <th>이름</th>
                <th>설명</th>
                <th>Prefix</th>
                <th>만료일</th>
                <th>마지막 사용</th>
                <th style={{ textAlign: 'center' }}>상태</th>
                <th style={{ textAlign: 'right' }}>액션</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id}>
                  <td>{key.name}</td>
                  <td style={{ color: 'var(--raon-text-sub)' }}>{key.description || '—'}</td>
                  <td style={{ fontFamily: 'monospace' }}>{key.keyPrefix}</td>
                  <td>{formatDate(key.expiresAt)}</td>
                  <td>{formatDateTime(key.lastUsedAt)}</td>
                  <td style={{ textAlign: 'center' }}>{statusChip(key)}</td>
                  <td style={{ textAlign: 'right' }}>
                    {!key.revokedAt && (
                      <button
                        type="button"
                        className="btn btn--sm btn--danger"
                        aria-label={`${key.name} 폐기`}
                        onClick={() => handleRevoke(key)}
                      >
                        폐기
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {issued && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="새 API 키 발급 결과"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
        >
          <div className="card" style={{ maxWidth: 560, margin: 0 }}>
            <div className="card__header">
              <h3 className="card__title">API 키 발급 완료</h3>
            </div>
            <p className="page-subtitle" style={{ color: 'var(--raon-danger, #b00020)' }}>
              ⚠️ 이 창을 닫으면 평문 키를 다시 볼 수 없습니다. 지금 복사해서 Gateway 환경변수에 저장하세요.
            </p>
            <pre
              style={{
                background: '#f5f5f5',
                padding: 12,
                borderRadius: 6,
                overflowX: 'auto',
                fontFamily: 'monospace',
              }}
            >
              {issued.plainKey}
            </pre>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 12 }}>
              <button type="button" className="btn btn--sm" onClick={handleCopyPlainKey}>
                복사
              </button>
              <button
                type="button"
                className="btn btn--sm btn--primary"
                onClick={() => setIssued(null)}
              >
                확인
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
