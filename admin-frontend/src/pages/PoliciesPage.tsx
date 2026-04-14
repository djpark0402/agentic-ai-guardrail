import { FormEvent, useEffect, useState } from 'react';

type Policy = {
  id: string;
  name: string;
  enabled: boolean;
  action: string;
};

function authHeaders(): HeadersInit {
  const token = localStorage.getItem('admin_token') ?? '';
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
  };
}

export function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [newName, setNewName] = useState('');

  async function loadPolicies() {
    try {
      const res = await fetch('/api/admin/policies', {
        method: 'GET',
        headers: authHeaders(),
      });
      if (!res.ok) {
        setError('정책을 불러오지 못했습니다.');
        return;
      }
      const data = await res.json();
      setPolicies(data);
    } catch {
      setError('정책을 불러오지 못했습니다.');
    }
  }

  useEffect(() => {
    loadPolicies();
  }, []);

  async function togglePolicy(policy: Policy) {
    await fetch(`/api/admin/policies/${policy.id}`, {
      method: 'PATCH',
      headers: authHeaders(),
      body: JSON.stringify({ enabled: !policy.enabled }),
    });
    setPolicies((prev) =>
      prev.map((p) => (p.id === policy.id ? { ...p, enabled: !p.enabled } : p)),
    );
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    const res = await fetch('/api/admin/policies', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ name: newName, enabled: true, action: 'block' }),
    });
    if (res.ok) {
      const created: Policy = await res.json();
      setPolicies((prev) => [...prev, created]);
    }
    setShowForm(false);
    setNewName('');
  }

  return (
    <div className="sakura-page">
      <h1>정책 관리</h1>
      {error && <p role="alert">{error}</p>}
      <button type="button" onClick={() => setShowForm(true)}>
        추가
      </button>
      {showForm && (
        <form onSubmit={handleCreate}>
          <label htmlFor="policy-name">정책명</label>
          <input
            id="policy-name"
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
          />
          <button type="submit">저장</button>
        </form>
      )}
      <ul>
        {policies.map((policy) => (
          <li key={policy.id}>
            <span>{policy.name}</span>
            <button
              type="button"
              role="switch"
              aria-checked={policy.enabled}
              aria-label={policy.name}
              onClick={() => togglePolicy(policy)}
            >
              {policy.enabled ? 'ON' : 'OFF'}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
