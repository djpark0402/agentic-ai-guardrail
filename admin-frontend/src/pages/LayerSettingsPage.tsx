import { FormEvent, useCallback, useEffect, useState } from 'react';

const LAYER_KEYS = ['l1Enabled', 'l2Enabled', 'l3Enabled', 'l4Enabled', 'l5Enabled', 'l6Enabled', 'outboundEnabled'] as const;
type LayerKey = (typeof LAYER_KEYS)[number];

type Policy = {
  id: number;
  name: string;
  description: string | null;
  l1Enabled: boolean;
  l2Enabled: boolean;
  l3Enabled: boolean;
  l4Enabled: boolean;
  l5Enabled: boolean;
  l6Enabled: boolean;
  outboundEnabled: boolean;
  isUse: boolean;
  createdAt: string;
  updatedAt: string;
};

type Draft = {
  name: string;
  description: string;
  l1Enabled: boolean;
  l2Enabled: boolean;
  l3Enabled: boolean;
  l4Enabled: boolean;
  l5Enabled: boolean;
  l6Enabled: boolean;
  outboundEnabled: boolean;
};

const EMPTY_DRAFT: Draft = {
  name: '',
  description: '',
  l1Enabled: true,
  l2Enabled: true,
  l3Enabled: true,
  l4Enabled: true,
  l5Enabled: true,
  l6Enabled: true,
  outboundEnabled: false,
};

const API = '/api/v1/policies';

function layerLabel(key: LayerKey): string {
  if (key === 'outboundEnabled') return 'OUT';
  return key.slice(0, 2).toUpperCase();
}

export function LayerSettingsPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [showForm, setShowForm] = useState(false);
  const [newDraft, setNewDraft] = useState<Draft>(EMPTY_DRAFT);
  const [creating, setCreating] = useState(false);

  const [editingId, setEditingId] = useState<number | null>(null);
  const [editDraft, setEditDraft] = useState<Draft | null>(null);
  const [saving, setSaving] = useState(false);

  const loadPolicies = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch(API);
      if (!res.ok) {
        setError('정책을 불러오지 못했습니다.');
        return;
      }
      const data = (await res.json()) as Policy[];
      setPolicies(data);
    } catch {
      setError('정책을 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  function startEdit(policy: Policy) {
    setEditingId(policy.id);
    setEditDraft({
      name: policy.name,
      description: policy.description ?? '',
      l1Enabled: policy.l1Enabled,
      l2Enabled: policy.l2Enabled,
      l3Enabled: policy.l3Enabled,
      l4Enabled: policy.l4Enabled,
      l5Enabled: policy.l5Enabled,
      l6Enabled: policy.l6Enabled,
      outboundEnabled: policy.outboundEnabled,
    });
  }

  function cancelEdit() {
    setEditingId(null);
    setEditDraft(null);
  }

  async function saveEdit(policy: Policy) {
    if (saving || !editDraft) return;
    if (!editDraft.name.trim()) {
      setError('정책명을 입력하세요.');
      return;
    }
    setSaving(true);
    try {
      const res = await fetch(`${API}/${policy.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: editDraft.name.trim(),
          description: editDraft.description,
          l1Enabled: editDraft.l1Enabled,
          l2Enabled: editDraft.l2Enabled,
          l3Enabled: editDraft.l3Enabled,
          l4Enabled: editDraft.l4Enabled,
          l5Enabled: editDraft.l5Enabled,
          l6Enabled: editDraft.l6Enabled,
          outboundEnabled: editDraft.outboundEnabled,
        }),
      });
      if (!res.ok) {
        setError('정책 저장에 실패했습니다.');
        return;
      }
      setEditingId(null);
      setEditDraft(null);
      await loadPolicies();
    } catch {
      setError('정책 저장에 실패했습니다.');
    } finally {
      setSaving(false);
    }
  }

  async function activatePolicy(policy: Policy) {
    try {
      const res = await fetch(`${API}/${policy.id}/activate`, { method: 'POST' });
      if (!res.ok) {
        setError('정책 활성화에 실패했습니다.');
        return;
      }
      await loadPolicies();
    } catch {
      setError('정책 활성화에 실패했습니다.');
    }
  }

  async function deletePolicy(policy: Policy) {
    if (!confirm(`정책 "${policy.name}"을 삭제하시겠습니까?`)) return;
    try {
      const res = await fetch(`${API}/${policy.id}`, { method: 'DELETE' });
      if (!res.ok) {
        setError('정책 삭제에 실패했습니다.');
        return;
      }
      setPolicies((prev) => prev.filter((p) => p.id !== policy.id));
    } catch {
      setError('정책 삭제에 실패했습니다.');
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (creating) return;
    if (!newDraft.name.trim()) return;
    setCreating(true);
    try {
      const res = await fetch(API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newDraft.name.trim(),
          description: newDraft.description,
          l1Enabled: newDraft.l1Enabled,
          l2Enabled: newDraft.l2Enabled,
          l3Enabled: newDraft.l3Enabled,
          l4Enabled: newDraft.l4Enabled,
          l5Enabled: newDraft.l5Enabled,
          l6Enabled: newDraft.l6Enabled,
          outboundEnabled: newDraft.outboundEnabled,
        }),
      });
      if (!res.ok) {
        setError('정책 생성에 실패했습니다.');
        return;
      }
      setShowForm(false);
      setNewDraft(EMPTY_DRAFT);
      await loadPolicies();
    } catch {
      setError('정책 생성에 실패했습니다.');
    } finally {
      setCreating(false);
    }
  }

  function renderSwitch(checked: boolean, onChange: (() => void) | null, label: string) {
    return (
      <button
        type="button"
        className="switch"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        aria-disabled={!onChange}
        disabled={!onChange}
        onClick={onChange ?? undefined}
      />
    );
  }

  return (
    <div>
      <h2 className="page-title">정책 설정</h2>
      <p className="page-subtitle">
        정책별 L1~L6 레이어를 설정합니다. 현재 활성(●) 표시된 정책 한 개만 게이트웨이에 적용됩니다.
      </p>

      {error && <div className="alert" role="alert">{error}</div>}

      <div className="card">
        <div className="card__header">
          <h3 className="card__title">정책 목록</h3>
          <button
            type="button"
            className="btn btn--primary"
            onClick={() => {
              setShowForm((s) => !s);
              setNewDraft(EMPTY_DRAFT);
            }}
          >
            {showForm ? '취소' : '+ 새 정책'}
          </button>
        </div>

        {showForm && (
          <form onSubmit={handleCreate} className="inline-form" aria-label="새 정책">
            <div className="filter-field">
              <label htmlFor="new-name">정책명</label>
              <input
                id="new-name"
                type="text"
                value={newDraft.name}
                onChange={(e) => setNewDraft({ ...newDraft, name: e.target.value })}
                required
                disabled={creating}
              />
            </div>
            <div className="filter-field" style={{ flex: 1, minWidth: 200 }}>
              <label htmlFor="new-desc">설명</label>
              <input
                id="new-desc"
                type="text"
                value={newDraft.description}
                onChange={(e) => setNewDraft({ ...newDraft, description: e.target.value })}
                disabled={creating}
              />
            </div>
            <div className="filter-field">
              <label>레이어</label>
              <div style={{ display: 'flex', gap: 14 }}>
                {LAYER_KEYS.map((k) => (
                  <div key={k} className="layer-toggle">
                    <span className="layer-toggle__label">{layerLabel(k)}</span>
                    {renderSwitch(
                      newDraft[k],
                      creating ? null : () => setNewDraft({ ...newDraft, [k]: !newDraft[k] }),
                      `새 정책 ${k}`,
                    )}
                  </div>
                ))}
              </div>
            </div>
            <button type="submit" className="btn btn--primary" disabled={creating}>
              {creating ? '저장 중...' : '저장'}
            </button>
          </form>
        )}

        {loading ? (
          <p className="empty-message">불러오는 중...</p>
        ) : policies.length === 0 ? (
          <p className="empty-message">등록된 정책이 없습니다. 새 정책을 추가해보세요.</p>
        ) : (
          <table aria-label="정책 목록">
            <thead>
              <tr>
                <th>이름</th>
                <th>설명</th>
                {LAYER_KEYS.map((k) => (
                  <th key={k} style={{ textAlign: 'center' }}>{layerLabel(k)}</th>
                ))}
                <th style={{ textAlign: 'center' }}>상태</th>
                <th style={{ textAlign: 'right' }}>액션</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => {
                const isEditing = editingId === policy.id && editDraft !== null;
                const draft = isEditing ? editDraft! : null;
                return (
                  <tr key={policy.id} className={policy.isUse ? 'row-active' : undefined}>
                    <td>
                      {isEditing ? (
                        <input
                          type="text"
                          value={draft!.name}
                          onChange={(e) => setEditDraft({ ...draft!, name: e.target.value })}
                          disabled={saving}
                          style={{ width: 140 }}
                          aria-label={`${policy.name} 이름 수정`}
                        />
                      ) : (
                        policy.name
                      )}
                    </td>
                    <td style={{ color: 'var(--raon-text-sub)' }}>
                      {isEditing ? (
                        <input
                          type="text"
                          value={draft!.description}
                          onChange={(e) => setEditDraft({ ...draft!, description: e.target.value })}
                          disabled={saving}
                          style={{ width: '100%', minWidth: 120 }}
                          aria-label={`${policy.name} 설명 수정`}
                        />
                      ) : (
                        policy.description || '—'
                      )}
                    </td>
                    {LAYER_KEYS.map((k) => (
                      <td key={k} style={{ textAlign: 'center' }}>
                        {renderSwitch(
                          isEditing ? draft![k] : policy[k],
                          isEditing && !saving
                            ? () => setEditDraft({ ...draft!, [k]: !draft![k] })
                            : null,
                          `${policy.name} ${k}`,
                        )}
                      </td>
                    ))}
                    <td style={{ textAlign: 'center' }}>
                      {policy.isUse ? (
                        <span className="chip chip--active">활성</span>
                      ) : (
                        <span style={{ color: 'var(--raon-text-sub)' }}>비활성</span>
                      )}
                    </td>
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      {isEditing ? (
                        <>
                          <button
                            type="button"
                            className="btn btn--sm btn--primary"
                            onClick={() => saveEdit(policy)}
                            disabled={saving}
                            style={{ marginRight: 4 }}
                          >
                            {saving ? '저장 중...' : '저장'}
                          </button>
                          <button
                            type="button"
                            className="btn btn--sm"
                            onClick={cancelEdit}
                            disabled={saving}
                          >
                            취소
                          </button>
                        </>
                      ) : (
                        <>
                          {!policy.isUse && (
                            <button
                              type="button"
                              className="btn btn--sm btn--primary"
                              onClick={() => activatePolicy(policy)}
                              style={{ marginRight: 4 }}
                            >
                              활성화
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn btn--sm"
                            onClick={() => startEdit(policy)}
                            style={{ marginRight: 4 }}
                          >
                            수정
                          </button>
                          <button
                            type="button"
                            className="btn btn--sm btn--danger"
                            onClick={() => deletePolicy(policy)}
                          >
                            삭제
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
