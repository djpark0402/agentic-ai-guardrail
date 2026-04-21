import { useCallback, useEffect, useMemo, useState } from 'react';

type AuditLog = {
  id: number;
  occurredAt: string;
  actionId: 'GATEWAY' | 'ADMIN';
  action: string;
  success: boolean;
  detail?: string | null;
};

type AuditLogPage = {
  content: AuditLog[];
  totalElements: number;
  totalPages: number;
  page: number;
  size: number;
};

type SortField = 'occurredAt' | 'actionId' | 'action' | 'success';
type SortDir = 'asc' | 'desc';

const API = '/api/v1/audit-logs';
const PAGE_SIZE = 20;

const ACTION_OPTIONS = ['POLICY_REQUEST', 'POLICY_CREATE', 'POLICY_UPDATE', 'POLICY_DELETE', 'POLICY_ACTIVATE'];
const ACTOR_OPTIONS = ['GATEWAY', 'ADMIN'];

function useDebounced<T>(value: T, delay = 300) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

function toInstant(date: string, endOfDay = false): string {
  if (!date) return '';
  return endOfDay ? `${date}T23:59:59Z` : `${date}T00:00:00Z`;
}

function formatOccurredAt(iso: string): string {
  try {
    const d = new Date(iso);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ` +
      `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
  } catch {
    return iso;
  }
}

export function AuditLogPage() {
  const [actionId, setActionId] = useState('');
  const [action, setAction] = useState('');
  const [success, setSuccess] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');

  const [sortField, setSortField] = useState<SortField>('occurredAt');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [pageIndex, setPageIndex] = useState(0);

  const [data, setData] = useState<AuditLogPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  const filters = useMemo(
    () => ({ actionId, action, success, from, to }),
    [actionId, action, success, from, to],
  );
  const debouncedFilters = useDebounced(filters, 300);

  useEffect(() => {
    setPageIndex(0);
  }, [debouncedFilters]);

  const fetchLogs = useCallback(async () => {
    setError(null);
    const params = new URLSearchParams();
    params.set('page', String(pageIndex));
    params.set('size', String(PAGE_SIZE));
    params.set('sort', sortField);
    params.set('direction', sortDir);
    if (debouncedFilters.actionId) params.set('actionId', debouncedFilters.actionId);
    if (debouncedFilters.action) params.set('action', debouncedFilters.action);
    if (debouncedFilters.success) params.set('success', debouncedFilters.success);
    if (debouncedFilters.from) params.set('from', toInstant(debouncedFilters.from, false));
    if (debouncedFilters.to) params.set('to', toInstant(debouncedFilters.to, true));

    try {
      const res = await fetch(`${API}?${params.toString()}`);
      if (!res.ok) {
        setError('감사 로그를 불러오는 중 오류가 발생했습니다.');
        setLoaded(true);
        return;
      }
      const json = (await res.json()) as AuditLogPage;
      setData(json);
      setLoaded(true);
    } catch {
      setError('감사 로그를 불러오는 중 오류가 발생했습니다.');
      setLoaded(true);
    }
  }, [pageIndex, sortField, sortDir, debouncedFilters]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  }

  function sortIndicator(field: SortField) {
    if (sortField !== field) return null;
    return <span className="sort-indicator">{sortDir === 'asc' ? '▲' : '▼'}</span>;
  }

  const actorChipClass = (a: AuditLog['actionId']) =>
    a === 'GATEWAY' ? 'chip chip--gateway' : 'chip chip--admin';

  const total = data?.totalElements ?? 0;
  const totalPages = data?.totalPages ?? 0;
  const rows = data?.content ?? [];

  return (
    <div>
      <h2 className="page-title">감사 로그</h2>
      <p className="page-subtitle">
        필터를 변경하면 자동으로 검색됩니다. 컬럼 헤더를 클릭하면 정렬됩니다.
      </p>

      <div className="filter-bar" role="search">
        <div className="filter-field">
          <label htmlFor="filter-actor">호출자</label>
          <select id="filter-actor" value={actionId} onChange={(e) => setActionId(e.target.value)}>
            <option value="">전체</option>
            {ACTOR_OPTIONS.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </div>
        <div className="filter-field">
          <label htmlFor="filter-action">액션</label>
          <select id="filter-action" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">전체</option>
            {ACTION_OPTIONS.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </div>
        <div className="filter-field">
          <label htmlFor="filter-success">결과</label>
          <select id="filter-success" value={success} onChange={(e) => setSuccess(e.target.value)}>
            <option value="">전체</option>
            <option value="true">성공</option>
            <option value="false">실패</option>
          </select>
        </div>
        <div className="filter-field">
          <label htmlFor="filter-from">시작일</label>
          <input id="filter-from" type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
        </div>
        <div className="filter-field">
          <label htmlFor="filter-to">종료일</label>
          <input id="filter-to" type="date" value={to} onChange={(e) => setTo(e.target.value)} />
        </div>
      </div>

      {error && <div className="alert" role="alert">{error}</div>}

      <div className="card">
        <div className="card__header">
          <h3 className="card__title">결과 <span style={{ color: 'var(--raon-text-sub)', fontWeight: 500 }}>({total}건)</span></h3>
        </div>

        {!error && loaded && rows.length === 0 && (
          <p className="empty-message">조회된 로그가 없습니다.</p>
        )}

        {!error && rows.length > 0 && (
          <>
            <table aria-label="감사 로그 목록">
              <thead>
                <tr>
                  <th className="sortable" onClick={() => toggleSort('occurredAt')}>
                    발생시간{sortIndicator('occurredAt')}
                  </th>
                  <th className="sortable" onClick={() => toggleSort('actionId')}>
                    호출자{sortIndicator('actionId')}
                  </th>
                  <th className="sortable" onClick={() => toggleSort('action')}>
                    액션{sortIndicator('action')}
                  </th>
                  <th className="sortable" onClick={() => toggleSort('success')} style={{ textAlign: 'center' }}>
                    결과{sortIndicator('success')}
                  </th>
                  <th>상세</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((log) => (
                  <tr key={log.id}>
                    <td>{formatOccurredAt(log.occurredAt)}</td>
                    <td>
                      <span className={actorChipClass(log.actionId)}>{log.actionId}</span>
                    </td>
                    <td>{log.action}</td>
                    <td style={{ textAlign: 'center' }}>
                      <span className={`chip ${log.success ? 'chip--success' : 'chip--fail'}`}>
                        {log.success ? '성공' : '실패'}
                      </span>
                    </td>
                    <td style={{ color: 'var(--raon-text-sub)' }}>{log.detail ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {totalPages > 1 && (
              <div className="pagination">
                <button
                  type="button"
                  className="btn btn--sm"
                  disabled={pageIndex === 0}
                  onClick={() => setPageIndex((p) => Math.max(0, p - 1))}
                >
                  이전
                </button>
                <span>
                  {pageIndex + 1} / {totalPages}
                </span>
                <button
                  type="button"
                  className="btn btn--sm"
                  disabled={pageIndex + 1 >= totalPages}
                  onClick={() => setPageIndex((p) => p + 1)}
                >
                  다음
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
