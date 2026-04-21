import { Routes, Route, Navigate, NavLink } from 'react-router-dom';
import { LayerSettingsPage } from '@/pages/LayerSettingsPage';
import { AuditLogPage } from '@/pages/AuditLogPage';
import { InternalApiKeysPage } from '@/pages/InternalApiKeysPage';
import { AgentApiKeysPage } from '@/pages/AgentApiKeysPage';

export function App() {
  return (
    <div className="app-shell">
      <header className="app-header">
        <h1 className="app-header__title">
          <span className="app-header__title-mark">라온</span> 가드레일 Admin
        </h1>
      </header>
      <aside className="app-sidebar" aria-label="주 메뉴">
        <NavLink
          to="/admin/layers"
          className={({ isActive }) => `app-sidebar__item${isActive ? ' active' : ''}`}
        >
          Layer 설정
        </NavLink>
        <NavLink
          to="/admin/audit-logs"
          className={({ isActive }) => `app-sidebar__item${isActive ? ' active' : ''}`}
        >
          감사 로그
        </NavLink>
        <NavLink
          to="/admin/internal-api-keys"
          className={({ isActive }) => `app-sidebar__item${isActive ? ' active' : ''}`}
        >
          Internal API 키
        </NavLink>
        <NavLink
          to="/admin/agent-api-keys"
          className={({ isActive }) => `app-sidebar__item${isActive ? ' active' : ''}`}
        >
          Agent API 키
        </NavLink>
      </aside>
      <main className="app-main">
        <Routes>
          <Route path="/" element={<Navigate to="/admin/layers" replace />} />
          <Route path="/admin/layers" element={<LayerSettingsPage />} />
          <Route path="/admin/audit-logs" element={<AuditLogPage />} />
          <Route path="/admin/internal-api-keys" element={<InternalApiKeysPage />} />
          <Route path="/admin/agent-api-keys" element={<AgentApiKeysPage />} />
        </Routes>
      </main>
    </div>
  );
}
