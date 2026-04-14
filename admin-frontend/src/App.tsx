import { Routes, Route, Navigate, Link } from 'react-router-dom';
import { LoginPage } from '@/pages/LoginPage';
import { PoliciesPage } from '@/pages/PoliciesPage';
import { AuditLogPage } from '@/pages/AuditLogPage';

if (!localStorage.getItem('admin_token')) {
  localStorage.setItem('admin_token', 'dev-bypass-token');
}

export function App() {
  return (
    <>
      <div className="sakura-petals" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
        <span />
        <span />
        <span />
      </div>
      <nav className="sakura-nav">
        <span aria-hidden="true">🌸</span>
        <Link to="/admin/policies">Policies</Link>
        <Link to="/admin/audit-logs">Audit Logs</Link>
      </nav>
      <Routes>
        <Route path="/" element={<Navigate to="/admin/policies" replace />} />
        <Route path="/admin/login" element={<LoginPage />} />
        <Route path="/admin/policies" element={<PoliciesPage />} />
        <Route path="/admin/audit-logs" element={<AuditLogPage />} />
      </Routes>
    </>
  );
}
