import { BrowserRouter, Routes, Route, Navigate } from 'react-router';
import { LoginPage } from './components/LoginPage';
import { DashboardPage } from './components/DashboardPage';
import { ScannerPage } from './components/ScannerPage';
import { ExploitationPage } from './components/ExploitationPage';
import { CompliancePage } from './components/CompliancePage';
import { AlertsPage } from './components/AlertsPage';
import { AuditLogsPage } from './components/AuditLogsPage';
import { ProtectedRoute } from './components/ProtectedRoute';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={
          <ProtectedRoute><DashboardPage /></ProtectedRoute>
        } />
        <Route path="/scanner" element={
          <ProtectedRoute><ScannerPage /></ProtectedRoute>
        } />
        <Route path="/exploitation" element={
          <ProtectedRoute requiredRole={['system_manager', 'security_officer']}>
            <ExploitationPage />
          </ProtectedRoute>
        } />
        <Route path="/compliance" element={
          <ProtectedRoute requiredRole={['system_manager', 'auditor']}>
            <CompliancePage />
          </ProtectedRoute>
        } />
        <Route path="/alerts" element={
          <ProtectedRoute><AlertsPage /></ProtectedRoute>
        } />
        <Route path="/audit-logs" element={
          <ProtectedRoute requiredRole={['system_manager', 'auditor']}>
            <AuditLogsPage />
          </ProtectedRoute>
        } />
      </Routes>
    </BrowserRouter>
  );
}
