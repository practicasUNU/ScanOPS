import { BrowserRouter, Routes, Route, Navigate } from 'react-router';
import { CriticalToast } from './components/CriticalToast';
import { useCriticalAlerts } from '../hooks/useCriticalAlerts';
import { LoginPage } from './components/LoginPage';
import { DashboardPage } from './components/DashboardPage';
import { ExploitationPage } from './components/ExploitationPage';
import { CompliancePage } from './components/CompliancePage';
import { AuditLogsPage } from './components/AuditLogsPage';
import { ProtectedRoute } from './components/ProtectedRoute';
import { AssetManagerPage } from './components/AssetManagerPage';
import { AssetDetailPage } from './components/AssetDetailPage';
import { AIReasoningPage } from './components/AIReasoningPage';
import { ReportingPage } from './components/ReportingPage';
import { SettingsPage } from './components/SettingsPage';
import { AlertsPage } from './components/AlertsPage';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore – JSX module without type declarations
import { UnifiedScannerLayout } from '../pages/UnifiedScanner/UnifiedScannerLayout';

function AppInner() {
  const { toastQueue, dismissToast } = useCriticalAlerts();
  return (
    <>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={
          <ProtectedRoute><DashboardPage /></ProtectedRoute>
        } />
        <Route path="/scanner" element={<Navigate to="/surface" replace />} />
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
        <Route path="/audit-logs" element={
          <ProtectedRoute requiredRole={['system_manager', 'auditor']}>
            <AuditLogsPage />
          </ProtectedRoute>
        } />
        <Route path="/settings" element={
          <ProtectedRoute requiredRole={['system_manager', 'security_officer']}>
            <SettingsPage />
          </ProtectedRoute>
        } />
        <Route path="/surface" element={
          <ProtectedRoute><UnifiedScannerLayout /></ProtectedRoute>
        } />
        <Route path="/assets/:id" element={
          <ProtectedRoute requiredRole={['system_manager', 'auditor']}>
            <AssetDetailPage />
          </ProtectedRoute>
        } />
        <Route path="/assets" element={
          <ProtectedRoute><AssetManagerPage /></ProtectedRoute>
        } />
        <Route path="/ai-reasoning" element={
          <ProtectedRoute><AIReasoningPage /></ProtectedRoute>
        } />
        <Route path="/reporting" element={
          <ProtectedRoute requiredRole={['system_manager', 'auditor']}>
            <ReportingPage />
          </ProtectedRoute>
        } />
        <Route path="/alerts" element={
          <ProtectedRoute requiredRole={['system_manager', 'security_officer']}>
            <AlertsPage />
          </ProtectedRoute>
        } />
      </Routes>
      <CriticalToast toasts={toastQueue} onDismiss={dismissToast} />
    </>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppInner />
    </BrowserRouter>
  );
}
