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
import { RouteErrorBoundary } from './components/RouteErrorBoundary';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore – JSX module without type declarations
import { UnifiedScannerLayout } from '../pages/UnifiedScanner/UnifiedScannerLayout';
import BastionadoPage from '../pages/BastionadoPage';
import { EDRDashboardPage } from './components/EDRDashboardPage';
import { IncidentResponsePage } from './components/IncidentResponsePage';

function AppInner() {
  const { toastQueue, dismissToast } = useCriticalAlerts();
  return (
    <>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <RouteErrorBoundary label="Dashboard">
              <DashboardPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/scanner" element={<Navigate to="/surface" replace />} />
        <Route path="/exploitation" element={
          <ProtectedRoute requiredRole={['system_manager', 'security_officer']}>
            <RouteErrorBoundary label="M4 Explotación">
              <ExploitationPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/compliance" element={
          <ProtectedRoute requiredRole={['system_manager', 'auditor']}>
            <RouteErrorBoundary label="Cumplimiento ENS">
              <CompliancePage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/audit-logs" element={
          <ProtectedRoute requiredRole={['system_manager', 'auditor']}>
            <RouteErrorBoundary label="Logs Auditoría">
              <AuditLogsPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/settings" element={
          <ProtectedRoute requiredRole={['system_manager', 'security_officer']}>
            <RouteErrorBoundary label="Configuración">
              <SettingsPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/surface" element={
          <ProtectedRoute>
            <RouteErrorBoundary label="M2/M3 Scanner">
              <UnifiedScannerLayout />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/assets/:id" element={
          <ProtectedRoute requiredRole={['system_manager', 'auditor']}>
            <RouteErrorBoundary label="M1 Asset Detail">
              <AssetDetailPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/assets" element={
          <ProtectedRoute>
            <RouteErrorBoundary label="M1 Asset Manager">
              <AssetManagerPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/ai-reasoning" element={
          <ProtectedRoute>
            <RouteErrorBoundary label="M8 IA Reasoning">
              <AIReasoningPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/reporting" element={
          <ProtectedRoute requiredRole={['system_manager', 'auditor']}>
            <RouteErrorBoundary label="M7 Reportes">
              <ReportingPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/alerts" element={
          <ProtectedRoute requiredRole={['system_manager', 'security_officer']}>
            <RouteErrorBoundary label="M5 SIEM">
              <AlertsPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/bastionado" element={
          <ProtectedRoute requiredRole={['system_manager', 'security_officer']}>
            <RouteErrorBoundary label="Bastionado">
              <BastionadoPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/edr" element={
          <ProtectedRoute requiredRole={['system_manager', 'security_officer']}>
            <RouteErrorBoundary label="M3 EDR">
              <EDRDashboardPage />
            </RouteErrorBoundary>
          </ProtectedRoute>
        } />
        <Route path="/incident-response" element={
          <ProtectedRoute requiredRole={['system_manager', 'security_officer']}>
            <RouteErrorBoundary label="Incident Response">
              <IncidentResponsePage />
            </RouteErrorBoundary>
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
