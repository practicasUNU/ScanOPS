import { BrowserRouter, Routes, Route, Navigate } from 'react-router';
import { LoginPage } from './components/LoginPage';
import { DashboardPage } from './components/DashboardPage';
import { ScannerPage } from './components/ScannerPage';
import { ExploitationPage } from './components/ExploitationPage';
import { CompliancePage } from './components/CompliancePage';
import { AlertsPage } from './components/AlertsPage';
import { AuditLogsPage } from './components/AuditLogsPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/scanner" element={<ScannerPage />} />
        <Route path="/exploitation" element={<ExploitationPage />} />
        <Route path="/compliance" element={<CompliancePage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/audit-logs" element={<AuditLogsPage />} />
      </Routes>
    </BrowserRouter>
  );
}
