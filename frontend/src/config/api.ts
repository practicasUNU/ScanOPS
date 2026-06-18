// Centralized API endpoint registry — all module base URLs in one place.
// Import from here instead of hardcoding strings in components/hooks.

export const API_BASE   = '/api/orchestrator';
export const M1_BASE    = '/api/m1/api/v1';
export const M2_BASE    = '/api/m2/api/v1';
export const M3_BASE    = '/api/m3';
export const M3_API     = '/api/m3/api/v1';
export const M4_BASE    = '/api/m4/api/m4';
export const M5_BASE    = '/api/m5';
export const M7_BASE    = '/api/m7';
export const M8_BASE    = '/api/m8';

export const ENDPOINTS = {
  // Orchestrator / cycle
  cycleStatus:          `${API_BASE}/orchestrator/cycle/status`,
  modulesHealth:        `${API_BASE}/orchestrator/modules/health`,
  pause:                `${API_BASE}/orchestrator/cycle/pause`,
  killSwitch:           `${API_BASE}/orchestrator/cycle/kill-switch`,
  killSwitchDeactivate: `${API_BASE}/orchestrator/cycle/kill-switch/deactivate`,
  dashboardMetrics:     `${API_BASE}/orchestrator/dashboard/metrics`,
  logStream:            `${API_BASE}/orchestrator/logs/stream`,
  config:               `${API_BASE}/orchestrator/config`,

  // Auth
  authToken:   `${API_BASE}/auth/token`,
  authRefresh: `${API_BASE}/auth/refresh`,
  authMe:      `${API_BASE}/auth/me`,

  // Users
  activeSessions: `${API_BASE}/users/active-sessions`,
  loginHistory:   `${API_BASE}/auth/login-events`,

  // M1 Asset Manager
  assets:       `${M1_BASE}/assets`,
  assetById:    (id: number | string) => `${M1_BASE}/assets/${id}`,
  assetAudit:   (id: number | string) => `${M1_BASE}/assets/${id}/audit`,

  // M2 Recon
  m2Scan:       `${M2_BASE}/scan`,

  // M3 Scanner
  m3ScanAsset:  (id: number | string) => `${M3_API}/scan/asset/${id}`,
  m3Results:    (id: number | string) => `${M3_API}/scan/results/${id}`,
  m3Stream:     `${M3_BASE}/stream/findings`,
  edrFindings:  `${M3_API}/edr/behavioral-findings`,

  // M4 Exploit
  pendingApprovals:  `${M4_BASE}/pending-approvals`,
  requestApproval:   `${M4_BASE}/request-approval`,
  approve:           `${M4_BASE}/approve`,
  executeApproval:   (id: number | string) => `${M4_BASE}/execute/${id}`,

  // M5 SIEM
  pipelineEvents: `${M5_BASE}/siem/pipeline-events`,
  authEvents:     `${M5_BASE}/siem/auth-events`,
  siemKpis:       `${M5_BASE}/siem/kpis`,
  honeypotEvents: `${M5_BASE}/honeypot/events`,
  honeypotStatus: `${M5_BASE}/honeypot/status`,

  // M7 Reporting
  reportExecutive: `${M7_BASE}/report/executive`,
  reportTechnical: `${M7_BASE}/report/technical`,
  reportSoa:       `${M7_BASE}/report/soa`,
  reportFullAudit: `${M7_BASE}/report/full-audit`,
  reportHistory:   `${M7_BASE}/report/history`,
  reportAsset:     (id: number | string) => `${M7_BASE}/report/asset/${id}`,

  // M8 AI Reasoning
  aiAnalysis:  `${M8_BASE}/api/v1/analyze`,
  aiResults:   `${M8_BASE}/api/v1/results`,
};
