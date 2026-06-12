export const API_BASE = '/api/orchestrator';
export const M1_BASE = '/api/m1/api/v1';
export const M3_BASE = '/api/m3';

export const ENDPOINTS = {
  cycleStatus: `${API_BASE}/orchestrator/cycle/status`,
  modulesHealth: `${API_BASE}/orchestrator/modules/health`,
  pause: `${API_BASE}/orchestrator/cycle/pause`,
  killSwitch: `${API_BASE}/orchestrator/cycle/kill-switch`,
  killSwitchDeactivate: `${API_BASE}/orchestrator/cycle/kill-switch/deactivate`,
  pendingApprovals: '/api/m4/api/m4/pending-approvals',
  authToken: `${API_BASE}/auth/token`,
  authRefresh: `${API_BASE}/auth/refresh`,
  authMe: `${API_BASE}/auth/me`,
  dashboardMetrics: `${API_BASE}/orchestrator/dashboard/metrics`,
};
