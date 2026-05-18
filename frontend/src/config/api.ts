export const API_BASE = 'http://localhost:8009';
export const M1_BASE = 'http://localhost:8001/api/v1';
export const M3_BASE = 'http://localhost:8002';

export const ENDPOINTS = {
  cycleStatus: `${API_BASE}/orchestrator/cycle/status`,
  modulesHealth: `${API_BASE}/orchestrator/modules/health`,
  pause: `${API_BASE}/orchestrator/cycle/pause`,
  killSwitch: `${API_BASE}/orchestrator/cycle/kill-switch`,
  killSwitchDeactivate: `${API_BASE}/orchestrator/cycle/kill-switch/deactivate`,
  pendingApprovals: 'http://localhost:8004/api/m4/pending-approvals',
  authToken: `${API_BASE}/auth/token`,
  authRefresh: `${API_BASE}/auth/refresh`,
  authMe: `${API_BASE}/auth/me`,
  d