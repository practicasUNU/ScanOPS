export const API_BASE = 'http://localhost:8009';

export const ENDPOINTS = {
  cycleStatus: `${API_BASE}/orchestrator/cycle/status`,
  modulesHealth: `${API_BASE}/orchestrator/modules/health`,
  pause: `${API_BASE}/orchestrator/cycle/pause`,
  killSwitch: `${API_BASE}/orchestrator/cycle/kill-switch`,
  killSwitchDeactivate: `${API_BASE}/orchestrator/cycle/kill-switch/deactivate`,
};
