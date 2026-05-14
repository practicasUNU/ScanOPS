import { ENDPOINTS } from '../config/api';

interface UseCycleActionsReturn {
  pauseCycle: () => Promise<{ paused: boolean }>;
  activateKillSwitch: (totpCode: string) => Promise<{ kill_switch_active: boolean }>;
  deactivateKillSwitch: () => Promise<{ kill_switch_active: boolean }>;
}

async function postJson<T>(url: string, params?: Record<string, string>): Promise<T> {
  const fullUrl = params
    ? `${url}?${new URLSearchParams(params).toString()}`
    : url;
  const response = await fetch(fullUrl, { method: 'POST' });
  if (!response.ok) {
    let message: string;
    try {
      const body = await response.json();
      message = body?.detail ?? `Error ${response.status}`;
    } catch {
      message = `Error ${response.status}`;
    }
    throw new Error(message);
  }
  return response.json();
}

export function useCycleActions(): UseCycleActionsReturn {
  const pauseCycle = () =>
    postJson<{ paused: boolean }>(ENDPOINTS.pause);

  const activateKillSwitch = (totpCode: string) =>
    postJson<{ kill_switch_active: boolean }>(ENDPOINTS.killSwitch, { totp_code: totpCode });

  const deactivateKillSwitch = () =>
    postJson<{ kill_switch_active: boolean }>(ENDPOINTS.killSwitchDeactivate);

  return { pauseCycle, activateKillSwitch, deactivateKillSwitch };
}
