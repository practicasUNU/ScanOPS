import { useState, useEffect, useCallback } from 'react';
import { ENDPOINTS } from '../config/api';
import { getStoredToken } from './useAuth';

export interface ModuleStatus {
  id: string;
  name: string;
  port: number;
  status: 'completed' | 'in_progress' | 'pending' | 'blocked' | 'offline';
}

export interface PhaseInfo {
  phase_number: number;
  name: string;
  scheduled_day: string;
  scheduled_time: string;
  status: 'completed' | 'in_progress' | 'pending';
  modules: ModuleStatus[];
}

export interface CycleStatus {
  week_number: number;
  year: number;
  week_label: string;
  current_phase: number;
  current_phase_name: string;
  cycle_active: boolean;
  requires_human_approval: boolean;
  kill_switch_active: boolean;
  paused: boolean;
  phases: PhaseInfo[];
  next_phase_at: string | null;
  last_updated: string;
}

interface UseCycleStatusReturn {
  data: CycleStatus | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export function useCycleStatus(pollIntervalMs: number = 30000): UseCycleStatusReturn {
  const [data, setData] = useState<CycleStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const token = getStoredToken();
      const response = await fetch(ENDPOINTS.cycleStatus, {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        setError(`Error ${response.status}`);
        return;
      }
      const json: CycleStatus = await response.json();
      setData(json);
      setError(null);
    } catch {
      setError('Orchestrator no disponible');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, pollIntervalMs);
    return () => clearInterval(interval);
  }, [fetchStatus, pollIntervalMs]);

  return { data, loading, error, refetch: fetchStatus };
}
