import { useState, useEffect, useCallback } from 'react';
import { ENDPOINTS } from '../config/api';
import { getStoredToken } from './useAuth';

export interface DashboardMetrics {
  total_assets: number;
  open_vulnerabilities: number;
  ens_compliance_score: number;
  m1_available: boolean;
  m3_available: boolean;
  timestamp: string;
}

export function useDashboardMetrics(pollIntervalMs = 60000) {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = useCallback(async () => {
    try {
      const token = getStoredToken();
      const res = await fetch(ENDPOINTS.dashboardMetrics, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error(`Error ${res.status}`);
      const data = await res.json();
      setMetrics(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Metrics unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, pollIntervalMs);
    return () => clearInterval(interval);
  }, [fetchMetrics, pollIntervalMs]);

  return { metrics, loading, error, refetch: fetchMetrics };
}
