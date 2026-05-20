import { useState, useEffect, useCallback } from 'react';

const SCAN_API_URL = 'http://localhost:8002/api/v1/scan/results/10';
const TOKEN_KEY = 'scanops_auth';

/** Reads the stored JWT from sessionStorage (ENS mp.info.3). */
function getToken() {
  try {
    const raw = sessionStorage.getItem(TOKEN_KEY);
    if (!raw) return null;
    return JSON.parse(raw)?.access_token ?? null;
  } catch {
    return null;
  }
}

/**
 * Fetches the unified scan report from M3.
 * Returns { data, loading, error, refetch }.
 */
export function useScanData() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = getToken();
      const res = await fetch(SCAN_API_URL, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} — ${res.statusText}`);
      const json = await res.json();
      setData(json);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al obtener datos de escaneo');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch: fetchData };
}
