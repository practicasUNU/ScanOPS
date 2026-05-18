import { useState, useEffect, useCallback } from 'react';
import { getStoredToken } from './useAuth';

const M1_BASE = 'http://localhost:8001/api/v1';
const M3_BASE = 'http://localhost:8002';

export interface Asset {
  id: number;
  ip: string;
  hostname: string | null;
  tipo: string;
  criticidad: string;
  status: string;
  responsable: string | null;
}

export interface VulnResult {
  id: number;
  asset_id: number;
  title: string;
  severity: string;
  tool_source: string;
  cve_id: string | null;
  created_at: string;
}

export interface ScanTask {
  task_id: string;
  status: string;
  tool: string;
  asset_id: number;
}

function authHeaders(): HeadersInit {
  const token = getStoredToken();
  return token
    ? { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };
}

export function useAssets() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${M1_BASE}/assets?page_size=100`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`M1 error ${res.status}`);
      const data = await res.json();
      setAssets(data.items ?? []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'M1 no disponible');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  const createAsset = useCallback(async (payload: {
    ip: string; hostname?: string; tipo: string; criticidad: string; responsable: string;
  }): Promise<Asset> => {
    const res = await fetch(`${M1_BASE}/assets`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error((err as { detail?: string }).detail ?? `Error ${res.status}`);
    }
    const asset: Asset = await res.json();
    setAssets(prev => [asset, ...prev]);
    return asset;
  }, []);

  const scanAsset = useCallback(async (asset_id: number, ip: string): Promise<ScanTask> => {
    const res = await fetch(`${M3_BASE}/scanner/nuclei`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ asset_id, ip }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error((err as { detail?: string }).detail ?? `M3 error ${res.status}`);
    }
    return res.json();
  }, []);

  const getVulnResults = useCallback(async (asset_id: number): Promise<VulnResult[]> => {
    const res = await fetch(`${M3_BASE}/scanner/results/${asset_id}`, { headers: authHeaders() });
    if (!res.ok) return [];
    return res.json();
  }, []);

  return { assets, loading, error, refetch: fetchAssets, createAsset, scanAsset, getVulnResults };
}
