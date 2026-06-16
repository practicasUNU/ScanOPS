import { useState, useEffect, useCallback } from 'react';
import { getStoredToken } from './useAuth';

const M3_BASE = '/api/m3/api/v1';

function authHeaders(): HeadersInit {
  const token = getStoredToken();
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };
}

// ── Types ──────────────────────────────────────────────────────────────────────

export interface BehavioralFinding {
  id: number;
  asset_id: number;
  process_name: string;
  anomaly_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence_score: number;
  detection_method: string;
  status: string;
  mitre_attack_tactics: string[];
  indicators: {
    cmdline?: string;
    matched?: string[];
    threat_intel?: Record<string, unknown>;
    [key: string]: unknown;
  };
  created_at: string;
  updated_at: string;
}

export interface ThreatIntelEntry {
  id: number;
  ioc_value: string;
  ioc_type: 'ip' | 'domain' | 'hash';
  is_malicious: boolean;
  vt_malicious_count: number | null;
  crowdsec_score: number | null;
  otx_pulse_count: number | null;
  ttl_expires: string;
  created_at: string;
}

export interface ResponseAction {
  id: number;
  asset_id: number;
  action_type: 'kill_process' | 'quarantine_file' | 'block_ip' | 'isolate_host' | 'collect_forensics';
  target_detail: string;
  requested_by: string;
  approved_by: string | null;
  justification: string;
  status: 'pending' | 'approved' | 'rejected' | 'executing' | 'completed' | 'failed';
  created_at: string;
  executed_at: string | null;
  execution_output: string | null;
}

export interface EDRStats {
  total_findings: number;
  critical_findings: number;
  malicious_ips: number;
  pending_approvals: number;
}

// ── useBehavioralFindings ──────────────────────────────────────────────────────

export function useBehavioralFindings(assetId?: number, page = 1, limit = 20) {
  const [findings, setFindings] = useState<BehavioralFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ page: String(page), limit: String(limit) });
      if (assetId) params.set('asset_id', String(assetId));
      const res = await fetch(`${M3_BASE}/edr/behavioral-findings?${params}`, {
        headers: authHeaders(),
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setFindings(data.findings ?? data.items ?? []);
      setTotal(data.total ?? 0);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error cargando findings');
    } finally {
      setLoading(false);
    }
  }, [assetId, page, limit]);

  useEffect(() => { load(); }, [load]);

  return { findings, total, loading, error, refetch: load };
}

// ── useThreatIntel ─────────────────────────────────────────────────────────────

export function useThreatIntel(page = 1, limit = 20) {
  const [entries, setEntries] = useState<ThreatIntelEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        page: String(page),
        limit: String(limit),
        malicious_only: 'true',
      });
      const res = await fetch(`${M3_BASE}/edr/threat-intel/cache?${params}`, {
        headers: authHeaders(),
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setEntries(data.entries ?? data.items ?? []);
      setTotal(data.total ?? 0);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error cargando threat intel');
    } finally {
      setLoading(false);
    }
  }, [page, limit]);

  useEffect(() => { load(); }, [load]);

  return { entries, total, loading, error, refetch: load };
}

// ── useResponseActions ─────────────────────────────────────────────────────────

export function useResponseActions(assetId?: number, statusFilter?: string) {
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const targetId = assetId ?? 0;
      const params = new URLSearchParams({ limit: '50' });
      if (statusFilter) params.set('status', statusFilter);
      const res = await fetch(`${M3_BASE}/edr/response-actions/${targetId}?${params}`, {
        headers: authHeaders(),
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setActions(data.actions ?? data.items ?? []);
      setTotal(data.total ?? 0);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error cargando acciones');
    } finally {
      setLoading(false);
    }
  }, [assetId, statusFilter]);

  useEffect(() => { load(); }, [load]);

  return { actions, total, loading, error, refetch: load };
}

// ── useEDRStats ────────────────────────────────────────────────────────────────

export function useEDRStats() {
  const [stats, setStats] = useState<EDRStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${M3_BASE}/edr/stats`, {
          headers: authHeaders(),
          signal: AbortSignal.timeout(8000),
        });
        if (res.ok) {
          setStats(await res.json());
        }
      } catch { /* stats are non-critical */ }
      finally { setLoading(false); }
    };
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);

  return { stats, loading };
}

// ── approveAction ──────────────────────────────────────────────────────────────

export async function approveAction(
  actionId: number,
  totpCode: string,
  pin: string,
  approvedBy: string,
): Promise<{ ok: boolean; message: string }> {
  try {
    const res = await fetch(`${M3_BASE}/edr/approve-action/${actionId}`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ totp_code: totpCode, pin, approved_by: approvedBy }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { ok: false, message: (data as Record<string,string>).detail ?? `Error ${res.status}` };
    }
    return { ok: true, message: 'Acción aprobada correctamente' };
  } catch (e: unknown) {
    return { ok: false, message: e instanceof Error ? e.message : 'Error de red' };
  }
}

export async function requestResponseAction(payload: {
  asset_id: number;
  action_type: string;
  target_detail: string;
  requested_by: string;
  justification: string;
  pin: string;
}): Promise<{ ok: boolean; data?: ResponseAction & { totp_secret: string; totp_qr_base64: string; approval_instructions: string }; message: string }> {
  try {
    const res = await fetch(`${M3_BASE}/edr/request-response-action`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { ok: false, message: (data as Record<string,string>).detail ?? `Error ${res.status}` };
    }
    return { ok: true, data: data as ResponseAction & { totp_secret: string; totp_qr_base64: string; approval_instructions: string }, message: 'Acción solicitada' };
  } catch (e: unknown) {
    return { ok: false, message: e instanceof Error ? e.message : 'Error de red' };
  }
}
