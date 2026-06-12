import { useState, useEffect, useCallback } from 'react';
import { getStoredToken } from './useAuth';

const M2_BASE = '/api/m2/api/v1';

export interface M2Port {
  port: number;
  service: string;
  version: string;
  state: string;
}

export interface M2Snapshot {
  snapshot_id: string;
  target: string;
  status: 'completed' | 'running' | 'failed' | string;
  created_at: string;
  findings_count?: number;
  ports_open?: number;
  services_detected?: number;
  os_family?: string | null;
  ports?: M2Port[];
  isBlacklisted?: boolean;
  registeredStatus?: string;
}

const MOCK_SNAPSHOTS: M2Snapshot[] = [
  {
    snapshot_id: 'scan-20260513-001', target: '10.202.15.200', status: 'completed',
    created_at: '2026-05-13T02:15:00Z', findings_count: 3, ports_open: 3,
    services_detected: 3, os_family: 'Linux',
    ports: [
      { port: 22, service: 'ssh', version: 'OpenSSH 8.9', state: 'open' },
      { port: 80, service: 'http', version: 'Apache 2.4', state: 'open' },
      { port: 443, service: 'https', version: 'nginx 1.24', state: 'open' },
    ],
  },
  {
    snapshot_id: 'scan-20260513-002', target: '10.202.15.201', status: 'completed',
    created_at: '2026-05-13T02:18:00Z', findings_count: 1, ports_open: 1,
    services_detected: 1, os_family: null,
    ports: [{ port: 3306, service: 'mysql', version: '8.0.32', state: 'open' }],
  },
  {
    snapshot_id: 'scan-20260513-003', target: '10.202.15.202', status: 'completed',
    created_at: '2026-05-13T02:21:00Z', findings_count: 4, ports_open: 4,
    services_detected: 2, os_family: 'Windows',
    ports: [
      { port: 135, service: 'msrpc', version: '', state: 'open' },
      { port: 139, service: 'netbios-ssn', version: '', state: 'open' },
      { port: 445, service: 'microsoft-ds', version: '', state: 'open' },
      { port: 3389, service: 'ms-wbt-server', version: 'RDP', state: 'open' },
    ],
  },
  {
    snapshot_id: 'scan-20260514-001', target: '10.202.15.55', status: 'completed',
    created_at: '2026-05-14T02:10:00Z', findings_count: 2, ports_open: 2,
    services_detected: 2, os_family: 'Linux',
    ports: [
      { port: 21, service: 'ftp', version: 'vsftpd 3.0', state: 'open' },
      { port: 23, service: 'telnet', version: '', state: 'open' },
    ],
  },
];

function authHeaders(): HeadersInit {
  const token = getStoredToken();
  return token
    ? { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };
}

export function useShadowIT(registeredAssets: { ip: string; status: string }[] = []) {
  const [allSnapshots, setAllSnapshots] = useState<M2Snapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSnapshots = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${M2_BASE}/snapshots`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`M2 error ${res.status}`);
      const list: M2Snapshot[] = await res.json();

      const toEnrich = list.slice(0, 10);
      const enriched = await Promise.all(
        toEnrich.map(async (snap) => {
          if (snap.findings_count !== undefined && snap.findings_count === 0) return snap;
          try {
            const r = await fetch(`${M2_BASE}/snapshots/latest?target=${encodeURIComponent(snap.target)}`, {
              headers: authHeaders(),
            });
            if (!r.ok) return snap;
            const detail = await r.json();
            const recon = detail.reconnaissance ?? {};
            const portsArr: M2Port[] = (recon.ports_discovered ?? []).map((p: any) => ({
              port: p.port,
              service: p.service ?? '',
              version: p.version ?? '',
              state: p.state ?? 'open',
            }));
            return {
              ...snap,
              ports_open: detail.summary?.total_ports_open ?? portsArr.length,
              services_detected: detail.summary?.total_services_detected,
              os_family: recon.os_information?.detected_family ?? null,
              ports: portsArr,
            } as M2Snapshot;
          } catch {
            return snap;
          }
        }),
      );

      setAllSnapshots(enriched);
      setError(null);
    } catch {
      setAllSnapshots(MOCK_SNAPSHOTS);
      setError('M2 no disponible');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchSnapshots(); }, [fetchSnapshots]);

  const registeredIPs = new Set(registeredAssets.map(a => a.ip));
  const snapshots = allSnapshots.filter(s => !registeredIPs.has(s.target));
  const alreadyRegistered = allSnapshots
    .filter(s => registeredIPs.has(s.target))
    .map(s => {
      const reg = registeredAssets.find(a => a.ip === s.target);
      return { ...s, isBlacklisted: reg?.status === 'BLOQUEADA', registeredStatus: reg?.status };
    });

  return { snapshots, alreadyRegistered, loading, error, refetch: fetchSnapshots };
}
