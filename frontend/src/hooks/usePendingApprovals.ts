import { useState, useEffect, useCallback } from 'react';
import { ENDPOINTS } from '../config/api';
import { getStoredToken } from './useAuth';

export interface ApprovalRequest {
  id: number;
  cve_id: string;
  target_ip: string;
  requester: string;
  status: string;
  created_at: string;
  expires_at: string;
  approved_at: string | null;
}

interface UsePendingApprovalsReturn {
  approvals: ApprovalRequest[];
  total: number;
  loading: boolean;
  error: string | null;
  refetch: () => void;
  isMock: boolean;
}

const MOCK_APPROVALS: ApprovalRequest[] = [
  {
    id: 99,
    cve_id: 'CVE-2023-38408',
    target_ip: '10.202.15.15',
    requester: 'M8-AI-Reasoning (demo)',
    status: 'PENDING',
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
    approved_at: null,
  },
];

export function usePendingApprovals(pollIntervalMs = 60000): UsePendingApprovalsReturn {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isMock, setIsMock] = useState(false);

  const fetchApprovals = useCallback(async () => {
    try {
      const token = getStoredToken();
      console.log('[M4] Fetching approvals, token present:', !!token);
      const response = await fetch(ENDPOINTS.pendingApprovals, {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {},
        signal: AbortSignal.timeout(8000),
      });
      console.log('[M4] Response status:', response.status);
      if (!response.ok) {
        const body = await response.text().catch(() => '');
        console.error('[M4] Error body:', body);
        setError(`M4 error ${response.status}`);
        setApprovals(MOCK_APPROVALS);
        setTotal(MOCK_APPROVALS.length);
        setIsMock(true);
        return;
      }
      const data = await response.json();
      console.log('[M4] Data received:', data);
      setApprovals(data.approvals ?? []);
      setTotal(data.total ?? 0);
      setError(null);
      setIsMock(false);
    } catch (e) {
      console.error('[M4] Fetch failed:', e);
      setError('M4 no disponible — mostrando datos de demostración');
      setApprovals(MOCK_APPROVALS);
      setTotal(MOCK_APPROVALS.length);
      setIsMock(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchApprovals();
    const interval = setInterval(fetchApprovals, pollIntervalMs);
    return () => clearInterval(interval);
  }, [fetchApprovals, pollIntervalMs]);

  return { approvals, total, loading, error, refetch: fetchApprovals, isMock };
}
