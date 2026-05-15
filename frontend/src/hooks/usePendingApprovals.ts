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
}

export function usePendingApprovals(pollIntervalMs = 60000): UsePendingApprovalsReturn {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchApprovals = useCallback(async () => {
    try {
      const token = getStoredToken();
      const response = await fetch(ENDPOINTS.pendingApprovals, {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        setError(`Error ${response.status}`);
        return;
      }
      const data = await response.json();
      setApprovals(data.approvals ?? []);
      setTotal(data.total ?? 0);
      setError(null);
    } catch {
      setError('M4 no disponible');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchApprovals();
    const interval = setInterval(fetchApprovals, pollIntervalMs);
    return () => clearInterval(interval);
  }, [fetchApprovals, pollIntervalMs]);

  return { approvals, total, loading, error, refetch: fetchApprovals };
}
