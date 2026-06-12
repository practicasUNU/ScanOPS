import { useState, useEffect, useCallback, useRef } from 'react';

export interface CriticalAlert {
  id: string;
  title: string;
  message: string;
  timestamp: string;
  source: 'siem' | 'access';
  link: string;
}

const POLL_INTERVAL_MS = 60_000;
const SEEN_KEY = 'scanops_seen_critical_ids';

function getToken(): string | null {
  try {
    return JSON.parse(sessionStorage.getItem('scanops_auth') || '{}')?.access_token ?? null;
  } catch { return null; }
}

function getSeenIds(): Set<string> {
  try {
    const raw = localStorage.getItem(SEEN_KEY);
    return new Set(raw ? JSON.parse(raw) : []);
  } catch { return new Set(); }
}

function markSeen(ids: string[]) {
  try {
    const existing = getSeenIds();
    ids.forEach(id => existing.add(id));
    const arr = Array.from(existing).slice(-200);
    localStorage.setItem(SEEN_KEY, JSON.stringify(arr));
  } catch {}
}

async function fetchCriticalEvents(): Promise<CriticalAlert[]> {
  const token = getToken();
  if (!token) return [];
  const headers: HeadersInit = { Authorization: `Bearer ${token}` };
  const alerts: CriticalAlert[] = [];

  // Fuente 1: SIEM pipeline events (M5)
  try {
    const res = await fetch('/api/m5/siem/pipeline-events?limit=20', {
      headers,
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const data = await res.json();
      (data.events ?? [])
        .filter((e: any) => e.severity === 'CRITICAL')
        .forEach((e: any) => {
          alerts.push({
            id: `siem-${e.id}`,
            title: e.event_type ?? 'Evento CRITICAL',
            message: e.description?.slice(0, 90) ?? '—',
            timestamp: e.timestamp ?? new Date().toISOString(),
            source: 'siem',
            link: '/alerts',
          });
        });
    }
  } catch {}

  // Fuente 2: auth events SSH servidores (M5)
  try {
    const res = await fetch('/api/m5/siem/auth-events?limit=20', {
      headers,
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const data = await res.json();
      (data.events ?? [])
        .filter((e: any) => e.severity === 'CRITICAL')
        .forEach((e: any) => {
          alerts.push({
            id: `auth-${e.timestamp}-${e.src_user}`,
            title: `Acceso CRITICAL — ${e.action_type ?? 'SSH'}`,
            message: `${e.src_user ?? '?'} desde ${e.src_ip ?? '?'} en ${e.agent_name ?? e.agent_ip ?? '?'}`,
            timestamp: e.timestamp ?? new Date().toISOString(),
            source: 'access',
            link: '/audit-logs',
          });
        });
    }
  } catch {}

  // Fuente 3: login events plataforma — fuerza bruta (≥5 fallos misma IP)
  try {
    const res = await fetch('/api/orchestrator/auth/login-events?limit=50', {
      headers,
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const data = await res.json();
      const events: any[] = data.events ?? [];
      const failsByIp: Record<string, any[]> = {};
      events.filter(e => !e.success && e.ip_origin).forEach(e => {
        failsByIp[e.ip_origin] = failsByIp[e.ip_origin] ?? [];
        failsByIp[e.ip_origin].push(e);
      });
      Object.entries(failsByIp)
        .filter(([, evs]) => evs.length >= 5)
        .forEach(([ip, evs]) => {
          alerts.push({
            id: `bruteforce-${ip}`,
            title: `Posible fuerza bruta`,
            message: `${evs.length} intentos fallidos desde ${ip}`,
            timestamp: evs[evs.length - 1]?.timestamp ?? new Date().toISOString(),
            source: 'access',
            link: '/audit-logs',
          });
        });
    }
  } catch {}

  return alerts;
}

// Estado global singleton — compartido entre instancias del hook
let globalAlerts: CriticalAlert[] = [];
let globalUnread = 0;
const subscribers = new Set<() => void>();

function notify() { subscribers.forEach(fn => fn()); }

export function useCriticalAlerts() {
  const [alerts, setAlerts] = useState<CriticalAlert[]>(globalAlerts);
  const [unreadCount, setUnreadCount] = useState(globalUnread);
  const [toastQueue, setToastQueue] = useState<CriticalAlert[]>([]);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const poll = useCallback(async () => {
    const fresh = await fetchCriticalEvents();
    if (fresh.length === 0) return;

    const seen = getSeenIds();
    const newOnes = fresh.filter(a => !seen.has(a.id));

    if (newOnes.length > 0) {
      globalAlerts = [...newOnes, ...globalAlerts].slice(0, 50);
      globalUnread += newOnes.length;
      setToastQueue(prev => [...prev, ...newOnes]);
      notify();
    }
  }, []);

  useEffect(() => {
    const update = () => {
      setAlerts([...globalAlerts]);
      setUnreadCount(globalUnread);
    };
    subscribers.add(update);

    poll();
    timerRef.current = setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      subscribers.delete(update);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [poll]);

  const markAllRead = useCallback(() => {
    markSeen(globalAlerts.map(a => a.id));
    globalUnread = 0;
    notify();
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToastQueue(prev => prev.filter(t => t.id !== id));
    markSeen([id]);
  }, []);

  return { alerts, unreadCount, toastQueue, dismissToast, markAllRead, refetch: poll };
}
