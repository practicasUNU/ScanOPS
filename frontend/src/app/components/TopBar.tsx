// frontend/src/app/components/TopBar.tsx
import { Bell, Shield, LogOut, Settings } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router';
import { getCycleState } from '../utils/cycleState';
import type { DotColor } from '../utils/cycleState';
import { useAuth } from '../../hooks/useAuth';
import { useCriticalAlerts } from '../../hooks/useCriticalAlerts';

interface TopBarProps {
  role?: string;
  cycleLabel?: string;
  dotColor?: DotColor;
}

export function TopBar({ role = 'System Manager', cycleLabel, dotColor }: TopBarProps) {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const [notifOpen, setNotifOpen] = useState(false);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [notifLoading, setNotifLoading] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);
  const { alerts: criticalAlerts, unreadCount: criticalCount, markAllRead } = useCriticalAlerts();

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const fetchNotifications = async () => {
    setNotifLoading(true);
    try {
      const token = (() => {
        try { return JSON.parse(sessionStorage.getItem('scanops_auth') || '{}')?.access_token ?? null; }
        catch { return null; }
      })();
      const h: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};

      const [siemRes, m4Res] = await Promise.allSettled([
        fetch('/api/m5/siem/pipeline-events?limit=5', { headers: h, signal: AbortSignal.timeout(5000) }),
        fetch('/api/m4/api/m4/pending-approvals?limit=5', { headers: h, signal: AbortSignal.timeout(5000) }),
      ]);

      const notifs: any[] = [];

      if (siemRes.status === 'fulfilled' && siemRes.value.ok) {
        const data = await siemRes.value.json();
        (data.events ?? []).forEach((e: any) => notifs.push({
          id: `siem-${e.id}`,
          type: 'siem',
          severity: e.severity,
          title: e.event_type,
          message: e.description?.slice(0, 80) ?? '—',
          timestamp: e.timestamp,
          link: '/alerts',
        }));
      }

      if (m4Res.status === 'fulfilled' && m4Res.value.ok) {
        const data = await m4Res.value.json();
        (data.approvals ?? []).forEach((a: any) => notifs.push({
          id: `m4-${a.id}`,
          type: 'm4',
          severity: 'HIGH',
          title: `Aprobación pendiente #${a.id}`,
          message: `${a.cve_id} → ${a.target_ip}`,
          timestamp: a.created_at,
          link: '/exploitation',
        }));
      }

      notifs.sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime());
      setNotifications(notifs.slice(0, 8));
    } catch { }
    finally { setNotifLoading(false); }
  };

  const handleBellClick = () => {
    setNotifOpen(p => !p);
    if (!notifOpen) {
      fetchNotifications();
      markAllRead();
    }
  };

  const unreadCount = notifications.length + criticalCount;

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const localCycle = getCycleState();
  const label = cycleLabel ?? localCycle.label;
  const color = dotColor ?? localCycle.dotColor;
  const dot = color === 'green' ? '●' : color === 'amber' ? '⏸' : color === 'red' ? '●' : '◌';

  const pillStyle =
    color === 'green'
      ? { borderColor: 'rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#22C55E' }
      : color === 'amber'
      ? { borderColor: 'rgba(245,158,11,0.25)', background: 'rgba(245,158,11,0.07)', color: '#F59E0B' }
      : color === 'red'
      ? { borderColor: 'rgba(239,68,68,0.25)', background: 'rgba(239,68,68,0.07)', color: '#EF4444' }
      : { borderColor: 'rgba(100,116,139,0.25)', background: 'rgba(100,116,139,0.07)', color: '#64748B' };

  return (
    <header
      className="h-16 flex items-center justify-between px-6 shrink-0"
      style={{ background: '#0D0F14', borderBottom: '1px solid #1C2030' }}
    >
      {/* Left: page title */}
      <div className="flex items-center gap-3">
        <h1 className="text-sm font-semibold" style={{ color: '#E2E8F0' }}>{role}</h1>
      </div>

      {/* Center: cycle status pill */}
      <div
        className="flex items-center gap-2 px-3 py-1.5 rounded-full font-mono text-xs border"
        style={pillStyle}
      >
        <span className={`text-sm leading-none ${color === 'green' ? 'animate-pulse' : ''}`}>
          {dot}
        </span>
        <span>{label}</span>
      </div>

      {/* Right: actions + user */}
      <div className="flex items-center gap-2">
        {/* MFA badge */}
        <div
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border"
          style={{ background: 'rgba(34,197,94,0.07)', borderColor: 'rgba(34,197,94,0.25)' }}
        >
          <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: '#22C55E' }} />
          <span className="text-[11px] font-medium" style={{ color: '#22C55E' }}>MFA</span>
        </div>

        {/* Settings */}
        <button
          onClick={() => navigate('/settings')}
          className="p-2 rounded-lg transition-colors cursor-pointer"
          style={{ color: '#64748B' }}
          onMouseEnter={e => {
            (e.currentTarget as HTMLButtonElement).style.color = '#E2E8F0';
            (e.currentTarget as HTMLButtonElement).style.background = '#1C2030';
          }}
          onMouseLeave={e => {
            (e.currentTarget as HTMLButtonElement).style.color = '#64748B';
            (e.currentTarget as HTMLButtonElement).style.background = '';
          }}
          title="Configuración"
        >
          <Settings className="w-4 h-4" />
        </button>

        {/* Notification bell */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={handleBellClick}
            className="relative p-2 rounded-lg transition-colors cursor-pointer"
            style={{ color: '#64748B' }}
            onMouseEnter={e => {
              (e.currentTarget as HTMLButtonElement).style.color = '#E2E8F0';
              (e.currentTarget as HTMLButtonElement).style.background = '#1C2030';
            }}
            onMouseLeave={e => {
              (e.currentTarget as HTMLButtonElement).style.color = '#64748B';
              (e.currentTarget as HTMLButtonElement).style.background = '';
            }}
            title="Notificaciones"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span
                className={`absolute top-0.5 right-0.5 min-w-[15px] h-[15px] rounded-full flex items-center justify-center text-[9px] font-bold text-white px-0.5 ${
                  criticalCount > 0 ? 'animate-pulse' : ''
                }`}
                style={{ background: '#EF4444' }}
              >
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>

          {notifOpen && (
            <div
              className="absolute right-0 top-full mt-2 w-80 rounded-xl shadow-2xl z-50 overflow-hidden"
              style={{ background: '#111318', border: '1px solid #1C2030' }}
            >
              <div
                className="flex items-center justify-between px-4 py-3"
                style={{ borderBottom: '1px solid #1C2030' }}
              >
                <span className="text-xs font-semibold text-white">Notificaciones</span>
                <div className="flex items-center gap-3">
                  <button
                    onClick={fetchNotifications}
                    className="text-[10px] font-mono underline cursor-pointer transition-colors"
                    style={{ color: '#64748B' }}
                    onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.color = '#E2E8F0'}
                    onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.color = '#64748B'}
                  >
                    Actualizar
                  </button>
                  <button
                    onClick={() => setNotifOpen(false)}
                    className="text-sm cursor-pointer transition-colors"
                    style={{ color: '#64748B' }}
                    onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.color = '#E2E8F0'}
                    onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.color = '#64748B'}
                  >
                    ×
                  </button>
                </div>
              </div>

              <div className="max-h-80 overflow-y-auto">
                {notifLoading ? (
                  <div className="flex items-center justify-center py-6 gap-2 text-xs" style={{ color: '#64748B' }}>
                    <span className="animate-spin">⟳</span> Cargando...
                  </div>
                ) : notifications.length === 0 && criticalAlerts.length === 0 ? (
                  <div className="text-center py-6 text-xs" style={{ color: '#64748B' }}>
                    Sin notificaciones recientes
                  </div>
                ) : (
                  [...criticalAlerts.map(a => ({
                    id: a.id,
                    type: 'critical' as const,
                    severity: 'CRITICAL',
                    title: a.title,
                    message: a.message,
                    timestamp: a.timestamp,
                    link: a.link,
                  })), ...notifications].map(n => (
                    <button
                      key={n.id}
                      onClick={() => { navigate(n.link); setNotifOpen(false); }}
                      className="w-full text-left px-4 py-3 transition-colors cursor-pointer last:border-0"
                      style={{ borderBottom: '1px solid rgba(28,32,48,0.7)' }}
                      onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.background = '#1C2030'}
                      onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.background = ''}
                    >
                      <div className="flex items-start gap-2.5">
                        <span
                          className="mt-1 w-1.5 h-1.5 rounded-full shrink-0"
                          style={{
                            background:
                              n.severity === 'CRITICAL' ? '#EF4444' :
                              n.severity === 'HIGH'     ? '#F97316' :
                              n.type === 'm4'           ? '#F59E0B' :
                              '#8B5CF6',
                          }}
                        />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-semibold text-white truncate">{n.title}</p>
                          <p className="text-[10px] truncate mt-0.5" style={{ color: '#64748B' }}>{n.message}</p>
                          <p className="text-[9px] font-mono mt-0.5" style={{ color: '#374151' }}>
                            {n.timestamp
                              ? new Date(n.timestamp.endsWith('Z') || n.timestamp.includes('+') ? n.timestamp : n.timestamp + 'Z')
                                  .toLocaleDateString('es-ES', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Madrid' })
                              : '—'}
                          </p>
                        </div>
                        <span className="text-[9px] shrink-0 mt-0.5" style={{ color: '#64748B' }}>
                          {n.type === 'm4' ? 'M4' : 'M5'}
                        </span>
                      </div>
                    </button>
                  ))
                )}
              </div>

              <div
                className="px-4 py-2.5 flex justify-between"
                style={{ borderTop: '1px solid #1C2030' }}
              >
                <button
                  onClick={() => { navigate('/alerts'); setNotifOpen(false); }}
                  className="text-[10px] hover:underline cursor-pointer"
                  style={{ color: '#8B5CF6' }}
                >
                  Ver todas las alertas →
                </button>
                <button
                  onClick={() => { navigate('/exploitation'); setNotifOpen(false); }}
                  className="text-[10px] hover:underline cursor-pointer"
                  style={{ color: '#F59E0B' }}
                >
                  Cola M4 →
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Divider + user info */}
        <div
          className="flex items-center gap-3 pl-3 ml-1"
          style={{ borderLeft: '1px solid #1C2030' }}
        >
          <div
            className="w-7 h-7 rounded-full flex items-center justify-center shrink-0"
            style={{ background: 'linear-gradient(135deg, #8B5CF6 0%, #6D28D9 100%)' }}
          >
            <Shield className="w-3.5 h-3.5 text-white" />
          </div>
          <div className="text-xs leading-none">
            <div className="font-medium text-white">admin</div>
            <div className="mt-0.5" style={{ color: '#64748B' }}>{role}</div>
          </div>
        </div>

        {/* Logout */}
        <button
          onClick={handleLogout}
          className="p-2 rounded-lg transition-colors cursor-pointer"
          style={{ color: '#64748B' }}
          onMouseEnter={e => {
            (e.currentTarget as HTMLButtonElement).style.color = '#EF4444';
            (e.currentTarget as HTMLButtonElement).style.background = 'rgba(239,68,68,0.1)';
          }}
          onMouseLeave={e => {
            (e.currentTarget as HTMLButtonElement).style.color = '#64748B';
            (e.currentTarget as HTMLButtonElement).style.background = '';
          }}
          title="Cerrar sesión"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
}
