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
        fetch('http://localhost:8006/siem/pipeline-events?limit=5', { headers: h, signal: AbortSignal.timeout(5000) }),
        fetch('http://localhost:8004/api/m4/pending-approvals?limit=5', { headers: h, signal: AbortSignal.timeout(5000) }),
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
  const dot = color === 'green' ? '●' : color === 'amber' ? '⏸' : color === 'red' ? '🔴' : '◌';

  const dotColorClass =
    color === 'green' ? 'text-[#22c55e]' :
    color === 'amber' ? 'text-[#f59e0b]' :
    color === 'red' ? 'text-[#ff3b3b]' : 'text-[#6b7280]';

  const pillBorderClass =
    color === 'green' ? 'border-[#22c55e]/20 bg-[#22c55e]/5' :
    color === 'amber' ? 'border-[#f59e0b]/20 bg-[#f59e0b]/5' :
    color === 'red' ? 'border-[#ff3b3b]/20 bg-[#ff3b3b]/5' : 'border-[#4b5563]/30 bg-[#374151]/10';

  const pillTextClass =
    color === 'green' ? 'text-[#22c55e]' :
    color === 'amber' ? 'text-[#f59e0b]' :
    color === 'red' ? 'text-[#ff3b3b]' : 'text-[#6b7280]';

  return (
    <header className="h-16 bg-[#1a1d27] border-b border-[#1e2530] flex items-center justify-between px-6">
      <div className="flex items-center gap-4">
        <h1 className="text-lg font-semibold text-white">{role}</h1>
      </div>

      {/* Centered cycle status pill */}
      <div className={`flex items-center gap-2 px-3 py-1.5 border rounded-full font-mono text-xs ${pillBorderClass} ${pillTextClass}`}>
        <span className={`text-sm leading-none ${dotColorClass} ${color === 'green' ? 'animate-pulse' : ''}`}>
          {dot}
        </span>
        <span>{label}</span>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-3 py-1.5 bg-[#22c55e]/10 border border-[#22c55e]/30 rounded-full">
          <div className="w-2 h-2 bg-[#22c55e] rounded-full animate-pulse"></div>
          <span className="text-xs text-[#22c55e] font-medium">MFA Activo</span>
        </div>

        {/* [NUEVO] Botón de Ajustes/Configuración */}
        <button 
          onClick={() => navigate('/settings')}
          className="p-2 text-[#9ca3af] hover:text-white hover:bg-[#1e2530] rounded-lg transition-colors cursor-pointer"
          title="Configuración"
        >
          <Settings className="w-5 h-5" />
        </button>

        <div className="relative" ref={notifRef}>
          <button
            onClick={handleBellClick}
            className="relative p-2 text-[#9ca3af] hover:text-white hover:bg-[#1e2530] rounded-lg transition-colors cursor-pointer"
            title="Notificaciones"
          >
            <Bell className="w-5 h-5" />
            {unreadCount > 0 && (
              <span className={`absolute top-0.5 right-0.5 min-w-[16px] h-4 rounded-full flex items-center justify-center text-[9px] font-bold text-white px-1 bg-[#ff3b3b] ${
                criticalCount > 0 ? 'animate-pulse' : ''
              }`}>
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>

          {notifOpen && (
            <div className="absolute right-0 top-full mt-2 w-80 bg-[#1a1d27] border border-[#1e2530] rounded-xl shadow-2xl z-50 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2530]">
                <span className="text-xs font-bold text-white">Notificaciones</span>
                <div className="flex items-center gap-2">
                  <button onClick={fetchNotifications}
                    className="text-[10px] text-[#6b7280] hover:text-white font-mono underline cursor-pointer">
                    Actualizar
                  </button>
                  <button onClick={() => setNotifOpen(false)}
                    className="text-[#6b7280] hover:text-white text-sm cursor-pointer">×</button>
                </div>
              </div>

              <div className="max-h-80 overflow-y-auto">
                {notifLoading ? (
                  <div className="flex items-center justify-center py-6 gap-2 text-[#6b7280] text-xs">
                    <span className="animate-spin">⟳</span> Cargando...
                  </div>
                ) : notifications.length === 0 && criticalAlerts.length === 0 ? (
                  <div className="text-center py-6 text-xs text-[#6b7280]">
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
                      className="w-full text-left px-4 py-3 hover:bg-[#1e2530] border-b border-[#1e2530]/50 last:border-0 transition-colors cursor-pointer"
                    >
                      <div className="flex items-start gap-2.5">
                        <span className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${
                          n.severity === 'CRITICAL' ? 'bg-[#ff3b3b]' :
                          n.severity === 'HIGH'     ? 'bg-orange-500' :
                          n.type === 'm4'           ? 'bg-[#f59e0b]' :
                          'bg-[#00d4ff]'
                        }`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-semibold text-white truncate">{n.title}</p>
                          <p className="text-[10px] text-[#9ca3af] truncate mt-0.5">{n.message}</p>
                          <p className="text-[9px] text-[#4b5563] font-mono mt-0.5">
                            {n.timestamp
                              ? new Date(n.timestamp.endsWith('Z') || n.timestamp.includes('+') ? n.timestamp : n.timestamp + 'Z')
                                  .toLocaleDateString('es-ES', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Madrid' })
                              : '—'}
                          </p>
                        </div>
                        <span className="text-[9px] text-[#6b7280] shrink-0 mt-0.5">
                          {n.type === 'm4' ? 'M4' : 'M5'}
                        </span>
                      </div>
                    </button>
                  ))
                )}
              </div>

              <div className="px-4 py-2.5 border-t border-[#1e2530] flex justify-between">
                <button onClick={() => { navigate('/alerts'); setNotifOpen(false); }}
                  className="text-[10px] text-[#00d4ff] hover:underline cursor-pointer">
                  Ver todas las alertas →
                </button>
                <button onClick={() => { navigate('/exploitation'); setNotifOpen(false); }}
                  className="text-[10px] text-[#f59e0b] hover:underline cursor-pointer">
                  Cola M4 →
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center gap-3 pl-4 border-l border-[#1e2530]">
          <div className="w-8 h-8 bg-gradient-to-br from-[#00d4ff] to-[#0099cc] rounded-full flex items-center justify-center">
            <Shield className="w-4 h-4 text-[#0f1117]" />
          </div>
          <div className="text-sm">
            <div className="text-white font-medium">admin@scanops.local</div>
            <div className="text-[#9ca3af] text-xs">{role}</div>
          </div>
        </div>

        <button
          onClick={handleLogout}
          className="p-2 text-[#9ca3af] hover:text-[#ff3b3b] hover:bg-[#ff3b3b]/10 rounded-lg transition-colors cursor-pointer"
          title="Cerrar sesión"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
}