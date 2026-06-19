import {
  Shield,
  LayoutDashboard,
  FileCheck,
  ClipboardList,
  Search,
  Bell,
  ScrollText,
  PanelLeftClose,
  PanelLeft,
  Boxes,
  Brain,
  FileText,
  Settings,
  ShieldAlert,
  Zap,
  Swords,
} from 'lucide-react';
import { Link, useLocation } from 'react-router';
import { useState, useEffect } from 'react';

function useModuleHealth() {
  const [health, setHealth] = useState<Record<string, string>>({});

  useEffect(() => {
    const check = async () => {
      try {
        const raw = sessionStorage.getItem('scanops_auth');
        const token = raw ? JSON.parse(raw)?.access_token : null;
        const res = await fetch('/api/orchestrator/orchestrator/modules/health', {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          signal: AbortSignal.timeout(4000),
        });
        if (res.ok) {
          const data = await res.json();
          setHealth(data.modules ?? {});
        }
      } catch { /* silencioso */ }
    };
    check();
    const id = setInterval(check, 30000);
    return () => clearInterval(id);
  }, []);

  return health;
}

const MODULE_MAP: Record<string, string | string[]> = {
  '/assets': 'M1',
  '/surface': ['M2', 'M3'],
  '/edr': 'M3',
  '/incident-response': 'M3',
  '/ai-reasoning': 'M8',
  '/exploitation': 'M4',
  '/alerts': 'M5',
  '/reporting': 'M7',
};

function getModuleStatus(path: string, health: Record<string, string>): 'online' | 'offline' | undefined {
  const mapping = MODULE_MAP[path];
  if (!mapping) return undefined;
  if (Array.isArray(mapping)) {
    if (mapping.every(m => health[m] === undefined)) return undefined;
    return mapping.some(m => health[m] === 'offline') ? 'offline' : 'online';
  }
  if (health[mapping] === undefined) return undefined;
  return health[mapping] === 'online' ? 'online' : 'offline';
}

export function Sidebar() {
  const location = useLocation();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const health = useModuleHealth();

  const isActive = (path: string) => location.pathname === path;

  const sections = [
    {
      title: 'Análisis',
      items: [
        { icon: Boxes, label: 'Asset Manager', path: '/assets' },
        { icon: Search, label: 'Scanner', path: '/surface' },
        { icon: ShieldAlert, label: 'EDR', path: '/edr' },
        { icon: Zap, label: 'Incident Response', path: '/incident-response' },
      ]
    },
    {
      title: 'Operaciones',
      items: [
        { icon: Brain, label: 'IA Reasoning', path: '/ai-reasoning' },
        { icon: Swords, label: 'Explotación', path: '/exploitation' },
        { icon: Bell, label: 'Alertas SIEM', path: '/alerts' },
        { icon: Shield, label: 'Bastionado', path: '/bastionado' },
        { icon: FileText, label: 'Reportes', path: '/reporting' },
      ]
    },
    {
      title: 'Gestión',
      items: [
        { icon: LayoutDashboard, label: 'Dashboard', path: '/dashboard' },
        { icon: FileCheck, label: 'Cumplimiento', path: '/compliance' },
        { icon: ScrollText, label: 'Logs Auditoría', path: '/audit-logs' },
        { icon: Settings, label: 'Configuración', path: '/settings' },
      ]
    }
  ];

  return (
    <aside
      className={`relative flex flex-col transition-all duration-300 ease-in-out z-20 ${
        isCollapsed ? 'w-[60px]' : 'w-60'
      }`}
      style={{ background: '#0D0F14', borderRight: '1px solid #1C2030' }}
    >
      {/* Botón flotante para colapsar */}
      <button
        onClick={() => setIsCollapsed(!isCollapsed)}
        className="absolute -right-3 top-6 p-1.5 rounded-full transition-all z-30 cursor-pointer"
        style={{
          background: '#0D0F14',
          border: '1px solid #1C2030',
          color: '#64748B',
        }}
        onMouseEnter={e => {
          (e.currentTarget as HTMLButtonElement).style.color = '#8B5CF6';
          (e.currentTarget as HTMLButtonElement).style.borderColor = 'rgba(139,92,246,0.5)';
        }}
        onMouseLeave={e => {
          (e.currentTarget as HTMLButtonElement).style.color = '#64748B';
          (e.currentTarget as HTMLButtonElement).style.borderColor = '#1C2030';
        }}
        title={isCollapsed ? 'Expandir menú' : 'Colapsar menú'}
      >
        {isCollapsed ? <PanelLeft className="w-3.5 h-3.5" /> : <PanelLeftClose className="w-3.5 h-3.5" />}
      </button>

      {/* Header con Logo */}
      <div
        className={`flex items-center h-[64px] shrink-0 ${isCollapsed ? 'justify-center px-0' : 'gap-3 px-5'}`}
        style={{ borderBottom: '1px solid #1C2030' }}
      >
        <div
          className="w-7 h-7 rounded flex items-center justify-center shrink-0"
          style={{ background: 'linear-gradient(135deg, #8B5CF6 0%, #6D28D9 100%)' }}
        >
          <Shield className="w-4 h-4 text-white" />
        </div>
        {!isCollapsed && (
          <div className="flex flex-col leading-none">
            <span className="text-sm font-semibold text-white tracking-wide">ScanOps</span>
            <span className="text-[10px] font-mono" style={{ color: '#8B5CF6' }}>
              v2.4.1
            </span>
          </div>
        )}
      </div>

      {/* Menú de Navegación por Secciones */}
      <div className="flex-1 py-3 overflow-y-auto overflow-x-hidden">
        {sections.map((section, idx) => (
          <div key={idx} className={idx > 0 ? 'mt-1' : ''}>
            {!isCollapsed ? (
              <div
                className="px-4 pt-4 pb-1 select-none"
                style={{ fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em', color: '#374151', textTransform: 'uppercase' }}
              >
                {section.title}
              </div>
            ) : (
              idx > 0 && (
                <div className="mx-3 my-2" style={{ borderTop: '1px solid #1C2030' }} />
              )
            )}

            <div className="px-2 space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon;
                const active = isActive(item.path);
                const moduleStatus = getModuleStatus(item.path, health);

                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    title={isCollapsed ? item.label : undefined}
                    className={`flex items-center rounded transition-all duration-150 ${
                      isCollapsed ? 'justify-center p-2.5' : 'gap-2.5 px-3 py-2'
                    }`}
                    style={active ? {
                      background: 'rgba(139,92,246,0.12)',
                      color: '#8B5CF6',
                    } : {
                      color: '#64748B',
                    }}
                    onMouseEnter={e => {
                      if (!active) {
                        (e.currentTarget as HTMLAnchorElement).style.background = '#1C2030';
                        (e.currentTarget as HTMLAnchorElement).style.color = '#E2E8F0';
                      }
                    }}
                    onMouseLeave={e => {
                      if (!active) {
                        (e.currentTarget as HTMLAnchorElement).style.background = '';
                        (e.currentTarget as HTMLAnchorElement).style.color = '#64748B';
                      }
                    }}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    {!isCollapsed && (
                      <>
                        <span className="text-[13px] font-medium truncate flex-1">
                          {item.label}
                        </span>
                        {moduleStatus !== undefined && (
                          <div
                            className="w-1.5 h-1.5 rounded-full shrink-0"
                            style={{ background: moduleStatus === 'online' ? '#22C55E' : '#EF4444' }}
                          />
                        )}
                      </>
                    )}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      {!isCollapsed && (
        <div className="px-4 py-3 shrink-0" style={{ borderTop: '1px solid #1C2030' }}>
          <div className="text-[11px]" style={{ color: '#22C55E' }}>ENS Alto Certified</div>
        </div>
      )}
    </aside>
  );
}
