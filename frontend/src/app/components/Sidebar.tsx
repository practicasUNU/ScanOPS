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

  // [1] ESTRUCTURA: Agrupamos las opciones por secciones de control y pipeline
  const sections = [
    {
      title: 'Pipeline',
      items: [
        { icon: Boxes, label: 'M1 - Asset Manager', path: '/assets' },
        { icon: Search, label: 'M2+M3 - Scanner', path: '/surface' },
        { icon: Brain, label: 'M8 - IA Reasoning', path: '/ai-reasoning' },
        { icon: ClipboardList, label: 'M4 - Explotación', path: '/exploitation' },
        { icon: Bell, label: 'M5 - Alertas SIEM', path: '/alerts' },
        { icon: Shield, label: 'Bastionado', path: '/bastionado' },
        { icon: FileText, label: 'M7 - Reportes', path: '/reporting' },
      ]
    },
    {
      title: 'Control',
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
      className={`relative bg-[#1a1d27] border-r border-[#1e2530] flex flex-col transition-all duration-300 ease-in-out z-20 ${
        isCollapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Botón flotante para colapsar */}
      <button
        onClick={() => setIsCollapsed(!isCollapsed)}
        className="absolute -right-3 top-6 bg-[#1a1d27] text-[#9ca3af] hover:text-[#00d4ff] p-1.5 rounded-full border border-[#1e2530] hover:border-[#00d4ff]/50 transition-all z-30 cursor-pointer"
        title={isCollapsed ? "Expandir menú" : "Colapsar menú"}
      >
        {isCollapsed ? <PanelLeft className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
      </button>

      {/* Header con Logo */}
      <div className={`p-6 border-b border-[#1e2530] flex items-center h-[89px] ${isCollapsed ? 'justify-center px-0' : 'gap-3'}`}>
        <div className="w-8 h-8 bg-gradient-to-br from-[#00d4ff] to-[#0099cc] rounded flex items-center justify-center shrink-0">
          <Shield className="w-5 h-5 text-[#0f1117]" />
        </div>
        {!isCollapsed && (
          <span className="text-xl font-semibold text-white truncate transition-opacity duration-300">
            ScanOps
          </span>
        )}
      </div>

      {/* Menú de Navegación por Secciones */}
      <div className="flex-1 p-4 space-y-4 overflow-y-auto overflow-x-hidden">
        {sections.map((section, idx) => (
          <div key={idx} className="space-y-1">
            {/* [2] TÍTULO DE CATEGORÍA: Solo se muestra si el sidebar está expandido */}
            {!isCollapsed ? (
              <div className="text-[10px] font-bold tracking-wider text-slate-500 uppercase px-3 pt-2 pb-1 select-none">
                {section.title}
              </div>
            ) : (
              // Una pequeña línea divisoria visual si está colapsado para separar bloques
              idx > 0 && <div className="border-t border-[#1e2530] my-2 mx-2" />
            )}

            {section.items.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.path);
              const isPipeline = section.title === 'Pipeline';
              const moduleStatus = isPipeline ? getModuleStatus(item.path, health) : undefined;

              return (
                <Link
                  key={item.path}
                  to={item.path}
                  title={isCollapsed ? item.label : undefined}
                  className={`flex items-center rounded-lg transition-all duration-200 ${
                    isCollapsed ? 'justify-center p-3' : 'gap-3 px-4 py-2.5'
                  } ${
                    active
                      ? 'bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/20'
                      : 'text-[#9ca3af] hover:bg-[#1e2530] hover:text-white border border-transparent'
                  }`}
                >
                  <Icon className="w-5 h-5 shrink-0" />
                  {!isCollapsed && (
                    <>
                      <span className="text-sm font-medium truncate transition-opacity duration-300">
                        {item.label}
                      </span>
                      {moduleStatus !== undefined && (
                        <div className={`ml-auto w-1.5 h-1.5 rounded-full shrink-0 ${
                          moduleStatus === 'online' ? 'bg-[#22c55e]' : 'bg-[#ff3b3b]'
                        }`} />
                      )}
                    </>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </div>

      {/* Footer de Versión */}
      <div className={`p-4 border-t border-[#1e2530] transition-all duration-300 ${isCollapsed ? 'text-center' : ''}`}>
        {!isCollapsed ? (
          <div className="text-xs text-[#9ca3af] space-y-1">
            <div className="truncate">v2.4.1-alpha</div>
            <div className="truncate text-[#22c55e]">ENS Alto Certified</div>
          </div>
        ) : (
          <div className="text-[10px] text-[#9ca3af] font-mono font-bold cursor-default" title="v2.4.1-alpha">
            v2.4
          </div>
        )}
      </div>
    </aside>
  );
}