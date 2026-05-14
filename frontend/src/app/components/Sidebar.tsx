import { Shield, LayoutDashboard, FileCheck, ClipboardList, Search, Bell, ScrollText } from 'lucide-react';
import { Link, useLocation } from 'react-router';

export function Sidebar() {
  const location = useLocation();

  const isActive = (path: string) => location.pathname === path;

  const navItems = [
    { icon: Shield, label: 'Dashboard', path: '/dashboard' },
    { icon: Search, label: 'Network Scanner', path: '/scanner' },
    { icon: ClipboardList, label: 'Explotación', path: '/exploitation' },
    { icon: FileCheck, label: 'Cumplimiento', path: '/compliance' },
    { icon: Bell, label: 'Alertas', path: '/alerts' },
    { icon: ScrollText, label: 'Logs Auditoría', path: '/audit-logs' },
  ];

  return (
    <aside className="w-60 bg-[#1a1d27] border-r border-[#1e2530] flex flex-col">
      <div className="p-6 border-b border-[#1e2530]">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-[#00d4ff] to-[#0099cc] rounded flex items-center justify-center">
            <Shield className="w-5 h-5 text-[#0f1117]" />
          </div>
          <span className="text-xl font-semibold text-white">ScanOps</span>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = isActive(item.path);

          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                active
                  ? 'bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/20'
                  : 'text-[#9ca3af] hover:bg-[#1e2530] hover:text-white'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span className="font-medium">{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-[#1e2530]">
        <div className="text-xs text-[#9ca3af] space-y-1">
          <div>v2.4.1-alpha</div>
          <div>ENS Alto Certified</div>
        </div>
      </div>
    </aside>
  );
}
