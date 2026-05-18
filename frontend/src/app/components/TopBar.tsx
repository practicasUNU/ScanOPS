import { Bell, Shield, LogOut } from 'lucide-react';
import { useNavigate } from 'react-router';
import { getCycleState } from '../utils/cycleState';
import type { DotColor } from '../utils/cycleState';
import { useAuth } from '../../hooks/useAuth';

interface TopBarProps {
  role?: string;
  cycleLabel?: string;
  dotColor?: DotColor;
}

export function TopBar({ role = 'System Manager', cycleLabel, dotColor }: TopBarProps) {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const localCycle = getCycleState();
  const label = cycleLabel ?? localCycle.label;
  const color = dotColor ?? localCycle.dotColor;
  const dot = color === 'green' ? '●' : color === 'amber' ? '⏸' : color === 'red' ? '🔴' : '◌';

  const dotColorClass =
    color === 'green'
      ? 'text-[#22c55e]'
      : color === 'amber'
      ? 'text-[#f59e0b]'
      : color === 'red'
      ? 'text-[#ff3b3b]'
      : 'text-[#6b7280]';

  const pillBorderClass =
    color === 'green'
      ? 'border-[#22c55e]/20 bg-[#22c55e]/5'
      : color === 'amber'
      ? 'border-[#f59e0b]/20 bg-[#f59e0b]/5'
      : color === 'red'
      ? 'border-[#ff3b3b]/20 bg-[#ff3b3b]/5'
      : 'border-[#4b5563]/30 bg-[#374151]/10';

  const pillTextClass =
    color === 'green'
      ? 'text-[#22c55e]'
      : color === 'amber'
      ? 'text-[#f59e0b]'
      : color === 'red'
      ? 'text-[#ff3b3b]'
      : 'text-[#6b7280]';

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

        <button className="relative p-2 text-[#9ca3af] hover:text-white hover:bg-[#1e2530] rounded-lg transition-colors">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-[#ff3b3b] rounded-full"></span>
        </button>

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
          className="p-2 text-[#9ca3af] hover:text-[#ff3b3b] hover:bg-[#ff3b3b]/10 rounded-lg transition-colors"
          title="Cerrar sesión"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
}
