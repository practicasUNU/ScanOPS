import { Bell, Shield } from 'lucide-react';
import { getCycleState } from '../utils/cycleState';

export function TopBar({ role = 'System Manager' }: { role?: string }) {
  const cycle = getCycleState();

  const dotColorClass =
    cycle.dotColor === 'green'
      ? 'text-[#22c55e]'
      : cycle.dotColor === 'amber'
      ? 'text-[#f59e0b]'
      : 'text-[#6b7280]';

  const pillBorderClass =
    cycle.dotColor === 'green'
      ? 'border-[#22c55e]/20 bg-[#22c55e]/5'
      : cycle.dotColor === 'amber'
      ? 'border-[#f59e0b]/20 bg-[#f59e0b]/5'
      : 'border-[#4b5563]/30 bg-[#374151]/10';

  const pillTextClass =
    cycle.dotColor === 'green'
      ? 'text-[#22c55e]'
      : cycle.dotColor === 'amber'
      ? 'text-[#f59e0b]'
      : 'text-[#6b7280]';

  return (
    <header className="h-16 bg-[#1a1d27] border-b border-[#1e2530] flex items-center justify-between px-6">
      <div className="flex items-center gap-4">
        <h1 className="text-lg font-semibold text-white">{role}</h1>
      </div>

      {/* Centered cycle status pill */}
      <div className={`flex items-center gap-2 px-3 py-1.5 border rounded-full font-mono text-xs ${pillBorderClass} ${pillTextClass}`}>
        <span className={`text-sm leading-none ${dotColorClass} ${cycle.dotColor === 'green' ? 'animate-pulse' : ''}`}>
          {cycle.dot}
        </span>
        <span>{cycle.label}</span>
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
      </div>
    </header>
  );
}
