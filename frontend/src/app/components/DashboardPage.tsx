import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { ENSComplianceWidget } from './ENSComplianceWidget';
import { Activity, AlertTriangle, CheckCircle2, CalendarClock, Play, Pause, Zap, Power, Shield } from 'lucide-react';
import { useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { getCycleState, mapApiCycleToUI } from '../utils/cycleState';
import { useCycleStatus } from '../../hooks/useCycleStatus';
import { useCycleActions } from '../../hooks/useCycleActions';

const logEntries = [
  { time: '14:32:18', level: 'INFO', msg: 'Starting exploitation phase M8...' },
  { time: '14:32:19', level: 'SUCCESS', msg: 'Target 192.168.1.45:445 - SMB enumeration complete' },
  { time: '14:32:21', level: 'WARN', msg: 'CVE-2024-1234 detected on target web-server-03' },
  { time: '14:32:23', level: 'INFO', msg: 'Metasploit module exploit/windows/smb/ms17_010_eternalblue loaded' },
  { time: '14:32:25', level: 'SUCCESS', msg: 'Meterpreter session 1 opened (10.0.0.1:4444 -> 192.168.1.45:49158)' },
  { time: '14:32:27', level: 'INFO', msg: 'Gathering system information...' },
  { time: '14:32:29', level: 'WARN', msg: 'Privilege escalation required for full access' },
  { time: '14:32:31', level: 'INFO', msg: 'Running post-exploitation enumeration scripts' },
];

interface PipelineModule {
  id: string;
  label?: string;
  isHuman?: boolean;
  status: string;
}

export function DashboardPage() {
  const [showKillSwitchModal, setShowKillSwitchModal] = useState(false);
  const [killSwitchTotp, setKillSwitchTotp] = useState('');

  const { data: cycleData, loading: cycleLoading, error: cycleError, refetch } = useCycleStatus(30000);
  const cycleActions = useCycleActions();
  const cycle = cycleData ? mapApiCycleToUI(cycleData) : getCycleState();

  const isPausedManually = cycleData?.paused ?? false;
  const killSwitchActive = cycleData?.kill_switch_active ?? false;

  const handleConfirmKillSwitch = async () => {
    try {
      await cycleActions.activateKillSwitch(killSwitchTotp);
      refetch();
    } catch {
      return;
    }
    setShowKillSwitchModal(false);
    setKillSwitchTotp('');
  };

  const pipelineBlocks: { timeLabel: string; phaseLabel: string; blockIndex: 0 | 1 | 2; modules: PipelineModule[] }[] = [
    {
      timeLabel: 'LUNES 02:00',
      phaseLabel: 'Fase 1 — Inventario',
      blockIndex: 0,
      modules: cycle.phases
        ?.filter(p => p.phase_number === 1)
        .flatMap(p => p.modules)
        .map(m => ({ id: m.id, status: m.status })) ?? [
          { id: 'M1', status: 'pending' },
          { id: 'M2', status: 'pending' },
        ],
    },
    {
      timeLabel: 'MAR/MIÉ 00:00',
      phaseLabel: 'Fase 2 + Fase 3',
      blockIndex: 1,
      modules: cycle.phases
        ?.filter(p => p.phase_number === 2 || p.phase_number === 3)
        .flatMap(p => p.modules)
        .map(m => ({
          id: m.id,
          label: m.status === 'blocked' ? 'Revisión' : undefined,
          isHuman: m.status === 'blocked',
          status: m.status,
        })) ?? [
          { id: 'M3', status: 'pending' },
          { id: 'M8', status: 'pending' },
          { id: '👤', label: 'Revisión', isHuman: true, status: 'pending' },
        ],
    },
    {
      timeLabel: 'SAB/DOM 01:00',
      phaseLabel: 'Fase 4 + Fase 5',
      blockIndex: 2,
      modules: cycle.phases
        ?.filter(p => p.phase_number === 4 || p.phase_number === 5)
        .flatMap(p => p.modules)
        .map(m => ({ id: m.id, status: m.status })) ?? [
          { id: 'M4', status: 'pending' },
          { id: 'M7', status: 'pending' },
        ],
    },
  ];

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" cycleLabel={cycle.label} dotColor={cycle.dotColor} />

        {/* Connection error banner */}
        {cycleError && (
          <div className="flex items-center gap-2 px-6 py-2 bg-[#f59e0b]/10 border-b border-[#f59e0b]/30 text-xs text-[#f59e0b] font-mono">
            <span>⚠ Orchestrator no disponible — mostrando datos locales · {cycleError}</span>
            <button onClick={refetch} className="ml-auto underline">Reintentar</button>
          </div>
        )}

        {/* Kill Switch persistent banner */}
        {killSwitchActive && (
          <div className="flex items-center gap-3 px-6 py-3 bg-[#ff3b3b]/10 border-b border-[#ff3b3b]/30">
            <span className="text-[#ff3b3b] text-lg">🔴</span>
            <span className="text-sm text-[#ff3b3b] font-mono font-semibold flex-1">
              Kill Switch activo · Ciclo detenido · Reactivación manual requerida
            </span>
            <button
              onClick={async () => {
                try { await cycleActions.deactivateKillSwitch(); refetch(); } catch {}
              }}
              className="px-4 py-1.5 text-xs text-[#ff3b3b] border border-[#ff3b3b]/40 rounded-lg hover:bg-[#ff3b3b]/10 transition-colors font-semibold"
            >
              Reactivar ciclo
            </button>
          </div>
        )}

        {/* Manual pause banner */}
        {isPausedManually && !killSwitchActive && (
          <div className="flex items-center gap-3 px-6 py-3 bg-[#f59e0b]/10 border-b border-[#f59e0b]/30">
            <span className="text-[#f59e0b] text-base">⏸</span>
            <span className="text-sm text-[#f59e0b] font-mono flex-1">
              Ciclo pausado manualmente · Reanudación automática: Viernes 18:00
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={async () => {
                  try { await cycleActions.pauseCycle(); refetch(); } catch {}
                }}
                className="px-4 py-1.5 text-xs bg-[#f59e0b] text-[#0f1117] rounded-lg hover:bg-[#d97706] transition-colors font-semibold"
              >
                Reanudar ahora
              </button>
              <button className="px-4 py-1.5 text-xs text-[#f59e0b] border border-[#f59e0b]/40 rounded-lg hover:bg-[#f59e0b]/10 transition-colors">
                Ver motivo
              </button>
            </div>
          </div>
        )}

        {/* First-load skeleton */}
        {cycleLoading && !cycleData && (
          <div className="flex items-center justify-center h-32 text-[#9ca3af] text-sm font-mono">
            Conectando con orchestrator...
          </div>
        )}

        <main className="flex-1 overflow-auto p-6 space-y-6">
          {/* KPI Cards */}
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#00d4ff]/10 rounded-lg flex items-center justify-center">
                  <Activity className="w-5 h-5 text-[#00d4ff]" />
                </div>
              </div>
              <div className="text-3xl font-semibold text-white mb-1">47</div>
              <div className="text-sm text-[#9ca3af]">Total Assets</div>
            </div>

            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#ff3b3b]/10 rounded-lg flex items-center justify-center">
                  <AlertTriangle className="w-5 h-5 text-[#ff3b3b]" />
                </div>
              </div>
              <div className="text-3xl font-semibold text-white mb-1">12</div>
              <div className="text-sm text-[#9ca3af]">Open Vulnerabilities</div>
            </div>

            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#22c55e]/10 rounded-lg flex items-center justify-center">
                  <CheckCircle2 className="w-5 h-5 text-[#22c55e]" />
                </div>
              </div>
              <div className="text-3xl font-semibold text-white mb-1">78%</div>
              <div className="text-sm text-[#9ca3af]">ENS Compliance</div>
            </div>

            {/* Dynamic Ciclo Semanal card */}
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#f59e0b]/10 rounded-lg flex items-center justify-center">
                  <CalendarClock className="w-5 h-5 text-[#f59e0b]" />
                </div>
              </div>
              <div className="text-xs text-[#9ca3af] mb-1 font-mono">{cycle.weekLabel}</div>
              <div className="text-lg font-semibold text-white mb-1">{cycle.phase}</div>
              <div className="text-sm text-[#f59e0b] font-mono">{cycle.timeRemaining}</div>
            </div>
          </div>

          <ENSComplianceWidget />

          {/* Temporal pipeline */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-5">Pipeline Semanal</h2>

            <div className="flex items-stretch gap-3">
              {pipelineBlocks.map((block, i) => {
                const isActive = block.blockIndex === cycle.activeBlock;
                return (
                  <div key={i} className="flex items-center gap-3 flex-1">
                    <div
                      className={`flex-1 rounded-lg p-4 border transition-all ${
                        isActive
                          ? 'border-[#00d4ff]/40 shadow-[0_0_12px_rgba(0,212,255,0.15)] bg-[#0f1117]'
                          : 'border-[#1e2530] bg-[#0f1117]'
                      }`}
                    >
                      <div className="text-xs text-[#9ca3af] font-mono mb-1">{block.timeLabel}</div>
                      <div className="text-sm text-white mb-3">{block.phaseLabel}</div>
                      <div className="flex flex-wrap gap-2">
                        {block.modules.map((mod) => (
                          <span
                            key={mod.id}
                            className={`px-2.5 py-1 rounded text-xs font-mono font-semibold border transition-all ${
                              mod.isHuman || mod.status === 'blocked'
                                ? 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30'
                                : mod.status === 'offline'
                                ? 'bg-[#ff3b3b]/10 text-[#ff3b3b] border-[#ff3b3b]/30'
                                : mod.status === 'completed'
                                ? 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/20'
                                : mod.status === 'in_progress' || mod.status === 'in-progress'
                                ? 'bg-[#00d4ff]/10 text-[#00d4ff] border-[#00d4ff]/30 animate-pulse'
                                : 'bg-[#374151] text-[#6b7280] border-[#4b5563]'
                            }`}
                          >
                            {mod.id}{mod.label ? ` ${mod.label}` : ''}
                          </span>
                        ))}
                      </div>
                    </div>
                    {i < pipelineBlocks.length - 1 && (
                      <span className="text-[#4b5563] text-xl select-none">→</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Live log */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-[#1e2530]">
              <h2 className="text-lg font-semibold text-white">Live Execution Log</h2>
              <div className="flex items-center gap-2 text-xs text-[#22c55e]">
                <div className="w-2 h-2 bg-[#22c55e] rounded-full animate-pulse"></div>
                LIVE
              </div>
            </div>

            <div className="bg-[#0f1117] p-4 h-80 overflow-auto font-mono text-sm">
              {logEntries.map((entry, i) => (
                <div key={i} className="py-1 hover:bg-[#1a1d27]/50">
                  <span className="text-[#6b7280]">[{entry.time}]</span>{' '}
                  <span className={
                    entry.level === 'SUCCESS' ? 'text-[#22c55e]' :
                    entry.level === 'WARN' ? 'text-[#f59e0b]' :
                    entry.level === 'ERROR' ? 'text-[#ff3b3b]' :
                    'text-[#00d4ff]'
                  }>{entry.level}</span>{' '}
                  <span className="text-[#e5e7eb]">{entry.msg}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-3">
            <button className="px-6 py-2.5 bg-[#22c55e] hover:bg-[#16a34a] text-white font-semibold rounded-lg transition-colors flex items-center gap-2">
              <Play className="w-4 h-4" />
              Launch
            </button>

            <button
              onClick={async () => {
                try { await cycleActions.pauseCycle(); refetch(); } catch {}
              }}
              className={`px-6 py-2.5 font-semibold rounded-lg transition-colors flex items-center gap-2 ${
                isPausedManually
                  ? 'bg-[#f59e0b] text-[#0f1117] hover:bg-[#d97706]'
                  : 'bg-[#f59e0b] hover:bg-[#d97706] text-white'
              }`}
            >
              <Pause className="w-4 h-4" />
              {isPausedManually ? 'Pausado' : 'Pause'}
            </button>

            <button className="px-6 py-2.5 bg-[#00d4ff]/10 hover:bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/30 font-semibold rounded-lg transition-colors flex items-center gap-2">
              <Zap className="w-4 h-4" />
              Emergency Scan
            </button>

            <div className="flex-1" />

            <button
              onClick={() => setShowKillSwitchModal(true)}
              className="px-6 py-2.5 bg-[#ff3b3b] hover:bg-[#dc2626] text-white font-semibold rounded-lg transition-colors flex items-center gap-2 shadow-lg shadow-[#ff3b3b]/30"
            >
              <Power className="w-4 h-4" />
              Kill Switch
            </button>
          </div>
        </main>
      </div>

      {/* Kill Switch confirmation modal */}
      <Dialog.Root open={showKillSwitchModal} onOpenChange={setShowKillSwitchModal}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-[#1a1d27] border border-[#ff3b3b]/30 rounded-lg p-6 shadow-2xl shadow-[#ff3b3b]/10">
            <Dialog.Title className="text-xl font-semibold text-[#ff3b3b] mb-3 flex items-center gap-2">
              <Shield className="w-5 h-5" />
              ⚠ Activar Kill Switch
            </Dialog.Title>
            <Dialog.Description className="text-sm text-[#9ca3af] mb-6 leading-relaxed">
              Esta acción detiene completamente el ciclo semanal. No se reanudará automáticamente.
              Requiere reactivación manual por el Responsable de Sistemas.
            </Dialog.Description>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
                  Código TOTP (6 dígitos)
                </label>
                <input
                  type="text"
                  value={killSwitchTotp}
                  onChange={(e) => setKillSwitchTotp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-4 py-2.5 text-white placeholder:text-[#6b7280] focus:outline-none focus:border-[#ff3b3b] focus:ring-1 focus:ring-[#ff3b3b] transition-colors font-mono tracking-widest text-center text-lg"
                  placeholder="000000"
                  maxLength={6}
                />
              </div>

              <button
                onClick={handleConfirmKillSwitch}
                disabled={killSwitchTotp.length !== 6}
                className="w-full bg-[#ff3b3b] hover:bg-[#dc2626] disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg transition-colors"
              >
                Confirmar Kill Switch
              </button>

              <Dialog.Close asChild>
                <button className="w-full bg-transparent border border-[#1e2530] hover:bg-[#1e2530] text-[#9ca3af] hover:text-white font-semibold py-2.5 rounded-lg transition-colors">
                  Cancelar
                </button>
              </Dialog.Close>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
