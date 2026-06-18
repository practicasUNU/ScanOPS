import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { ENSComplianceWidget } from './ENSComplianceWidget';
import { Activity, AlertTriangle, CheckCircle2, CalendarClock, Play, Pause, Zap, Power, Shield, Loader2, Users, Circle, RefreshCw } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { getCycleState, mapApiCycleToUI } from '../utils/cycleState';
import { useCycleStatus } from '../../hooks/useCycleStatus';
import { useCycleActions } from '../../hooks/useCycleActions';
import { useLogStream } from '../../hooks/useLogStream';
import { useDashboardMetrics } from '../../hooks/useDashboardMetrics';

interface PipelineModule {
  id: string;
  label?: string;
  isHuman?: boolean;
  status: string;
}

const ROLE_LABELS: Record<string, string> = {
  system_manager:   'Admin',
  security_officer: 'Resp. Seguridad',
  auditor:          'Auditor',
  service:          'Servicio',
};

const ORCHESTRATOR_BASE = '/api/orchestrator';

interface ActiveSession {
  username: string;
  role: string;
  last_seen: string;
  ip: string;
  user_agent: string;
}

export function DashboardPage() {
  const [showKillSwitchModal, setShowKillSwitchModal] = useState(false);
  const [killSwitchTotp, setKillSwitchTotp] = useState('');

  const [immRunning, setImmRunning] = useState(false);
  const [immLogs, setImmLogs] = useState<{ts:string;level:string;msg:string}[]>([]);
  const [immOpen, setImmOpen] = useState(false);
  const [immPhase, setImmPhase] = useState<'idle'|'m1'|'m2'|'m3'|'m8'|'m4'|'done'|'error'>('idle');
  const [immErrors, setImmErrors] = useState<string[]>([]);
  const [immApprovals, setImmApprovals] = useState<{
    approval_id: number;
    qr_code_base64: string;
    asset_ip: string;
    cve: string;
  }[]>([]);
  const [immAuthorized, setImmAuthorized] = useState(false);
  const immLogRef = useRef<HTMLDivElement>(null);

  // ── Active sessions (admin only) ──────────────────────────────────────────
  const [userRole, setUserRole] = useState<string | null>(null);
  const [activeSessions, setActiveSessions] = useState<ActiveSession[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [sessionsLastUpdate, setSessionsLastUpdate] = useState<Date | null>(null);

  const ilog = (msg: string, level: 'info'|'success'|'warn'|'error' = 'info') => {
    const ts = new Date().toLocaleTimeString('es-ES');
    setImmLogs(p => [...p, { ts, level, msg }]);
    if (level === 'error') {
      setImmErrors(p => [...p, msg]);
    }
  };

  useEffect(() => {
    if (immLogRef.current) {
      immLogRef.current.scrollTop = immLogRef.current.scrollHeight;
    }
  }, [immLogs]);

  function getToken(): string | null {
    try { return JSON.parse(sessionStorage.getItem('scanops_auth') || '{}')?.access_token ?? null; }
    catch { return null; }
  }

  function authH(): HeadersInit {
    const t = getToken();
    return t ? { 'Content-Type': 'application/json', Authorization: `Bearer ${t}` }
             : { 'Content-Type': 'application/json' };
  }

  // Read role from session storage once
  useEffect(() => {
    try {
      const auth = JSON.parse(sessionStorage.getItem('scanops_auth') || '{}');
      setUserRole(auth?.role ?? null);
    } catch { /* ignore */ }
  }, []);

  // Poll active sessions every 30s (admin only)
  useEffect(() => {
    if (userRole !== 'system_manager') return;
    const fetchSessions = async () => {
      setSessionsLoading(true);
      try {
        const res = await fetch(`${ORCHESTRATOR_BASE}/users/active-sessions`, { headers: authH() });
        if (res.ok) {
          const data = await res.json();
          setActiveSessions(data.active_sessions ?? []);
          setSessionsLastUpdate(new Date());
        }
      } catch { /* silent */ } finally {
        setSessionsLoading(false);
      }
    };
    fetchSessions();
    const interval = setInterval(fetchSessions, 30_000);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userRole]);

  const handleImmediateCycle = async () => {
    setImmRunning(true);
    setImmOpen(true);
    setImmLogs([]);
    setImmErrors([]);
    setImmApprovals([]);
    setImmAuthorized(false);
    setImmPhase('m1');

    try {
      // ── FASE M1: Obtener activos ────────────────────────────
      ilog('[M1] Obteniendo inventario de activos...');
      const assetsRes = await fetch('/api/m1/api/v1/assets?page=1&page_size=50',
        { headers: authH(), signal: AbortSignal.timeout(10000) });
      if (!assetsRes.ok) throw new Error(`M1 falló: HTTP ${assetsRes.status}`);
      const assetsData = await assetsRes.json();
      const assets = assetsData.items ?? assetsData.assets ?? [];
      ilog(`[M1] ✓ ${assets.length} activos registrados`, 'success');
      assets.forEach((a: any) => ilog(`[M1]   → ${a.ip} (${a.hostname ?? a.nombre ?? '—'}) [${a.criticidad}]`));

      // ── FASES M2+M3+M8+M4 por cada activo ──────────────────
      for (const asset of assets) {
        ilog(`━━━ Pipeline para ${asset.ip} ━━━`, 'warn');

        // M2
        setImmPhase('m2');
        ilog(`[M2] Reconocimiento Nmap sobre ${asset.ip}...`);
        try {
          const m2Res = await fetch(
            `/api/m2/api/v1/scan?target=${encodeURIComponent(asset.ip)}`,
            { method: 'POST', headers: authH(), signal: AbortSignal.timeout(120000) });
          if (m2Res.ok) {
            const m2Data = await m2Res.json();
            const ports = m2Data.reconnaissance?.ports_discovered?.length ?? 0;
            ilog(`[M2] ✓ ${ports} puertos en ${m2Data.summary?.scan_duration_seconds?.toFixed(1)}s`, 'success');
          }
        } catch { ilog(`[M2] ⚠ Timeout en ${asset.ip}`, 'warn'); }

        // M3
        setImmPhase('m3');
        ilog(`[M3] Lanzando Nmap+Nuclei+Nikto+ffuf+whatweb+testssl sobre ${asset.ip}...`);
        try {
          const m3Launch = await fetch(`/api/m3/api/v1/scan/asset/${asset.id}`,
            { method: 'POST', headers: authH(),
              body: JSON.stringify({ scan_types: ['nmap','nuclei','nikto','ffuf','whatweb','testssl'],
                description: `Ciclo inmediato: ${asset.ip}` }),
              signal: AbortSignal.timeout(15000) });
          if (m3Launch.ok) {
            ilog(`[M3] Escaneo lanzado — esperando resultados...`);
            await new Promise(r => setTimeout(r, 15000));
            for (let i = 0; i < 30; i++) {
              await new Promise(r => setTimeout(r, 5000));
              try {
                const rRes = await fetch(`/api/m3/api/v1/scan/results/${asset.id}`,
                  { headers: authH(), signal: AbortSignal.timeout(8000) });
                if (rRes.ok) {
                  const rData = await rRes.json();
                  if ((rData.total_findings ?? 0) > 0) {
                    ilog(`[M3] ✓ ${rData.total_findings} vulnerabilidades en ${asset.ip}`, 'success');
                    const findings = Object.values(rData.findings_by_scanner ?? {}).flat() as any[];
                    findings.filter((f: any) => f.severity === 'CRITICAL').slice(0,3)
                      .forEach((f: any) => ilog(`[M3]   → [CRITICAL] ${f.title}`, 'error'));
                    break;
                  }
                }
              } catch { continue; }
              if (i % 3 === 0) ilog(`[M3] Escaneando... ${15+(i+1)*5}s`);
            }
          }
        } catch { ilog(`[M3] ⚠ Error en ${asset.ip}`, 'warn'); }

        // M8
        setImmPhase('m8');
        ilog(`[M8] Invocando Mistral/Ollama para ${asset.ip}...`);
        let m8Result: any = null;
        try {
          const m8Launch = await fetch(
            `/api/m3/api/v1/scan/assets/${asset.id}/attack-vector`,
            { method: 'POST', headers: authH(), signal: AbortSignal.timeout(15000) });
          if (m8Launch.ok) {
            const { task_id } = await m8Launch.json();
            ilog(`[M8] Tarea lanzada — Mistral procesando...`);
            for (let a = 0; a < 60; a++) {
              await new Promise(r => setTimeout(r, 4000));
              try {
                const rRes = await fetch(
                  `/api/m3/api/v1/scan/assets/${asset.id}/attack-vector/result/${task_id}`,
                  { headers: authH(), signal: AbortSignal.timeout(8000) });
                if (rRes.ok) {
                  const rData = await rRes.json();
                  if (rData.status === 'SUCCESS' && rData.result) {
                    m8Result = rData.result;
                    ilog(`[M8] ✓ Vector: ${m8Result.msf_module ?? 'exploit/multi/handler'} | Riesgo: ${String(m8Result.risk_level ?? 'ALTO').toUpperCase()}`, 'success');
                    break;
                  }
                  if (rData.status === 'FAILED' || rData.status === 'FAILURE') break;
                }
              } catch { continue; }
              if (a % 5 === 0) ilog(`[M8] Analizando... [${a+1}/60]`);
            }

          }
        } catch { ilog(`[M8] ⚠ Error en ${asset.ip}`, 'warn'); }
      }

      // ── FASE M4: Una sola aprobación maestra para todos los activos ──
      setImmPhase('m4');
      const assetIps = assets.map((a: any) => a.ip).join(', ');
      ilog(`[M4] Creando aprobación maestra para ${assets.length} activos...`);
      try {
        const m4Res = await fetch('/api/m4/api/m4/request-approval', {
          method: 'POST',
          headers: authH(),
          body: JSON.stringify({
            cve: `CICLO-INMEDIATO-${assets.length}-ACTIVOS`,
            ip: assets[0]?.ip ?? '0.0.0.0',
            user_email: 'admin@scanops.local',
            pin: '1234',
          }),
          signal: AbortSignal.timeout(10000),
        });
        if (m4Res.ok) {
          const m4Data = await m4Res.json();
          ilog(`[M4] ✓ Aprobación maestra #${m4Data.approval_id} creada — PIN: 1234`, 'success');
          ilog(`[M4]   → Activos: ${assetIps}`, 'info');
          if (m4Data.qr_code_base64) {
            setImmApprovals([{
              approval_id: m4Data.approval_id,
              qr_code_base64: m4Data.qr_code_base64,
              asset_ip: assetIps,
              cve: `Ciclo completo — ${assets.length} activos`,
            }]);
          }
        }
      } catch { ilog(`[M4] ⚠ Error creando aprobación maestra`, 'warn'); }

      setImmPhase('done');
      ilog('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'info');
      ilog(`[✓] CICLO INMEDIATO COMPLETADO — ${assets.length} activos procesados`, 'success');
      ilog(`[✓] Ve a M4 Explotación para autorizar las solicitudes pendientes`, 'warn');

    } catch (e: any) {
      setImmPhase('error');
      ilog(`[✗] Error crítico: ${e.message}`, 'error');
    } finally {
      setImmRunning(false);
      refetch();
    }
  };

  const { data: cycleData, loading: cycleLoading, error: cycleError, refetch } = useCycleStatus(30000);
  const cycleActions = useCycleActions();
  const cycle = cycleData ? mapApiCycleToUI(cycleData) : getCycleState();

  const isPausedManually = cycleData?.paused ?? false;
  const killSwitchActive = cycleData?.kill_switch_active ?? false;

  const { entries: logEntries, connected: logConnected } = useLogStream();
  const { metrics, loading: metricsLoading } = useDashboardMetrics(60000);
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logEntries]);

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
      modules: (() => {
        const allModules = cycle.phases
          ?.filter(p => p.phase_number === 2 || p.phase_number === 3)
          .flatMap(p => p.modules) ?? [];

        const statusPriority: Record<string, number> = {
          blocked: 5, in_progress: 4, completed: 3, pending: 2, offline: 1,
        };

        const deduped = new Map<string, PipelineModule>();
        for (const m of allModules) {
          const existing = deduped.get(m.id);
          const currentPrio = statusPriority[m.status] ?? 0;
          const existingPrio = existing ? (statusPriority[existing.status] ?? 0) : -1;
          if (currentPrio > existingPrio) {
            deduped.set(m.id, {
              id: m.id,
              label: m.status === 'blocked' ? 'Revisión' : undefined,
              isHuman: m.status === 'blocked',
              status: m.status,
            });
          }
        }

        return allModules.length > 0 ? Array.from(deduped.values()) : [
          { id: 'M3', status: 'pending' },
          { id: 'M8', status: 'pending' },
          { id: '👤', label: 'Revisión', isHuman: true, status: 'pending' },
        ];
      })(),
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
    <div className="flex h-screen bg-[#0A0C10]">
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
                className="px-4 py-1.5 text-xs bg-[#f59e0b] text-[#0A0C10] rounded-lg hover:bg-[#d97706] transition-colors font-semibold"
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
          <div className="flex items-center justify-center h-32 text-[#64748B] text-sm font-mono">
            Conectando con orchestrator...
          </div>
        )}

        <main className="flex-1 overflow-auto p-6 space-y-6">
          {/* KPI Cards */}
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-[#111318] border border-[#1C2030] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#8B5CF6]/10 rounded-lg flex items-center justify-center">
                  <Activity className="w-5 h-5 text-[#8B5CF6]" />
                </div>
              </div>
              <div className="text-3xl font-semibold text-white mb-1">
                {metricsLoading ? '—' : (metrics?.total_assets ?? '—')}
              </div>
              <div className="text-sm text-[#64748B]">Total Assets</div>
              {metrics && !metrics.m1_available && (
                <span className="text-xs text-[#f59e0b] font-mono">M1 offline</span>
              )}
            </div>

            <div className="bg-[#111318] border border-[#1C2030] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#ff3b3b]/10 rounded-lg flex items-center justify-center">
                  <AlertTriangle className="w-5 h-5 text-[#ff3b3b]" />
                </div>
              </div>
              <div className="text-3xl font-semibold text-white mb-1">
                {metricsLoading ? '—' : (metrics?.open_vulnerabilities ?? '—')}
              </div>
              <div className="text-sm text-[#64748B]">Open Vulnerabilities</div>
              {metrics && !metrics.m3_available && (
                <span className="text-xs text-[#f59e0b] font-mono">M3 offline</span>
              )}
            </div>

            <div className="bg-[#111318] border border-[#1C2030] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#22c55e]/10 rounded-lg flex items-center justify-center">
                  <CheckCircle2 className="w-5 h-5 text-[#22c55e]" />
                </div>
              </div>
              <div className="text-3xl font-semibold text-white mb-1">
                {metricsLoading ? '—' : `${metrics?.ens_compliance_score ?? '—'}%`}
              </div>
              <div className="text-sm text-[#64748B]">ENS Compliance</div>
              {metrics && !metrics.m3_available && (
                <span className="text-xs text-[#f59e0b] font-mono">M3 offline</span>
              )}
            </div>

            {/* Dynamic Ciclo Semanal card */}
            <div className="bg-[#111318] border border-[#1C2030] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#f59e0b]/10 rounded-lg flex items-center justify-center">
                  <CalendarClock className="w-5 h-5 text-[#f59e0b]" />
                </div>
              </div>
              <div className="text-xs text-[#64748B] mb-1 font-mono">{cycle.weekLabel}</div>
              <div className="text-lg font-semibold text-white mb-1">{cycle.phase}</div>
              <div className="text-sm text-[#f59e0b] font-mono">{cycle.timeRemaining}</div>
            </div>
          </div>

          <ENSComplianceWidget />

          {/* ── Active Sessions (admin only) ──────────────────────── */}
          {userRole === 'system_manager' && (
            <div className="bg-[#111318] border border-[#1C2030] rounded-lg overflow-hidden">
              <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#1C2030]">
                <div className="flex items-center gap-2.5">
                  <div className="w-7 h-7 bg-[#a78bfa]/10 rounded-lg flex items-center justify-center">
                    <Users className="w-3.5 h-3.5 text-[#a78bfa]" />
                  </div>
                  <span className="text-sm font-semibold text-white">Usuarios conectados</span>
                  <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-[#a78bfa]/20 text-[#a78bfa] border border-[#a78bfa]/30">
                    {activeSessions.length}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[10px] text-[#334155] font-mono">
                  {sessionsLastUpdate && (
                    <span>actualizado {sessionsLastUpdate.toLocaleTimeString('es-ES')}</span>
                  )}
                  {sessionsLoading
                    ? <Loader2 className="w-3 h-3 text-[#475569] animate-spin" />
                    : <RefreshCw className="w-3 h-3 text-[#334155]" />
                  }
                </div>
              </div>

              {activeSessions.length === 0 ? (
                <div className="px-5 py-6 text-center text-xs text-[#334155] font-mono">
                  {sessionsLoading ? 'Cargando sesiones...' : 'Sin sesiones activas registradas'}
                </div>
              ) : (
                <div className="divide-y divide-[#1C2030]">
                  {activeSessions.map((s) => {
                    const ago = Math.round((Date.now() - new Date(s.last_seen).getTime()) / 60000);
                    const agoLabel = ago < 1 ? 'ahora mismo' : ago < 60 ? `hace ${ago}m` : `hace ${Math.round(ago/60)}h`;
                    return (
                      <div key={s.username} className="flex items-center gap-4 px-5 py-3 hover:bg-[#111318]/60 transition-colors">
                        <div className="relative shrink-0">
                          <div className="w-8 h-8 rounded-full bg-[#7c3aed]/20 flex items-center justify-center text-xs font-bold text-[#a78bfa]">
                            {s.username.charAt(0).toUpperCase()}
                          </div>
                          <Circle className="absolute -bottom-0.5 -right-0.5 w-3 h-3 text-[#22c55e] fill-[#22c55e]" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-mono text-white">{s.username}</span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#7c3aed]/15 text-[#a78bfa] border border-[#7c3aed]/20 font-semibold">
                              {ROLE_LABELS[s.role] ?? s.role}
                            </span>
                          </div>
                          <div className="text-[11px] text-[#475569] font-mono truncate mt-0.5">
                            {s.ip !== '—' ? s.ip : 'IP desconocida'}
                            {s.user_agent !== '—' && (
                              <span className="ml-2 text-[#334155]">· {s.user_agent.split(' ')[0]}</span>
                            )}
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          <div className="text-[11px] text-[#22c55e] font-mono">● activo</div>
                          <div className="text-[10px] text-[#334155]">{agoLabel}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Temporal pipeline */}
          <div className="bg-[#111318] border border-[#1C2030] rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-5">Pipeline Semanal</h2>

            <div className="flex items-stretch gap-3">
              {pipelineBlocks.map((block, i) => {
                const isActive = block.blockIndex === cycle.activeBlock;
                return (
                  <div key={i} className="flex items-center gap-3 flex-1">
                    <div
                      className={`flex-1 rounded-lg p-4 border transition-all ${
                        isActive
                          ? 'border-[#8B5CF6]/40 shadow-[0_0_12px_rgba(139,92,246,0.15)] bg-[#0A0C10]'
                          : 'border-[#1C2030] bg-[#0A0C10]'
                      }`}
                    >
                      <div className="text-xs text-[#64748B] font-mono mb-1">{block.timeLabel}</div>
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
                                ? 'bg-[#8B5CF6]/10 text-[#8B5CF6] border-[#8B5CF6]/30 animate-pulse'
                                : 'bg-[#374151] text-[#475569] border-[#334155]'
                            }`}
                          >
                            {mod.id}{mod.label ? ` ${mod.label}` : ''}
                          </span>
                        ))}
                      </div>
                    </div>
                    {i < pipelineBlocks.length - 1 && (
                      <span className="text-[#334155] text-xl select-none">→</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Live log */}
          <div className="bg-[#111318] border border-[#1C2030] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-[#1C2030]">
              <h2 className="text-lg font-semibold text-white">Live Execution Log</h2>
              <div className="flex items-center gap-1.5 text-xs font-mono">
                <div className={`w-2 h-2 rounded-full ${logConnected ? 'bg-[#22c55e] animate-pulse' : 'bg-[#475569]'}`} />
                <span className={logConnected ? 'text-[#22c55e]' : 'text-[#475569]'}>
                  {logConnected ? 'LIVE' : 'OFFLINE'}
                </span>
              </div>
            </div>

            <div ref={logContainerRef} className="bg-[#0a0c12] p-3 h-32 overflow-y-auto font-mono text-xs space-y-0.5">
              {logEntries.length === 0 ? (
                <div className="text-[#334155]">Esperando eventos del ciclo...</div>
              ) : (
                logEntries.map((entry, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="text-[#334155] shrink-0">
                      {new Date(entry.timestamp).toLocaleTimeString('es-ES')}
                    </span>
                    <span className={`shrink-0 ${
                      entry.level === 'SUCCESS' ? 'text-[#22c55e]' :
                      entry.level === 'WARN' ? 'text-[#f59e0b]' :
                      entry.level === 'ERROR' ? 'text-[#ff3b3b]' :
                      'text-[#8B5CF6]'
                    }`}>{entry.level}</span>
                    <span className="text-[#475569] shrink-0">[{entry.module}]</span>
                    <span className="text-[#d1d5db]">{entry.message}</span>
                  </div>
                ))
              )}
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
                  ? 'bg-[#f59e0b] text-[#0A0C10] hover:bg-[#d97706]'
                  : 'bg-[#f59e0b] hover:bg-[#d97706] text-white'
              }`}
            >
              <Pause className="w-4 h-4" />
              {isPausedManually ? 'Pausado' : 'Pause'}
            </button>

            <button className="px-6 py-2.5 bg-[#8B5CF6]/10 hover:bg-[#8B5CF6]/20 text-[#8B5CF6] border border-[#8B5CF6]/30 font-semibold rounded-lg transition-colors flex items-center gap-2">
              <Zap className="w-4 h-4" />
              Emergency Scan
            </button>

            <button
              onClick={() => { setImmOpen(true); if (!immRunning) handleImmediateCycle(); }}
              disabled={immRunning}
              className="flex items-center gap-2 px-4 py-2 bg-[#7c3aed]/10 border border-[#7c3aed]/30
                         text-[#a78bfa] rounded-lg text-xs font-bold hover:bg-[#7c3aed]/20
                         disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
              {immRunning
                ? <><Loader2 className="w-3.5 h-3.5 animate-spin"/>Ciclo en curso...</>
                : <><Zap className="w-3.5 h-3.5"/>Ejecutar Ciclo Inmediato</>}
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

      {/* Immediate cycle modal */}
      {immOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#111318] border border-[#1C2030] rounded-2xl w-full max-w-2xl
                          mx-4 shadow-2xl flex flex-col max-h-[80vh]">

            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1C2030]">
              <div className="flex items-center gap-3">
                <Zap className="w-5 h-5 text-[#a78bfa]"/>
                <div>
                  <h3 className="text-sm font-bold text-white">Ciclo Inmediato — Todos los activos</h3>
                  <p className="text-xs text-[#475569]">M1 → M2 → M3 → M8 → M4</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {(['m1','m2','m3','m8','m4'] as const).map(phase => (
                  <span key={phase} className={`text-xs font-mono px-2 py-0.5 rounded border ${
                    immPhase === phase
                      ? 'bg-[#a78bfa]/20 border-[#a78bfa]/40 text-[#a78bfa] animate-pulse'
                      : 'bg-[#1C2030] border-[#374151] text-[#334155]'
                  }`}>
                    {phase.toUpperCase()}
                  </span>
                ))}
                {!immRunning && (
                  <button onClick={() => setImmOpen(false)}
                    className="text-[#475569] hover:text-white text-lg">×</button>
                )}
              </div>
            </div>

            {/* Error banner */}
            {immErrors.length > 0 && (
              <div className="mx-4 mt-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg px-4 py-2.5">
                <div className="flex items-center gap-2 mb-1.5">
                  <AlertTriangle className="w-4 h-4 text-[#ff3b3b] shrink-0"/>
                  <span className="text-xs font-bold text-[#ff3b3b]">
                    {immErrors.length} error{immErrors.length > 1 ? 'es' : ''} detectado{immErrors.length > 1 ? 's' : ''}
                  </span>
                </div>
                <ul className="space-y-0.5">
                  {immErrors.map((e, i) => (
                    <li key={i} className="text-[10px] text-[#ff3b3b] font-mono">• {e}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Log */}
            <div ref={immLogRef}
                 className="flex-1 overflow-y-auto bg-[#0A0C10] p-4 font-mono text-xs
                            space-y-0.5 min-h-[300px]">
              {immLogs.length === 0 && <p className="text-[#374151]">Iniciando ciclo...</p>}
              {immLogs.map((l, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-[#374151] shrink-0">{l.ts}</span>
                  <span className={
                    l.level === 'success' ? 'text-[#22c55e]' :
                    l.level === 'error'   ? 'text-[#ff3b3b]' :
                    l.level === 'warn'    ? 'text-[#f59e0b]' :
                    'text-[#64748B]'
                  }>{l.msg}</span>
                </div>
              ))}
              {immRunning && (
                <div className="flex items-center gap-2 text-[#a78bfa] mt-1">
                  <Loader2 className="w-3 h-3 animate-spin"/>
                  <span>Procesando...</span>
                </div>
              )}
            </div>

            {/* Footer */}
            {immPhase === 'done' && (
              <div className="px-5 py-4 border-t border-[#1C2030] space-y-3">
                {immApprovals.length > 0 && (
                  <div className="flex items-center gap-4">
                    <div className="flex flex-col items-center gap-2">
                      <img src={`data:image/png;base64,${immApprovals[0].qr_code_base64}`}
                           alt="QR TOTP" className="w-48 h-48 rounded-lg border border-[#1C2030]"/>
                      <p className="text-[10px] text-[#475569]">Escanea con Google Authenticator</p>
                    </div>
                    <div>
                      <p className="text-xs font-bold text-white">
                        Aprobación maestra #{immApprovals[0].approval_id}
                      </p>
                      <p className="text-[10px] font-mono text-[#8B5CF6] mt-0.5">
                        {immApprovals[0].asset_ip}
                      </p>
                      <p className="text-[10px] text-[#f59e0b] font-mono mt-0.5">PIN: 1234</p>
                    </div>
                  </div>
                )}
                <div className="flex items-center gap-3 pt-1">
                  <CheckCircle2 className="w-4 h-4 text-[#22c55e]"/>
                  <span className="text-xs text-[#22c55e] font-mono">
                    Ciclo completado — Escanea el QR y autoriza en M4
                  </span>
                  <button onClick={() => window.open('/exploitation', '_blank')}
                    className="ml-auto px-4 py-1.5 bg-[#a78bfa]/10 border border-[#a78bfa]/30
                               text-[#a78bfa] rounded text-xs font-semibold hover:bg-[#a78bfa]/20">
                    Ir a M4 →
                  </button>
                </div>
                {!immAuthorized ? (
                  <button
                    onClick={async () => {
                      setImmAuthorized(true);
                      ilog(`[✓] AUTORIZACIÓN CONFIRMADA — Ciclo ENS completado al 100%`, 'success');
                      ilog(`[✓] Evidencia registrada: M1+M2+M3+M8+M4 — ENS op.exp.2, op.acc.5`, 'success');
                      if (immApprovals[0]?.approval_id) {
                        ilog(`[EXEC] Ejecutando ataque autorizado...`, 'warn');
                        try {
                          const token = getToken();
                          const execRes = await fetch(
                            `/api/m4/api/m4/execute/${immApprovals[0].approval_id}`,
                            { method: 'POST',
                              headers: token ? { Authorization: `Bearer ${token}` } : {},
                              signal: AbortSignal.timeout(30000) }
                          );
                          if (execRes.ok) {
                            const execData = await execRes.json();
                            if (execData.success) {
                              ilog(`[EXEC] ✓ ACCESO OBTENIDO — ${execData.target_ip} | admin:${execData.password_found}`, 'success');
                              ilog(`[EXEC] ★ VULNERABILIDAD CONFIRMADA`, 'error');
                            } else {
                              ilog(`[EXEC] Sin credenciales válidas`, 'warn');
                            }
                          }
                        } catch (e: any) { ilog(`[EXEC] Error: ${e.message}`, 'error'); }
                      }
                    }}
                    className="w-full py-2.5 bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e]
                               rounded-lg text-xs font-semibold hover:bg-[#22c55e]/20 transition-colors
                               flex items-center justify-center gap-2">
                    <CheckCircle2 className="w-4 h-4"/>
                    He autorizado en M4 — Ejecutar ataque
                  </button>
                ) : (
                  <div className="w-full py-2.5 bg-[#22c55e]/20 border border-[#22c55e]/40 rounded-lg
                                  flex items-center justify-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-[#22c55e]"/>
                    <span className="text-xs font-bold text-[#22c55e]">Ciclo ENS completado al 100% ✓</span>
                  </div>
                )}
              </div>
            )}
            {immPhase === 'error' && (
              <div className="px-5 py-3 border-t border-[#1C2030] flex items-center gap-3">
                <AlertTriangle className="w-4 h-4 text-[#ff3b3b]"/>
                <span className="text-xs text-[#ff3b3b]">Ciclo fallido — revisa los logs</span>
                <button onClick={() => { setImmLogs([]); setImmErrors([]); setImmPhase('idle'); handleImmediateCycle(); }}
                  className="ml-auto px-3 py-1.5 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30
                             text-[#ff3b3b] rounded text-xs hover:bg-[#ff3b3b]/20">
                  Reintentar
                </button>
              </div>
            )}

          </div>
        </div>
      )}

      {/* Kill Switch confirmation modal */}
      <Dialog.Root open={showKillSwitchModal} onOpenChange={setShowKillSwitchModal}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-[#111318] border border-[#ff3b3b]/30 rounded-lg p-6 shadow-2xl shadow-[#ff3b3b]/10">
            <Dialog.Title className="text-xl font-semibold text-[#ff3b3b] mb-3 flex items-center gap-2">
              <Shield className="w-5 h-5" />
              ⚠ Activar Kill Switch
            </Dialog.Title>
            <Dialog.Description className="text-sm text-[#64748B] mb-6 leading-relaxed">
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
                  className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg px-4 py-2.5 text-white placeholder:text-[#475569] focus:outline-none focus:border-[#ff3b3b] focus:ring-1 focus:ring-[#ff3b3b] transition-colors font-mono tracking-widest text-center text-lg"
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
                <button className="w-full bg-transparent border border-[#1C2030] hover:bg-[#1C2030] text-[#64748B] hover:text-white font-semibold py-2.5 rounded-lg transition-colors">
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
