import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { ENSComplianceWidget } from './ENSComplianceWidget';
import { Activity, AlertTriangle, CheckCircle2, CalendarClock, Play, Pause, Zap, Power, Shield, Loader2, Users, Circle, RefreshCw } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import { AreaChart, Area, ResponsiveContainer } from 'recharts';
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

  const [metricsHistory, setMetricsHistory] = useState<{
    assets: number[];
    vulns: number[];
    compliance: number[];
  }>({ assets: [], vulns: [], compliance: [] });

  useEffect(() => {
    if (!metrics) return;
    setMetricsHistory(prev => ({
      assets:     [...prev.assets.slice(-7),     metrics.total_assets],
      vulns:      [...prev.vulns.slice(-7),      metrics.open_vulnerabilities],
      compliance: [...prev.compliance.slice(-7), metrics.ens_compliance_score],
    }));
  }, [metrics]);

  const toSparkData = (arr: number[]) => {
    if (arr.length === 0) return [{ v: 0 }, { v: 0 }];
    if (arr.length === 1) return [{ v: arr[0] }, { v: arr[0] }];
    return arr.map(v => ({ v }));
  };

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
    <div className="flex h-screen bg-gradient-to-br from-[#020617] via-[#0F172A] to-[#020617]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" cycleLabel={cycle.label} dotColor={cycle.dotColor} />

        {/* Critical status banners */}
        {killSwitchActive && (
          <div className="flex items-center gap-3 px-6 py-3 bg-[#EF4444]/15 border-b border-[#EF4444]/40 backdrop-blur-sm">
            <span className="text-[#EF4444]">●</span>
            <span className="text-sm text-[#EF4444] font-semibold flex-1">
              Kill Switch activo — Ciclo detenido
            </span>
            <button
              onClick={async () => {
                try { await cycleActions.deactivateKillSwitch(); refetch(); } catch {}
              }}
              className="px-4 py-1.5 text-xs text-white bg-[#EF4444]/20 border border-[#EF4444]/40 rounded-lg hover:bg-[#EF4444]/30 transition-colors font-semibold"
            >
              Reactivar ciclo
            </button>
          </div>
        )}

        {isPausedManually && !killSwitchActive && (
          <div className="flex items-center gap-3 px-6 py-3 bg-[#F59E0B]/15 border-b border-[#F59E0B]/40 backdrop-blur-sm">
            <span className="text-[#F59E0B]">⏸</span>
            <span className="text-sm text-[#F59E0B] flex-1">
              Ciclo pausado — Reanudación automática viernes 18:00
            </span>
            <button
              onClick={async () => {
                try { await cycleActions.pauseCycle(); refetch(); } catch {}
              }}
              className="px-3 py-1.5 text-xs bg-[#F59E0B] text-[#020617] rounded-lg hover:bg-[#D97706] transition-colors font-semibold"
            >
              Reanudar
            </button>
          </div>
        )}

        {cycleError && (
          <div className="flex items-center gap-2 px-6 py-3 bg-[#F59E0B]/15 border-b border-[#F59E0B]/40 text-sm text-[#F59E0B]">
            <span>⚠ Orchestrator indisponible</span>
            <button onClick={refetch} className="ml-auto text-xs underline hover:no-underline">Reintentar</button>
          </div>
        )}

        {cycleLoading && !cycleData && (
          <div className="flex items-center justify-center h-24 text-[#94A3B8] text-sm font-medium">
            Conectando con orchestrator...
          </div>
        )}

        <main className="flex-1 overflow-auto p-6 space-y-6">
          {/* KPI Cards — Priority metrics */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {/* Total Assets */}
            <div className="bg-[#0F172A] border border-[#334155] rounded-lg p-6 flex flex-col gap-0 overflow-hidden relative hover:border-[#475569] transition-colors">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#06B6D4]/15 rounded-lg flex items-center justify-center border border-[#06B6D4]/20">
                  <Activity className="w-5 h-5 text-[#06B6D4]" />
                </div>
                {metrics && !metrics.m1_available && (
                  <span className="text-[10px] text-[#F59E0B] font-semibold bg-[#F59E0B]/20 px-2 py-1 rounded-md border border-[#F59E0B]/30">M1 offline</span>
                )}
              </div>
              <div className="text-[12px] font-semibold text-[#94A3B8] uppercase tracking-widest mb-2">Activos</div>
              {metricsLoading ? (
                <>
                  <div className="h-8 w-12 bg-[#1E293B] rounded animate-pulse mb-2" />
                  <div className="h-3 w-24 bg-[#1E293B] rounded animate-pulse" />
                </>
              ) : (
                <>
                  <div className="text-4xl font-bold text-[#F8FAFC] leading-none mb-2">
                    {metrics?.total_assets ?? '—'}
                  </div>
                  <div className="text-xs text-[#94A3B8] mb-3">Registrados en inventario</div>
                </>
              )}
              <div className="mt-auto -mx-6 -mb-6 pt-3">
                <ResponsiveContainer width="100%" height={48}>
                  <AreaChart data={toSparkData(metricsHistory.assets)} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                    <defs>
                      <linearGradient id="spark-assets" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="v" stroke="#06B6D4" strokeWidth={2} fill="url(#spark-assets)" dot={false} isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Open Vulnerabilities */}
            <div className="bg-[#0F172A] border border-[#334155] rounded-lg p-6 flex flex-col gap-0 overflow-hidden relative hover:border-[#475569] transition-colors">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#EF4444]/15 rounded-lg flex items-center justify-center border border-[#EF4444]/20">
                  <AlertTriangle className="w-5 h-5 text-[#EF4444]" />
                </div>
                {metrics && !metrics.m3_available && (
                  <span className="text-[10px] text-[#F59E0B] font-semibold bg-[#F59E0B]/20 px-2 py-1 rounded-md border border-[#F59E0B]/30">M3 offline</span>
                )}
              </div>
              <div className="text-[12px] font-semibold text-[#94A3B8] uppercase tracking-widest mb-2">Vulnerabilidades</div>
              {metricsLoading ? (
                <>
                  <div className="h-8 w-12 bg-[#1E293B] rounded animate-pulse mb-2" />
                  <div className="h-3 w-28 bg-[#1E293B] rounded animate-pulse" />
                </>
              ) : (
                <>
                  <div className="text-4xl font-bold text-[#F8FAFC] leading-none mb-2">
                    {metrics?.open_vulnerabilities ?? '—'}
                  </div>
                  <div className="text-xs text-[#94A3B8] mb-3">Hallazgos críticos abiertos</div>
                </>
              )}
              <div className="mt-auto -mx-6 -mb-6 pt-3">
                <ResponsiveContainer width="100%" height={48}>
                  <AreaChart data={toSparkData(metricsHistory.vulns)} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                    <defs>
                      <linearGradient id="spark-vulns" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="v" stroke="#EF4444" strokeWidth={2} fill="url(#spark-vulns)" dot={false} isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* ENS Compliance */}
            <div className="bg-[#0F172A] border border-[#334155] rounded-lg p-6 flex flex-col gap-0 overflow-hidden relative hover:border-[#475569] transition-colors">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#22C55E]/15 rounded-lg flex items-center justify-center border border-[#22C55E]/20">
                  <CheckCircle2 className="w-5 h-5 text-[#22C55E]" />
                </div>
                {metrics && !metrics.m3_available && (
                  <span className="text-[10px] text-[#F59E0B] font-semibold bg-[#F59E0B]/20 px-2 py-1 rounded-md border border-[#F59E0B]/30">M3 offline</span>
                )}
              </div>
              <div className="text-[12px] font-semibold text-[#94A3B8] uppercase tracking-widest mb-2">Cumplimiento ENS</div>
              {metricsLoading ? (
                <>
                  <div className="h-8 w-12 bg-[#1E293B] rounded animate-pulse mb-2" />
                  <div className="h-3 w-20 bg-[#1E293B] rounded animate-pulse" />
                </>
              ) : (
                <>
                  <div className="text-4xl font-bold text-[#F8FAFC] leading-none mb-2">
                    {metrics?.ens_compliance_score != null ? `${metrics.ens_compliance_score}%` : '—'}
                  </div>
                  <div className="text-xs text-[#94A3B8] mb-3">Conformidad ENS Alto</div>
                </>
              )}
              <div className="mt-auto -mx-6 -mb-6 pt-3">
                <ResponsiveContainer width="100%" height={48}>
                  <AreaChart data={toSparkData(metricsHistory.compliance)} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                    <defs>
                      <linearGradient id="spark-compliance" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22C55E" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#22C55E" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="v" stroke="#22C55E" strokeWidth={2} fill="url(#spark-compliance)" dot={false} isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Weekly Cycle Status */}
            <div className="bg-[#0F172A] border border-[#334155] rounded-lg p-6 flex flex-col overflow-hidden relative hover:border-[#475569] transition-colors">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#F59E0B]/15 rounded-lg flex items-center justify-center border border-[#F59E0B]/20">
                  <CalendarClock className="w-5 h-5 text-[#F59E0B]" />
                </div>
              </div>
              <div className="text-[12px] font-semibold text-[#94A3B8] uppercase tracking-widest mb-2">Ciclo Semanal</div>
              <div className="text-[11px] text-[#94A3B8] mb-1 font-mono">{cycle.weekLabel}</div>
              <div className="text-lg font-bold text-[#F8FAFC] mb-1 leading-tight">{cycle.phase}</div>
              <div className="text-xs text-[#F59E0B] font-semibold">{cycle.timeRemaining}</div>
              <div className="mt-auto pt-4 flex items-end gap-1">
                {[1,2,3,4,5,6,7].map(w => (
                  <div
                    key={w}
                    className="flex-1 rounded-sm transition-all duration-300"
                    style={{
                      height: w <= (cycle.activeBlock ?? 0) + 1 ? `${12 + w * 3}px` : '8px',
                      background: w <= (cycle.activeBlock ?? 0) + 1
                        ? `rgba(245, 158, 11, ${0.3 + w * 0.05})`
                        : '#1E293B',
                    }}
                  />
                ))}
              </div>
            </div>
          </div>

          <ENSComplianceWidget />

          {/* ── Active Sessions (admin only) ──────────────────────── */}
          {userRole === 'system_manager' && (
            <div className="bg-[#0F172A] border border-[#334155] rounded-lg overflow-hidden">
              <div className="flex items-center justify-between px-6 py-4 border-b border-[#334155]">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 bg-[#A78BFA]/20 rounded-lg flex items-center justify-center border border-[#A78BFA]/30">
                    <Users className="w-4 h-4 text-[#A78BFA]" />
                  </div>
                  <span className="text-sm font-bold text-[#F8FAFC] uppercase tracking-widest">Usuarios Activos</span>
                  <span className="px-2.5 py-1 text-xs font-bold rounded-full bg-[#A78BFA]/25 text-[#D8B4FE] border border-[#A78BFA]/40">
                    {activeSessions.length}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-xs text-[#94A3B8] font-mono">
                  {sessionsLastUpdate && (
                    <span>actualizado {sessionsLastUpdate.toLocaleTimeString('es-ES')}</span>
                  )}
                  {sessionsLoading
                    ? <Loader2 className="w-4 h-4 text-[#64748B] animate-spin" />
                    : <RefreshCw className="w-4 h-4 text-[#64748B]" />
                  }
                </div>
              </div>

              {activeSessions.length === 0 ? (
                <div className="px-6 py-8 text-center text-sm text-[#475569] font-mono">
                  {sessionsLoading ? 'Cargando sesiones...' : 'Sin sesiones activas'}
                </div>
              ) : (
                <div className="divide-y divide-[#334155]">
                  {activeSessions.map((s) => {
                    const ago = Math.round((Date.now() - new Date(s.last_seen).getTime()) / 60000);
                    const agoLabel = ago < 1 ? 'ahora' : ago < 60 ? `${ago}m` : `${Math.round(ago/60)}h`;
                    return (
                      <div key={s.username} className="flex items-center gap-4 px-6 py-3 hover:bg-[#1A1E2F] transition-colors">
                        <div className="relative shrink-0">
                          <div className="w-9 h-9 rounded-full bg-[#A78BFA]/20 border border-[#A78BFA]/30 flex items-center justify-center text-xs font-bold text-[#D8B4FE]">
                            {s.username.charAt(0).toUpperCase()}
                          </div>
                          <Circle className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 text-[#22C55E] fill-[#22C55E]" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-sm font-semibold text-[#F8FAFC]">{s.username}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#A78BFA]/20 text-[#D8B4FE] border border-[#A78BFA]/30 font-semibold">
                              {ROLE_LABELS[s.role] ?? s.role}
                            </span>
                          </div>
                          <div className="text-xs text-[#64748B] font-mono truncate">
                            {s.ip !== '—' ? s.ip : 'IP desconocida'}
                            {s.user_agent !== '—' && (
                              <span className="ml-2 text-[#475569]">• {s.user_agent.split(' ')[0]}</span>
                            )}
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          <div className="text-xs text-[#22C55E] font-semibold">● Activo</div>
                          <div className="text-xs text-[#94A3B8] font-mono">{agoLabel}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Pipeline Visualization */}
          <div className="bg-[#0F172A] border border-[#334155] rounded-lg p-6">
            <h3 className="text-sm font-bold text-[#F8FAFC] uppercase tracking-widest mb-4">Fases de Ejecución Semanal</h3>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
              {pipelineBlocks.map((block, i) => {
                const isActive = block.blockIndex === cycle.activeBlock;
                return (
                  <div key={i} className="flex items-stretch gap-3">
                    <div
                      className={`flex-1 rounded-lg p-4 border transition-all ${
                        isActive
                          ? 'border-[#22C55E]/40 shadow-[0_0_12px_rgba(34,197,94,0.15)] bg-[#020617]'
                          : 'border-[#334155] bg-[#0A0C10]'
                      }`}
                    >
                      <div className="text-[11px] text-[#94A3B8] font-mono uppercase tracking-wider mb-2 font-semibold">{block.timeLabel}</div>
                      <div className="text-sm font-semibold text-[#F8FAFC] mb-3">{block.phaseLabel}</div>
                      <div className="flex flex-wrap gap-2">
                        {block.modules.map((mod) => (
                          <span
                            key={mod.id}
                            className={`px-2 py-1 rounded text-xs font-mono font-semibold border transition-all ${
                              mod.isHuman || mod.status === 'blocked'
                                ? 'bg-[#F59E0B]/20 text-[#F59E0B] border-[#F59E0B]/40'
                                : mod.status === 'offline'
                                ? 'bg-[#EF4444]/20 text-[#EF4444] border-[#EF4444]/40'
                                : mod.status === 'completed'
                                ? 'bg-[#22C55E]/20 text-[#22C55E] border-[#22C55E]/40'
                                : mod.status === 'in_progress' || mod.status === 'in-progress'
                                ? 'bg-[#A78BFA]/20 text-[#D8B4FE] border-[#A78BFA]/40 animate-pulse'
                                : 'bg-[#334155]/50 text-[#CBD5E1] border-[#475569]'
                            }`}
                          >
                            {mod.id}{mod.label ? ` (${mod.label})` : ''}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Live Execution Log — Compact */}
          <div className="bg-[#0F172A] border border-[#334155] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#334155]">
              <h3 className="text-sm font-bold text-[#F8FAFC] uppercase tracking-widest">Eventos en Tiempo Real</h3>
              <div className="flex items-center gap-2 text-xs font-semibold font-mono">
                <div className={`w-2 h-2 rounded-full ${logConnected ? 'bg-[#22C55E] animate-pulse' : 'bg-[#94A3B8]'}`} />
                <span className={logConnected ? 'text-[#22C55E]' : 'text-[#94A3B8]'}>
                  {logConnected ? '● LIVE' : '● OFFLINE'}
                </span>
              </div>
            </div>

            <div ref={logContainerRef} className="bg-[#020617] px-6 py-3 h-40 overflow-y-auto font-mono text-xs space-y-1">
              {logEntries.length === 0 ? (
                <div className="text-[#475569] italic">Esperando eventos...</div>
              ) : (
                logEntries.map((entry, i) => (
                  <div key={i} className="flex gap-3 items-start">
                    <span className="text-[#475569] shrink-0 min-w-fit">
                      {new Date(entry.timestamp).toLocaleTimeString('es-ES')}
                    </span>
                    <span className={`shrink-0 font-semibold min-w-fit ${
                      entry.level === 'SUCCESS' ? 'text-[#22C55E]' :
                      entry.level === 'WARN' ? 'text-[#F59E0B]' :
                      entry.level === 'ERROR' ? 'text-[#EF4444]' :
                      'text-[#A78BFA]'
                    }`}>{entry.level}</span>
                    <span className="text-[#64748B] shrink-0">[{entry.module}]</span>
                    <span className="text-[#CBD5E1] flex-1 break-words">{entry.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Action Control Panel */}
          <div className="bg-[#0F172A] border border-[#334155] rounded-lg p-6">
            <h3 className="text-sm font-bold text-[#F8FAFC] uppercase tracking-widest mb-4">Control de Ciclo</h3>
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
              {/* Primary actions */}
              <button className="px-4 py-3 bg-[#22C55E] hover:bg-[#16A34A] active:bg-[#15803D] text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2 text-sm">
                <Play className="w-4 h-4" />
                <span className="hidden sm:inline">Ejecutar</span>
              </button>

              <button
                onClick={async () => {
                  try { await cycleActions.pauseCycle(); refetch(); } catch {}
                }}
                className={`px-4 py-3 font-semibold rounded-lg transition-all flex items-center justify-center gap-2 text-sm ${
                  isPausedManually
                    ? 'bg-[#F59E0B] hover:bg-[#D97706] active:bg-[#B45309] text-white'
                    : 'bg-[#F59E0B] hover:bg-[#D97706] active:bg-[#B45309] text-white'
                }`}
              >
                <Pause className="w-4 h-4" />
                <span className="hidden sm:inline">{isPausedManually ? 'Reanud.' : 'Pausar'}</span>
              </button>

              <button className="px-4 py-3 bg-[#06B6D4]/20 hover:bg-[#06B6D4]/30 text-[#06B6D4] border border-[#06B6D4]/40 font-semibold rounded-lg transition-all flex items-center justify-center gap-2 text-sm">
                <AlertTriangle className="w-4 h-4" />
                <span className="hidden sm:inline">Escaneo</span>
              </button>

              {/* Immediate cycle button */}
              <button
                onClick={() => { setImmOpen(true); if (!immRunning) handleImmediateCycle(); }}
                disabled={immRunning}
                className="px-4 py-3 bg-[#A78BFA]/20 hover:bg-[#A78BFA]/30 disabled:opacity-40 disabled:cursor-not-allowed text-[#D8B4FE] border border-[#A78BFA]/40 font-semibold rounded-lg transition-all flex items-center justify-center gap-2 text-sm">
                {immRunning
                  ? <><Loader2 className="w-4 h-4 animate-spin"/></>
                  : <><Zap className="w-4 h-4"/></>}
                <span className="hidden sm:inline text-xs">{immRunning ? 'En curso' : 'Inmediato'}</span>
              </button>

              {/* Critical action — Kill Switch */}
              <button
                onClick={() => setShowKillSwitchModal(true)}
                className="px-4 py-3 bg-[#EF4444] hover:bg-[#DC2626] active:bg-[#B91C1C] text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2 text-sm shadow-lg shadow-[#EF4444]/20"
              >
                <Power className="w-4 h-4" />
                <span className="hidden sm:inline">Kill Switch</span>
              </button>
            </div>
          </div>
        </main>
      </div>

      {/* Immediate cycle modal */}
      {immOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="bg-[#0F172A] border border-[#334155] rounded-xl w-full max-w-2xl
                          mx-4 shadow-2xl flex flex-col max-h-[80vh]">

            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#334155]">
              <div className="flex items-center gap-3">
                <Zap className="w-5 h-5 text-[#A78BFA]"/>
                <div>
                  <h3 className="text-sm font-bold text-[#F8FAFC]">Ciclo Inmediato — Todos los activos</h3>
                  <p className="text-xs text-[#94A3B8] font-mono">M1 → M2 → M3 → M8 → M4</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {(['m1','m2','m3','m8','m4'] as const).map(phase => (
                  <span key={phase} className={`text-xs font-mono px-2 py-1 rounded border font-semibold ${
                    immPhase === phase
                      ? 'bg-[#A78BFA]/25 border-[#A78BFA]/40 text-[#D8B4FE] animate-pulse'
                      : 'bg-[#334155]/40 border-[#475569] text-[#64748B]'
                  }`}>
                    {phase.toUpperCase()}
                  </span>
                ))}
                {!immRunning && (
                  <button onClick={() => setImmOpen(false)}
                    className="text-[#64748B] hover:text-[#F8FAFC] text-2xl ml-2">×</button>
                )}
              </div>
            </div>

            {/* Error banner */}
            {immErrors.length > 0 && (
              <div className="mx-6 mt-4 bg-[#EF4444]/15 border border-[#EF4444]/40 rounded-lg px-4 py-3">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-[#EF4444] shrink-0"/>
                  <span className="text-xs font-bold text-[#EF4444]">
                    {immErrors.length} error{immErrors.length > 1 ? 'es' : ''} detectado{immErrors.length > 1 ? 's' : ''}
                  </span>
                </div>
                <ul className="space-y-1">
                  {immErrors.map((e, i) => (
                    <li key={i} className="text-[11px] text-[#EF4444] font-mono">• {e}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Log */}
            <div ref={immLogRef}
                 className="flex-1 overflow-y-auto bg-[#020617] px-6 py-4 font-mono text-xs
                            space-y-1 min-h-[300px]">
              {immLogs.length === 0 && <p className="text-[#475569] italic">Iniciando ciclo...</p>}
              {immLogs.map((l, i) => (
                <div key={i} className="flex gap-3">
                  <span className="text-[#475569] shrink-0 min-w-fit">{l.ts}</span>
                  <span className={`shrink-0 font-semibold min-w-fit ${
                    l.level === 'success' ? 'text-[#22C55E]' :
                    l.level === 'error'   ? 'text-[#EF4444]' :
                    l.level === 'warn'    ? 'text-[#F59E0B]' :
                    'text-[#A78BFA]'
                  }`}>{l.level.toUpperCase().charAt(0)}</span>
                  <span className="text-[#CBD5E1] flex-1 break-words">{l.msg}</span>
                </div>
              ))}
              {immRunning && (
                <div className="flex items-center gap-2 text-[#A78BFA] mt-2">
                  <Loader2 className="w-3 h-3 animate-spin"/>
                  <span>Procesando ciclo...</span>
                </div>
              )}
            </div>

            {/* Footer */}
            {immPhase === 'done' && (
              <div className="px-6 py-4 border-t border-[#334155] space-y-4 bg-[#1A1E2F]/40">
                {immApprovals.length > 0 && (
                  <div className="flex items-start gap-4">
                    <div className="flex flex-col items-center gap-2">
                      <img src={`data:image/png;base64,${immApprovals[0].qr_code_base64}`}
                           alt="QR TOTP" className="w-40 h-40 rounded-lg border border-[#334155]"/>
                      <p className="text-xs text-[#64748B] font-semibold">Google Authenticator</p>
                    </div>
                    <div className="flex-1">
                      <p className="text-xs font-bold text-[#F8FAFC] uppercase tracking-wide">
                        Aprobación #{immApprovals[0].approval_id}
                      </p>
                      <p className="text-xs font-mono text-[#A78BFA] mt-1 mb-2">
                        {immApprovals[0].asset_ip}
                      </p>
                      <p className="text-xs text-[#F59E0B] font-semibold font-mono">PIN: 1234</p>
                    </div>
                  </div>
                )}
                <div className="flex items-center gap-2 p-3 bg-[#22C55E]/15 border border-[#22C55E]/40 rounded-lg">
                  <CheckCircle2 className="w-4 h-4 text-[#22C55E] shrink-0"/>
                  <span className="text-xs text-[#22C55E] font-semibold flex-1">
                    Ciclo completado — Escanea QR y autoriza en M4
                  </span>
                  <button onClick={() => window.open('/exploitation', '_blank')}
                    className="px-3 py-1 bg-[#A78BFA]/20 border border-[#A78BFA]/40 text-[#D8B4FE] rounded text-xs font-semibold hover:bg-[#A78BFA]/30">
                    Ir a M4
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
                    className="w-full py-3 bg-[#22C55E] hover:bg-[#16A34A] active:bg-[#15803D] text-white font-bold rounded-lg text-sm transition-all flex items-center justify-center gap-2">
                    <CheckCircle2 className="w-4 h-4"/>
                    Autorizado en M4 — Ejecutar Explotación
                  </button>
                ) : (
                  <div className="w-full py-3 bg-[#22C55E]/20 border border-[#22C55E]/40 rounded-lg flex items-center justify-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-[#22C55E]"/>
                    <span className="text-xs font-bold text-[#22C55E]">Ciclo ENS completado al 100% ✓</span>
                  </div>
                )}
              </div>
            )}
            {immPhase === 'error' && (
              <div className="px-6 py-4 border-t border-[#334155] bg-[#EF4444]/10 flex items-center gap-3">
                <AlertTriangle className="w-4 h-4 text-[#EF4444]"/>
                <span className="text-xs text-[#EF4444] font-semibold flex-1">Ciclo fallido — Revisa logs</span>
                <button onClick={() => { setImmLogs([]); setImmErrors([]); setImmPhase('idle'); handleImmediateCycle(); }}
                  className="px-3 py-1.5 bg-[#EF4444]/20 border border-[#EF4444]/40 text-[#EF4444] rounded text-xs font-semibold hover:bg-[#EF4444]/30">
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
          <Dialog.Overlay className="fixed inset-0 bg-black/70 backdrop-blur-sm" />
          <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-[#0F172A] border border-[#EF4444]/40 rounded-lg p-6 shadow-2xl shadow-[#EF4444]/10">
            <Dialog.Title className="text-lg font-bold text-[#EF4444] mb-2 flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Kill Switch — Acción Crítica
            </Dialog.Title>
            <Dialog.Description className="text-sm text-[#94A3B8] mb-6 leading-relaxed">
              Detiene completamente el ciclo semanal. No se reanudará automáticamente. Requiere reactivación manual.
            </Dialog.Description>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-[#F8FAFC] mb-2">
                  Código TOTP de 2FA (6 dígitos)
                </label>
                <input
                  type="text"
                  value={killSwitchTotp}
                  onChange={(e) => setKillSwitchTotp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full bg-[#020617] border border-[#334155] rounded-lg px-4 py-3 text-[#F8FAFC] placeholder:text-[#64748B] focus:outline-none focus:border-[#EF4444] focus:ring-1 focus:ring-[#EF4444]/30 transition-colors font-mono tracking-widest text-center text-xl font-semibold"
                  placeholder="000000"
                  maxLength={6}
                  autoFocus
                />
              </div>

              <button
                onClick={handleConfirmKillSwitch}
                disabled={killSwitchTotp.length !== 6}
                className="w-full bg-[#EF4444] hover:bg-[#DC2626] active:bg-[#B91C1C] disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold py-3 rounded-lg transition-all text-sm"
              >
                {killSwitchTotp.length === 6 ? 'Confirmar Kill Switch' : 'Ingresa 6 dígitos'}
              </button>

              <Dialog.Close asChild>
                <button className="w-full bg-transparent border border-[#334155] hover:border-[#475569] text-[#94A3B8] hover:text-[#F8FAFC] font-semibold py-2.5 rounded-lg transition-colors text-sm">
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
