import { useState } from 'react';
import { useNavigate } from 'react-router';
import {
  ShieldAlert, Activity, Globe, Clock, ChevronRight,
  RefreshCw, AlertTriangle, Cpu, Network, Eye,
} from 'lucide-react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { Badge } from './ui/badge';
import { useBehavioralFindings, useThreatIntel, useEDRStats } from '../../hooks/useEDR';

// ── Severity helpers ───────────────────────────────────────────────────────────

function sevClass(sev: string) {
  switch (sev?.toUpperCase()) {
    case 'CRITICAL': return 'bg-red-500/15 text-red-400 border-red-500/30';
    case 'HIGH':     return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
    case 'MEDIUM':   return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    case 'LOW':      return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    default:         return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  }
}

function anomalyIcon(type: string) {
  const t = (type ?? '').toUpperCase();
  if (t.includes('C2') || t.includes('CALLBACK'))     return <Network className="w-3.5 h-3.5 text-red-400" />;
  if (t.includes('EXFIL'))                            return <Globe className="w-3.5 h-3.5 text-orange-400" />;
  if (t.includes('PRIV'))                             return <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />;
  if (t.includes('YARA'))                             return <Eye className="w-3.5 h-3.5 text-purple-400" />;
  if (t.includes('LATERAL') || t.includes('SSH'))     return <Cpu className="w-3.5 h-3.5 text-blue-400" />;
  return <Activity className="w-3.5 h-3.5 text-slate-400" />;
}

const fmt = new Intl.DateTimeFormat('es-ES', {
  day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
});

// ── KPI Card ───────────────────────────────────────────────────────────────────

function KpiCard({ label, value, accent, icon: Icon }: {
  label: string; value: number | string; accent: string;
  icon: React.ElementType;
}) {
  const colorMap: Record<string, string> = {
    red:    'text-red-400 border-red-500/20 bg-red-500/5',
    orange: 'text-orange-400 border-orange-500/20 bg-orange-500/5',
    cyan:   'text-[#8B5CF6] border-[#8B5CF6]/20 bg-[#8B5CF6]/5',
    amber:  'text-amber-400 border-amber-500/20 bg-amber-500/5',
  };
  return (
    <div className={`flex flex-col gap-2 p-4 rounded-xl border ${colorMap[accent] ?? colorMap.cyan}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs text-inherit opacity-70 uppercase tracking-wider font-medium">{label}</span>
        <Icon className="w-4 h-4 opacity-70" />
      </div>
      <div className="text-3xl font-bold font-mono">{value}</div>
    </div>
  );
}

// ── TI Source Badges ───────────────────────────────────────────────────────────

function TIBadges({ vt, cs, otx }: { vt: number | null; cs: number | null; otx: number | null }) {
  return (
    <div className="flex gap-1 flex-wrap">
      {vt !== null && (
        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
          vt > 5 ? 'bg-red-500/10 text-red-400 border-red-500/30' : 'bg-slate-500/10 text-slate-400 border-slate-500/30'
        }`}>VT {vt}</span>
      )}
      {cs !== null && (
        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
          cs > 0 ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' : 'bg-slate-500/10 text-slate-400 border-slate-500/30'
        }`}>CS {cs}</span>
      )}
      {otx !== null && (
        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
          otx > 0 ? 'bg-purple-500/10 text-purple-400 border-purple-500/30' : 'bg-slate-500/10 text-slate-400 border-slate-500/30'
        }`}>OTX {otx}</span>
      )}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export function EDRDashboardPage() {
  const navigate = useNavigate();
  const [findingsPage, setFindingsPage] = useState(1);
  const [tiPage, setTiPage] = useState(1);
  const PAGE_SIZE = 10;

  const { findings, total: findingsTotal, loading: findingsLoading, refetch: refetchFindings } =
    useBehavioralFindings(undefined, findingsPage, PAGE_SIZE);

  const { entries, total: tiTotal, loading: tiLoading, refetch: refetchTI } =
    useThreatIntel(tiPage, PAGE_SIZE);

  const { stats, loading: statsLoading } = useEDRStats();

  // Mock data for demo
  const mockFindings = [
    { id: '1', process_name: 'explorer.exe', anomaly_type: 'LATERAL_MOVEMENT', severity: 'CRITICAL', mitre_attack_tactics: ['T1021'], confidence_score: 95, created_at: new Date(Date.now() - 3600000).toISOString(), asset_id: 15, detection_method: [], indicators: { cmdline: 'explorer.exe /root' } },
    { id: '2', process_name: 'svchost.exe', anomaly_type: 'C2_CALLBACK', severity: 'HIGH', mitre_attack_tactics: ['T1071'], confidence_score: 88, created_at: new Date(Date.now() - 7200000).toISOString(), asset_id: 22, detection_method: ['yara'], indicators: { cmdline: 'svchost.exe -k netsvcs' } },
    { id: '3', process_name: 'powershell.exe', anomaly_type: 'PRIVILEGE_ESCALATION', severity: 'HIGH', mitre_attack_tactics: ['T1548'], confidence_score: 82, created_at: new Date(Date.now() - 10800000).toISOString(), asset_id: 8, detection_method: [], indicators: { cmdline: 'powershell.exe -NoProfile -ExecutionPolicy Bypass' } },
    { id: '4', process_name: 'cmd.exe', anomaly_type: 'DATA_EXFILTRATION', severity: 'MEDIUM', mitre_attack_tactics: ['T1041'], confidence_score: 75, created_at: new Date(Date.now() - 14400000).toISOString(), asset_id: 31, detection_method: [], indicators: { cmdline: 'cmd.exe /c type secret.txt' } },
  ];

  const mockTI = [
    { id: '1', ioc_value: '192.168.1.105', ioc_type: 'ip', vt_malicious_count: 15, crowdsec_score: 8, otx_pulse_count: 3, is_malicious: true, ttl_expires: new Date(Date.now() + 86400000).toISOString() },
    { id: '2', ioc_value: '10.202.15.50', ioc_type: 'ip', vt_malicious_count: 0, crowdsec_score: 0, otx_pulse_count: 0, is_malicious: false, ttl_expires: new Date(Date.now() + 172800000).toISOString() },
    { id: '3', ioc_value: 'malware.evil.com', ioc_type: 'domain', vt_malicious_count: 45, crowdsec_score: 9, otx_pulse_count: 12, is_malicious: true, ttl_expires: new Date(Date.now() + 86400000).toISOString() },
  ];

  const mockStats = { total_findings: 4, critical_findings: 1, malicious_ips: 2, pending_approvals: 3 };

  // Always use mock data for demo
  const displayFindings = mockFindings;
  const displayTI = mockTI;
  const displayStats = mockStats;

  const handleRefresh = () => {
    refetchFindings();
    refetchTI();
  };

  return (
    <div className="flex h-screen bg-[#0A0C10] text-[#d1d5db] overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-[#8B5CF6]" />
                M3.1 EDR — Behavioral Dashboard
              </h1>
              <p className="text-xs text-[#475569] mt-1">
                Detección de anomalías en tiempo real · Threat intelligence · Incident response
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => navigate('/incident-response')}
                className="flex items-center gap-2 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 rounded-lg text-xs font-medium transition-colors"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                Incident Response
                {(stats?.pending_approvals ?? 0) > 0 && (
                  <span className="ml-1 px-1.5 py-0.5 bg-red-500 text-white rounded-full text-[10px] font-bold">
                    {stats!.pending_approvals}
                  </span>
                )}
              </button>
              <button
                onClick={handleRefresh}
                className="flex items-center gap-1.5 px-3 py-2 bg-[#111318] border border-[#1C2030] rounded-lg text-xs text-[#64748B] hover:text-white hover:border-[#8B5CF6]/40 transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Actualizar
              </button>
            </div>
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <KpiCard
              label="Total anomalías" icon={Activity}
              value={statsLoading ? '—' : (displayStats?.total_findings ?? findingsTotal)}
              accent="cyan"
            />
            <KpiCard
              label="Críticas/Altas" icon={ShieldAlert}
              value={statsLoading ? '—' : (displayStats?.critical_findings ?? displayFindings.filter(f => ['CRITICAL','HIGH'].includes(f.severity)).length)}
              accent="red"
            />
            <KpiCard
              label="IPs maliciosas" icon={Globe}
              value={statsLoading ? '—' : (displayStats?.malicious_ips ?? displayTI.filter(e => e.ioc_type === 'ip').length)}
              accent="orange"
            />
            <KpiCard
              label="Aprobaciones pendientes" icon={Clock}
              value={statsLoading ? '—' : (displayStats?.pending_approvals ?? 0)}
              accent="amber"
            />
          </div>

          {/* Behavioral Anomalies Table */}
          <div className="bg-[#111318] border border-[#1C2030] rounded-xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#1C2030]">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#8B5CF6]" />
                Behavioral Anomalies
                <span className="text-[10px] font-mono text-[#475569] ml-1">
                  {displayFindings.length} total
                </span>
              </h2>
            </div>

            {displayFindings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-[#475569] text-sm gap-2">
                <ShieldAlert className="w-8 h-8 opacity-30" />
                No se han detectado anomalías
              </div>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[#1C2030] text-[#475569]">
                        <th className="text-left px-4 py-2 font-medium">Proceso</th>
                        <th className="text-left px-4 py-2 font-medium">Tipo de anomalía</th>
                        <th className="text-left px-4 py-2 font-medium">Severidad</th>
                        <th className="text-left px-4 py-2 font-medium">MITRE</th>
                        <th className="text-left px-4 py-2 font-medium">Confianza</th>
                        <th className="text-left px-4 py-2 font-medium">Detectado</th>
                        <th className="text-left px-4 py-2 font-medium">Acción</th>
                      </tr>
                    </thead>
                    <tbody>
                      {displayFindings.map((f) => (
                        <tr key={f.id} className="border-b border-[#1C2030]/50 hover:bg-[#1C2030]/40 transition-colors">
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2">
                              {anomalyIcon(f.anomaly_type)}
                              <span className="font-mono text-white truncate max-w-[140px]">
                                {f.process_name || '—'}
                              </span>
                            </div>
                            {f.indicators?.cmdline && (
                              <div className="font-mono text-[#475569] text-[10px] truncate max-w-[200px] mt-0.5">
                                {String(f.indicators.cmdline).substring(0, 60)}…
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-2.5">
                            <span className="font-mono text-[#64748B]">{f.anomaly_type}</span>
                            {f.detection_method?.includes('yara') && (
                              <span className="ml-1 px-1 py-0.5 bg-purple-500/10 text-purple-400 border border-purple-500/30 rounded text-[10px]">
                                YARA
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-2.5">
                            <Badge className={`${sevClass(f.severity)} border text-[10px] font-mono px-2 py-0.5`}>
                              {f.severity}
                            </Badge>
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex flex-wrap gap-1 max-w-[120px]">
                              {(f.mitre_attack_tactics ?? []).slice(0, 2).map((t) => (
                                <span key={t} className="px-1.5 py-0.5 bg-[#1C2030] border border-[#374151] text-[#64748B] rounded text-[10px] font-mono">
                                  {t}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-1.5">
                              <div className="w-16 h-1.5 bg-[#1C2030] rounded-full overflow-hidden">
                                <div
                                  className="h-full rounded-full bg-[#8B5CF6]"
                                  style={{ width: `${f.confidence_score ?? 50}%` }}
                                />
                              </div>
                              <span className="font-mono text-[#64748B] text-[10px]">
                                {f.confidence_score ?? 50}%
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5 text-[#475569] font-mono">
                            {fmt.format(new Date(f.created_at))}
                          </td>
                          <td className="px-4 py-2.5">
                            <button
                              onClick={() => navigate('/incident-response', { state: { preselect: { assetId: f.asset_id, processName: f.process_name, anomalyType: f.anomaly_type } } })}
                              className="flex items-center gap-1 px-2 py-1 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 rounded text-[10px] font-medium transition-colors"
                            >
                              <ShieldAlert className="w-3 h-3" />
                              Responder
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                {findingsTotal > PAGE_SIZE && (
                  <div className="flex items-center justify-between px-4 py-2 border-t border-[#1C2030] text-xs text-[#475569]">
                    <span>Página {findingsPage} de {Math.ceil(findingsTotal / PAGE_SIZE)}</span>
                    <div className="flex gap-2">
                      <button
                        disabled={findingsPage <= 1}
                        onClick={() => setFindingsPage(p => Math.max(1, p - 1))}
                        className="px-2 py-1 bg-[#1C2030] rounded disabled:opacity-40 hover:bg-[#252a36] transition-colors"
                      >‹ Anterior</button>
                      <button
                        disabled={findingsPage >= Math.ceil(findingsTotal / PAGE_SIZE)}
                        onClick={() => setFindingsPage(p => p + 1)}
                        className="px-2 py-1 bg-[#1C2030] rounded disabled:opacity-40 hover:bg-[#252a36] transition-colors"
                      >Siguiente ›</button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Threat Intelligence Heatmap */}
          <div className="bg-[#111318] border border-[#1C2030] rounded-xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#1C2030]">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Globe className="w-4 h-4 text-orange-400" />
                Threat Intelligence — IOCs maliciosos
                <span className="text-[10px] font-mono text-[#475569] ml-1">{displayTI.length} total</span>
              </h2>
            </div>

            {displayTI.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-[#475569] text-sm gap-2">
                <Globe className="w-6 h-6 opacity-30" />
                No hay IOCs maliciosos en caché
              </div>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[#1C2030] text-[#475569]">
                        <th className="text-left px-4 py-2 font-medium">IOC</th>
                        <th className="text-left px-4 py-2 font-medium">Tipo</th>
                        <th className="text-left px-4 py-2 font-medium">Reputación (VT / CS / OTX)</th>
                        <th className="text-left px-4 py-2 font-medium">Estado</th>
                        <th className="text-left px-4 py-2 font-medium">TTL expira</th>
                      </tr>
                    </thead>
                    <tbody>
                      {displayTI.map((e) => (
                        <tr key={e.id} className="border-b border-[#1C2030]/50 hover:bg-[#1C2030]/40 transition-colors">
                          <td className="px-4 py-2.5">
                            <span className="font-mono text-white">{e.ioc_value}</span>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono ${
                              e.ioc_type === 'ip'     ? 'bg-blue-500/10 text-blue-400 border-blue-500/30' :
                              e.ioc_type === 'domain' ? 'bg-purple-500/10 text-purple-400 border-purple-500/30' :
                                                        'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            }`}>{e.ioc_type.toUpperCase()}</span>
                          </td>
                          <td className="px-4 py-2.5">
                            <TIBadges vt={e.vt_malicious_count} cs={e.crowdsec_score} otx={e.otx_pulse_count} />
                          </td>
                          <td className="px-4 py-2.5">
                            {e.is_malicious ? (
                              <span className="flex items-center gap-1 text-red-400 font-medium">
                                <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                                MALICIOSO
                              </span>
                            ) : (
                              <span className="text-[#475569]">limpio</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-[#475569] font-mono">
                            {fmt.format(new Date(e.ttl_expires))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {tiTotal > PAGE_SIZE && (
                  <div className="flex items-center justify-between px-4 py-2 border-t border-[#1C2030] text-xs text-[#475569]">
                    <span>Página {tiPage} de {Math.ceil(tiTotal / PAGE_SIZE)}</span>
                    <div className="flex gap-2">
                      <button
                        disabled={tiPage <= 1}
                        onClick={() => setTiPage(p => Math.max(1, p - 1))}
                        className="px-2 py-1 bg-[#1C2030] rounded disabled:opacity-40 hover:bg-[#252a36] transition-colors"
                      >‹ Anterior</button>
                      <button
                        disabled={tiPage >= Math.ceil(tiTotal / PAGE_SIZE)}
                        onClick={() => setTiPage(p => p + 1)}
                        className="px-2 py-1 bg-[#1C2030] rounded disabled:opacity-40 hover:bg-[#252a36] transition-colors"
                      >Siguiente ›</button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Quick link to IR queue */}
          <button
            onClick={() => navigate('/incident-response')}
            className="w-full flex items-center justify-between px-5 py-4 bg-[#111318] border border-red-500/20 hover:border-red-500/40 rounded-xl text-sm text-red-400 transition-colors group"
          >
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5" />
              <div className="text-left">
                <div className="font-semibold text-white">Incident Response Queue</div>
                <div className="text-xs text-[#475569]">Gestionar aprobaciones pendientes · historial de acciones</div>
              </div>
            </div>
            <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </button>

        </main>
      </div>
    </div>
  );
}
