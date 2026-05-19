import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  Search, Loader2, AlertTriangle, Trash2, Eye,
  Plus, Pencil, Activity,
} from 'lucide-react';
import { useState, useEffect, useRef } from 'react';

const ORCHESTRATOR_BASE = 'http://localhost:8009';
const M1_BASE = 'http://localhost:8001';

function getToken(): string | null {
  try {
    const raw = sessionStorage.getItem('scanops_auth');
    return raw ? JSON.parse(raw)?.access_token ?? null : null;
  } catch { return null; }
}

function authH(): HeadersInit {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

interface OrchestratorLog {
  level: string;
  message: string;
  module: string;
  timestamp: string;
  _source: 'orchestrator';
}

interface AssetAuditLog {
  id: number;
  asset_id: number;
  action: 'CREATE' | 'UPDATE' | 'DELETE' | string;
  user_id: string;
  user_role?: string;
  timestamp: string;
  changes?: Record<string, unknown>;
  ip_origin?: string;
  reason?: string;
  _source: 'asset';
  _asset_ip?: string;
}

type AuditEntry = OrchestratorLog | AssetAuditLog;
void (null as unknown as AuditEntry);

function fmtTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return ts; }
}

function fmtDatetime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString('es-ES', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch { return ts; }
}

function levelColor(level: string): string {
  switch (level?.toUpperCase()) {
    case 'ERROR':   return 'text-[#ff3b3b]';
    case 'WARN':    return 'text-[#f59e0b]';
    case 'SUCCESS': return 'text-[#22c55e]';
    default:        return 'text-[#9ca3af]';
  }
}

export function AuditLogsPage() {
  const [orchestratorLogs, setOrchestratorLogs] = useState<OrchestratorLog[]>([]);
  const [sseConnected, setSseConnected] = useState(false);
  const [assetLogs, setAssetLogs] = useState<AssetAuditLog[]>([]);
  const [assetLoading, setAssetLoading] = useState(true);
  const [assetError, setAssetError] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterAction, setFilterAction] = useState('ALL');
  const [filterAsset, setFilterAsset] = useState('ALL');
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  // SSE — orchestrator logs
  useEffect(() => {
    const token = getToken();
    const url = token
      ? `${ORCHESTRATOR_BASE}/orchestrator/logs/stream?token=${encodeURIComponent(token)}`
      : `${ORCHESTRATOR_BASE}/orchestrator/logs/stream`;

    const evtSource = new EventSource(url);

    evtSource.onopen = () => setSseConnected(true);
    evtSource.onerror = () => setSseConnected(false);
    evtSource.onmessage = (e) => {
      try {
        const entry: OrchestratorLog = { ...JSON.parse(e.data as string), _source: 'orchestrator' };
        setOrchestratorLogs(prev => [entry, ...prev].slice(0, 200));
      } catch { /* malformed event */ }
    };

    return () => evtSource.close();
  }, []);

  // Auto-scroll terminal
  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollTop = logEndRef.current.scrollHeight;
    }
  }, [orchestratorLogs]);

  // Asset audit logs — cargar al montar
  useEffect(() => {
    const load = async () => {
      setAssetLoading(true);
      setAssetError(false);
      try {
        const assetsRes = await fetch(
          `${M1_BASE}/api/v1/assets?page=1&page_size=200`,
          { headers: authH(), signal: AbortSignal.timeout(10000) },
        );
        if (!assetsRes.ok) throw new Error(`HTTP ${assetsRes.status}`);
        const assetsData = await assetsRes.json() as { items?: { id: number; ip?: string }[] };
        const assets = (assetsData.items ?? []).slice(0, 10);

        const results = await Promise.allSettled(
          assets.map(async (asset) => {
            const res = await fetch(
              `${M1_BASE}/api/v1/assets/${asset.id}/audit?limit=50`,
              { headers: authH(), signal: AbortSignal.timeout(8000) },
            );
            if (!res.ok) return [];
            const data = await res.json() as (Omit<AssetAuditLog, '_source' | '_asset_ip'>)[];
            return (Array.isArray(data) ? data : []).map(entry => ({
              ...entry,
              _source: 'asset' as const,
              _asset_ip: asset.ip ?? String(asset.id),
            }));
          }),
        );

        const entries: AssetAuditLog[] = results.flatMap(r =>
          r.status === 'fulfilled' ? r.value : [],
        );

        entries.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        setAssetLogs(entries);
      } catch {
        setAssetError(true);
      } finally {
        setAssetLoading(false);
      }
    };
    load();
  }, []);

  // KPIs
  const totalEntries = orchestratorLogs.length + assetLogs.length;
  const errorCount = orchestratorLogs.filter(l => l.level?.toUpperCase() === 'ERROR').length;
  const assetOpsCount = assetLogs.length;
  const lastActivity = (() => {
    const allTs = [
      ...orchestratorLogs.map(l => l.timestamp),
      ...assetLogs.map(l => l.timestamp),
    ].filter(Boolean);
    if (!allTs.length) return '—';
    const latest = allTs.reduce((a, b) => (a > b ? a : b));
    return fmtTime(latest);
  })();

  // Filtros asset logs
  const assetIPs = [...new Set(assetLogs.map(l => l._asset_ip).filter(Boolean))];
  const filteredAsset = assetLogs.filter(l => {
    const q = searchTerm.toLowerCase();
    const matchSearch =
      !q ||
      (l.user_id ?? '').toLowerCase().includes(q) ||
      (l.action ?? '').toLowerCase().includes(q) ||
      (l.ip_origin ?? '').toLowerCase().includes(q) ||
      (l._asset_ip ?? '').toLowerCase().includes(q);
    const matchAction = filterAction === 'ALL' || l.action === filterAction;
    const matchAsset = filterAsset === 'ALL' || l._asset_ip === filterAsset;
    return matchSearch && matchAction && matchAsset;
  });

  const actionBadge = (action: string) => {
    const cfg: Record<string, { cls: string; icon: React.ReactNode; label: string }> = {
      CREATE: { cls: 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]', icon: <Plus className="w-3 h-3" />, label: 'CREATE' },
      UPDATE: { cls: 'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]', icon: <Pencil className="w-3 h-3" />, label: 'UPDATE' },
      DELETE: { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]', icon: <Trash2 className="w-3 h-3" />, label: 'DELETE' },
    };
    const c = cfg[action] ?? { cls: 'bg-[#374151]/30 border-[#4b5563]/30 text-[#6b7280]', icon: null, label: action };
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-xs font-semibold ${c.cls}`}>
        {c.icon}{c.label}
      </span>
    );
  };

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="Auditor" />

        <main className="flex-1 overflow-auto p-6 space-y-6">

          {/* ── Cabecera ── */}
          <div>
            <h1 className="text-2xl font-semibold text-white mb-1">Logs de Auditoría</h1>
            <p className="text-[#9ca3af] text-sm">Trazabilidad completa del sistema · ENS op.exp.5 · RD 311/2022</p>
          </div>

          {/* KPI cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4">
              <div className="text-2xl font-bold text-white">{totalEntries}</div>
              <div className="text-xs text-[#9ca3af] mt-0.5">Total entradas</div>
            </div>
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4">
              <div className="text-2xl font-bold text-[#ff3b3b]">{errorCount}</div>
              <div className="text-xs text-[#9ca3af] mt-0.5">Errores del sistema</div>
            </div>
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4">
              <div className="text-2xl font-bold text-[#00d4ff]">{assetOpsCount}</div>
              <div className="text-xs text-[#9ca3af] mt-0.5">Operaciones sobre activos</div>
            </div>
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4">
              <div className="text-2xl font-bold text-white font-mono">{lastActivity}</div>
              <div className="text-xs text-[#9ca3af] mt-0.5">Última actividad</div>
            </div>
          </div>

          {/* ── Layout 2 columnas ── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* ── Panel izquierdo — Orchestrator SSE ── */}
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl overflow-hidden flex flex-col">
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2530]">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#00d4ff]" />
                  <span className="text-sm font-semibold text-white">Sistema — Live</span>
                  <span className={`flex items-center gap-1 text-xs ${sseConnected ? 'text-[#22c55e]' : 'text-[#ff3b3b]'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${sseConnected ? 'bg-[#22c55e] animate-pulse' : 'bg-[#ff3b3b]'}`} />
                    {sseConnected ? 'Conectado' : 'Desconectado'}
                  </span>
                </div>
                <button
                  onClick={() => setOrchestratorLogs([])}
                  title="Limpiar logs"
                  className="text-[#6b7280] hover:text-[#ff3b3b] transition-colors p-1 rounded"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>

              <div
                ref={logEndRef}
                className="flex-1 bg-[#0f1117] p-3 font-mono text-xs overflow-y-auto h-80 space-y-0.5"
              >
                {orchestratorLogs.length === 0 && (
                  <div className="text-[#4b5563] italic">Esperando logs del orchestrator...</div>
                )}
                {[...orchestratorLogs].reverse().map((log, i) => (
                  <div key={i} className={`leading-5 ${levelColor(log.level)}`}>
                    <span className="text-[#4b5563]">[{fmtTime(log.timestamp)}]</span>
                    {' '}
                    <span className="text-[#6b7280]">[{log.module}]</span>
                    {' '}
                    {log.message}
                  </div>
                ))}
              </div>

              <div className="px-4 py-2 border-t border-[#1e2530] text-[10px] text-[#4b5563] font-mono">
                {orchestratorLogs.length} entradas · máx 200
              </div>
            </div>

            {/* ── Panel derecho — Asset audit logs ── */}
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl overflow-hidden flex flex-col">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1e2530]">
                <Search className="w-4 h-4 text-[#00d4ff]" />
                <span className="text-sm font-semibold text-white">Auditoría de Activos (M1)</span>
              </div>

              {/* Filtros */}
              <div className="px-4 py-3 border-b border-[#1e2530] flex flex-wrap gap-2">
                <div className="relative flex-1 min-w-32">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#4b5563]" />
                  <input
                    value={searchTerm}
                    onChange={e => setSearchTerm(e.target.value)}
                    placeholder="Buscar..."
                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-[#374151] focus:outline-none focus:border-[#00d4ff]"
                  />
                </div>
                <select
                  value={filterAction}
                  onChange={e => setFilterAction(e.target.value)}
                  className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#00d4ff]"
                >
                  <option value="ALL">Todas las acciones</option>
                  <option value="CREATE">CREATE</option>
                  <option value="UPDATE">UPDATE</option>
                  <option value="DELETE">DELETE</option>
                </select>
                <select
                  value={filterAsset}
                  onChange={e => setFilterAsset(e.target.value)}
                  className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#00d4ff]"
                >
                  <option value="ALL">Todos los activos</option>
                  {assetIPs.map(ip => <option key={ip} value={ip}>{ip}</option>)}
                </select>
              </div>

              {/* Contenido */}
              <div className="flex-1 overflow-auto">
                {assetLoading && (
                  <div className="flex justify-center items-center py-12">
                    <Loader2 className="w-6 h-6 animate-spin text-[#00d4ff]" />
                  </div>
                )}

                {!assetLoading && assetError && (
                  <div className="m-4 flex items-center gap-2 px-4 py-3 bg-[#f59e0b]/10 border border-[#f59e0b]/20 rounded-lg text-sm text-[#f59e0b]">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    M1 no disponible — no se pudo cargar el historial de auditoría.
                  </div>
                )}

                {!assetLoading && !assetError && filteredAsset.length === 0 && (
                  <p className="text-[#6b7280] text-sm text-center py-8">Sin registros de auditoría disponibles.</p>
                )}

                {!assetLoading && !assetError && filteredAsset.length > 0 && (
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-[#1a1d27]">
                      <tr className="text-left text-[#6b7280] border-b border-[#1e2530]">
                        <th className="px-3 py-2 font-medium">Timestamp</th>
                        <th className="px-3 py-2 font-medium">Activo</th>
                        <th className="px-3 py-2 font-medium">Acción</th>
                        <th className="px-3 py-2 font-medium">Usuario</th>
                        <th className="px-3 py-2 font-medium">Rol</th>
                        <th className="px-3 py-2 font-medium">IP Origen</th>
                        <th className="px-3 py-2 font-medium">Det.</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2530]">
                      {filteredAsset.map(log => (
                        <>
                          <tr
                            key={log.id}
                            className="hover:bg-[#1e2530]/40 transition-colors"
                          >
                            <td className="px-3 py-2 font-mono text-[#9ca3af] whitespace-nowrap">
                              {fmtDatetime(log.timestamp)}
                            </td>
                            <td className="px-3 py-2 font-mono text-[#00d4ff]">
                              {log._asset_ip ?? String(log.asset_id)}
                            </td>
                            <td className="px-3 py-2">{actionBadge(log.action)}</td>
                            <td className="px-3 py-2 text-white">{log.user_id}</td>
                            <td className="px-3 py-2">
                              {log.user_role
                                ? <span className="px-1.5 py-0.5 bg-[#374151]/40 text-[#9ca3af] border border-[#4b5563]/30 rounded text-[10px]">{log.user_role}</span>
                                : <span className="text-[#4b5563]">—</span>
                              }
                            </td>
                            <td className="px-3 py-2 font-mono text-[#9ca3af]">
                              {log.ip_origin ?? '—'}
                            </td>
                            <td className="px-3 py-2">
                              <button
                                onClick={() => setExpandedRow(expandedRow === log.id ? null : log.id)}
                                className="text-[#6b7280] hover:text-[#00d4ff] transition-colors"
                                title="Ver detalles"
                              >
                                <Eye className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>

                          {expandedRow === log.id && (
                            <tr key={`${log.id}-detail`}>
                              <td colSpan={7} className="px-4 py-3 bg-[#0f1117] border-l-2 border-[#00d4ff]">
                                {log.reason && (
                                  <div className="mb-2">
                                    <span className="text-[10px] text-[#6b7280] uppercase tracking-wider">Motivo: </span>
                                    <span className="text-xs text-white">{log.reason}</span>
                                  </div>
                                )}
                                {log.changes && Object.keys(log.changes).length > 0 ? (
                                  <div>
                                    <div className="text-[10px] text-[#6b7280] uppercase tracking-wider mb-1">Cambios</div>
                                    <pre className="bg-[#080a10] rounded p-3 font-mono text-xs text-[#9ca3af] max-h-40 overflow-y-auto">
                                      {JSON.stringify(log.changes, null, 2)}
                                    </pre>
                                  </div>
                                ) : !log.reason ? (
                                  <span className="text-xs text-[#4b5563]">Sin detalles adicionales.</span>
                                ) : null}
                              </td>
                            </tr>
                          )}
                        </>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              <div className="px-4 py-2 border-t border-[#1e2530] text-[10px] text-[#4b5563] font-mono">
                {filteredAsset.length} entradas · máx 500 por carga
              </div>
            </div>

          </div>

          {/* ── Footer ── */}
          <div className="text-center text-xs text-[#4b5563]">
            Logs inmutables · ENS op.exp.5 · RD 311/2022 · Retención mínima 2 años
          </div>

        </main>
      </div>
    </div>
  );
}
