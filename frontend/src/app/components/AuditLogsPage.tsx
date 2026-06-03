// frontend/src/app/components/AuditLogsPage.tsx
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  Search, Loader2, AlertTriangle, Trash2, Eye,
  Plus, Pencil, Activity, LogIn, ShieldAlert, RefreshCw,
  CheckCircle2, XCircle, User, Monitor, Download,
} from 'lucide-react';
import { useState, useEffect, useRef } from 'react';

const ORCHESTRATOR_BASE = 'http://localhost:8009';
const M1_BASE           = 'http://localhost:8001';
const AUTH_BASE         = 'http://localhost:8009';

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
  level: string; message: string; module: string; timestamp: string; _source: 'orchestrator';
}
interface AssetAuditLog {
  id: number; asset_id: number; action: 'CREATE' | 'UPDATE' | 'DELETE' | string;
  user_id: string; user_role?: string; timestamp: string;
  changes?: Record<string, unknown>; ip_origin?: string; reason?: string;
  _source: 'asset'; _asset_ip?: string;
}
interface LoginEvent {
  timestamp: string; username: string; role: string | null; success: boolean;
  ip_origin: string | null; user_agent: string | null; reason: string | null;
}
interface SIEMAlert {
  alert_id: string;
  timestamp: string;
  agent_id: string;
  agent_name: string;
  agent_ip: string;
  rule_id: string;
  rule_desc: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  raw_log: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  success?: boolean;
  src_ip?: string;
  src_user?: string;
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return ts; }
}
function fmtDatetime(ts: string): string {
  try { return new Date(ts).toLocaleString('es-ES', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return ts; }
}
function levelColor(level: string): string {
  switch (level?.toUpperCase()) {
    case 'ERROR': return 'text-[#ff3b3b]';
    case 'WARN':  return 'text-[#f59e0b]';
    case 'SUCCESS': return 'text-[#22c55e]';
    default: return 'text-[#9ca3af]';
  }
}

function LoginSessionsTab() {
  const [events, setEvents]             = useState<LoginEvent[]>([]);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState(false);
  const [search, setSearch]             = useState('');
  const [filterResult, setFilterResult] = useState<'ALL' | 'SUCCESS' | 'FAIL'>('ALL');
  const [filterUser, setFilterUser]     = useState('ALL');
  const [expandedIdx, setExpandedIdx]   = useState<number | null>(null);

  const [srvEvents, setSrvEvents]     = useState<SIEMAlert[]>([]);
  const [srvLoading, setSrvLoading]   = useState(true);
  const [srvError, setSrvError]       = useState(false);
  const [srvExpanded, setSrvExpanded] = useState<string | null>(null);

  const [srvSearch, setSrvSearch]               = useState('');
  const [srvFilterServer, setSrvFilterServer]   = useState('ALL');
  const [srvFilterSeverity, setSrvFilterSeverity] = useState('ALL');
  const [srvFilterResult, setSrvFilterResult]   = useState<'ALL' | 'SUCCESS' | 'FAIL'>('ALL');
  const [srvFilterIP, setSrvFilterIP]           = useState('ALL');
  const [srvPage, setSrvPage]                   = useState(1);
  const SRV_PAGE_SIZE = 20;

  const load = async () => {
    setLoading(true); setError(false);
    try {
      const res = await fetch(`${AUTH_BASE}/auth/login-events?limit=200`, { headers: authH(), signal: AbortSignal.timeout(8000) });
      if (!res.ok) throw new Error();
      const data = await res.json() as { total: number; events: LoginEvent[] };
      setEvents(data.events ?? []);
    } catch { setError(true); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    const loadSrv = async () => {
      setSrvLoading(true); setSrvError(false);
      try {
        const res = await fetch(
          'http://localhost:8006/siem/auth-events?limit=200',
          { headers: authH(), signal: AbortSignal.timeout(8000) }
        );
        if (!res.ok) throw new Error();
        const data = await res.json() as { events?: SIEMAlert[] };
        const all = data.events ?? [];
        setSrvEvents(all);
      } catch { setSrvError(true); }
      finally { setSrvLoading(false); }
    };
    loadSrv();
  }, []);

  useEffect(() => { setSrvPage(1); }, [srvSearch, srvFilterServer, srvFilterSeverity, srvFilterResult, srvFilterIP]);

  const srvServers    = [...new Set(srvEvents.map(e => e.agent_name).filter(Boolean))];
  const srvSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const srvSourceIPs  = [...new Set(srvEvents.map(e => e.src_ip).filter(Boolean))] as string[];

  const srvFiltered = srvEvents.filter(e => {
    const q = srvSearch.toLowerCase();
    const matchSearch = !q ||
      (e.agent_name ?? '').toLowerCase().includes(q) ||
      (e.rule_desc ?? '').toLowerCase().includes(q) ||
      (e.raw_log ?? '').toLowerCase().includes(q) ||
      (e.src_ip ?? '').toLowerCase().includes(q);
    const matchServer   = srvFilterServer === 'ALL' || e.agent_name === srvFilterServer;
    const matchSeverity = srvFilterSeverity === 'ALL' || e.severity === srvFilterSeverity;
    const matchResult   = srvFilterResult === 'ALL' ||
      (srvFilterResult === 'SUCCESS' && !!e.success) ||
      (srvFilterResult === 'FAIL' && !e.success);
    const matchIP = srvFilterIP === 'ALL' || e.src_ip === srvFilterIP;
    return matchSearch && matchServer && matchSeverity && matchResult && matchIP;
  });

  const srvTotalPages = Math.max(1, Math.ceil(srvFiltered.length / SRV_PAGE_SIZE));
  const srvPaged = srvFiltered.slice((srvPage - 1) * SRV_PAGE_SIZE, srvPage * SRV_PAGE_SIZE);

  const exportSrvCSV = () => {
    const headers = [
      'Timestamp', 'Servidor', 'IP Servidor', 'Agent ID',
      'Resultado', 'Severidad', 'IP Origen', 'Usuario',
      'Evento', 'Raw Log', 'MITRE Táctica', 'MITRE Técnica'
    ];

    const escape = (val: unknown): string => {
      const str = val == null ? '' : String(val);
      if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const rows = srvFiltered.map(e => [
      escape(e.timestamp),
      escape(e.agent_name),
      escape(e.agent_ip),
      escape(e.agent_id),
      escape(e.success ? 'EXITOSO' : 'FALLIDO'),
      escape(e.severity),
      escape(e.src_ip ?? ''),
      escape(e.src_user ?? ''),
      escape(e.rule_desc),
      escape(e.raw_log),
      escape(e.mitre_tactic ?? ''),
      escape(e.mitre_technique ?? ''),
    ].join(','));

    const csv = [headers.join(','), ...rows].join('\n');
    const bom = '﻿';
    const blob = new Blob([bom + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const date = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `scanops_server_logins_${date}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const total       = events.length;
  const failures    = events.filter(e => !e.success).length;
  const successes   = events.filter(e => e.success).length;
  const uniqueUsers = [...new Set(events.map(e => e.username))];

  const bruteForceIPs = (() => {
    const cutoff = Date.now() - 10 * 60 * 1000;
    const ipFails: Record<string, number> = {};
    events.filter(e => !e.success && e.ip_origin && new Date(e.timestamp).getTime() > cutoff)
          .forEach(e => { ipFails[e.ip_origin!] = (ipFails[e.ip_origin!] ?? 0) + 1; });
    return Object.entries(ipFails).filter(([, c]) => c >= 5).map(([ip]) => ip);
  })();

  const filtered = events.filter(e => {
    const q = search.toLowerCase();
    const matchSearch = !q || e.username.toLowerCase().includes(q) || (e.ip_origin ?? '').toLowerCase().includes(q) || (e.role ?? '').toLowerCase().includes(q);
    const matchResult = filterResult === 'ALL' || (filterResult === 'SUCCESS' && e.success) || (filterResult === 'FAIL' && !e.success);
    const matchUser   = filterUser === 'ALL' || e.username === filterUser;
    return matchSearch && matchResult && matchUser;
  });

  const roleBadge = (role: string | null) => {
    if (!role) return <span className="text-[#4b5563]">—</span>;
    const colors: Record<string, string> = {
      system_manager:   'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]',
      security_officer: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',
      auditor:          'bg-[#a78bfa]/10 border-[#a78bfa]/30 text-[#a78bfa]',
    };
    const cls = colors[role] ?? 'bg-[#374151]/30 border-[#4b5563]/30 text-[#6b7280]';
    return <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-semibold ${cls}`}>{role}</span>;
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4">
          <div className="text-2xl font-bold text-white">{total}</div>
          <div className="text-xs text-[#9ca3af] mt-0.5">Intentos totales</div>
        </div>
        <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4">
          <div className="text-2xl font-bold text-[#22c55e]">{successes}</div>
          <div className="text-xs text-[#9ca3af] mt-0.5">Sesiones exitosas</div>
        </div>
        <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4">
          <div className={`text-2xl font-bold ${failures > 0 ? 'text-[#ff3b3b]' : 'text-white'}`}>{failures}</div>
          <div className="text-xs text-[#9ca3af] mt-0.5">Intentos fallidos</div>
        </div>
        <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4">
          <div className={`text-2xl font-bold ${bruteForceIPs.length > 0 ? 'text-[#f59e0b]' : 'text-white'}`}>{bruteForceIPs.length}</div>
          <div className="text-xs text-[#9ca3af] mt-0.5">IPs sospechosas (10 min)</div>
        </div>
      </div>

      {bruteForceIPs.length > 0 && (
        <div className="flex items-start gap-3 px-4 py-3 bg-[#f59e0b]/10 border border-[#f59e0b]/30 rounded-xl">
          <ShieldAlert className="w-4 h-4 text-[#f59e0b] mt-0.5 shrink-0" />
          <div>
            <div className="text-sm font-semibold text-[#f59e0b]">Posible fuerza bruta detectada</div>
            <div className="text-xs text-[#9ca3af] mt-0.5">IPs con ≥5 fallos en los últimos 10 min: <span className="font-mono text-white">{bruteForceIPs.join(', ')}</span></div>
          </div>
        </div>
      )}

      <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2530]">
          <div className="flex items-center gap-2">
            <LogIn className="w-4 h-4 text-[#00d4ff]" />
            <span className="text-sm font-semibold text-white">Eventos de Inicio de Sesión</span>
            <span className="text-xs text-[#4b5563]">· ENS op.acc.1, op.exp.5</span>
          </div>
          <button onClick={load} disabled={loading} className="flex items-center gap-1.5 text-xs text-[#9ca3af] hover:text-[#00d4ff] transition-colors disabled:opacity-50">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Actualizar
          </button>
        </div>

        <div className="px-4 py-3 border-b border-[#1e2530] flex flex-wrap gap-2">
          <div className="relative flex-1 min-w-32">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#4b5563]" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Buscar por usuario, IP, rol..."
              className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-[#374151] focus:outline-none focus:border-[#00d4ff]" />
          </div>
          <select value={filterResult} onChange={e => setFilterResult(e.target.value as 'ALL' | 'SUCCESS' | 'FAIL')}
            className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#00d4ff]">
            <option value="ALL">Todos los resultados</option>
            <option value="SUCCESS">Solo exitosos</option>
            <option value="FAIL">Solo fallidos</option>
          </select>
          <select value={filterUser} onChange={e => setFilterUser(e.target.value)}
            className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#00d4ff]">
            <option value="ALL">Todos los usuarios</option>
            {uniqueUsers.map(u => <option key={u} value={u}>{u}</option>)}
          </select>
        </div>

        <div className="flex-1 overflow-auto min-h-[300px]">
          {loading && <div className="flex justify-center items-center py-16"><Loader2 className="w-6 h-6 animate-spin text-[#00d4ff]" /></div>}
          {!loading && error && (
            <div className="m-4 flex items-center gap-2 px-4 py-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg text-sm text-[#ff3b3b]">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              No se pudo obtener el historial. Comprueba que <code className="font-mono text-xs">/auth/login-events</code> está disponible.
            </div>
          )}
          {!loading && !error && filtered.length === 0 && (
            <p className="text-[#6b7280] text-sm text-center py-12">
              {events.length === 0 ? 'Sin eventos de sesión registrados aún.' : 'Sin resultados para los filtros aplicados.'}
            </p>
          )}
          {!loading && !error && filtered.length > 0 && (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[#1a1d27]">
                <tr className="text-left text-[#6b7280] border-b border-[#1e2530]">
                  <th className="px-3 py-2 font-medium">Timestamp</th>
                  <th className="px-3 py-2 font-medium">Usuario</th>
                  <th className="px-3 py-2 font-medium">Rol</th>
                  <th className="px-3 py-2 font-medium">Resultado</th>
                  <th className="px-3 py-2 font-medium">IP Origen</th>
                  <th className="px-3 py-2 font-medium">Det.</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2530]">
                {filtered.map((ev, idx) => (
                  <>
                    <tr key={idx} className={`hover:bg-[#1e2530]/40 transition-colors ${!ev.success ? 'border-l-2 border-[#ff3b3b]/40' : ''}`}>
                      <td className="px-3 py-2 font-mono text-[#9ca3af] whitespace-nowrap">{fmtDatetime(ev.timestamp)}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5">
                          <User className="w-3 h-3 text-[#4b5563] shrink-0" />
                          <span className="text-white font-medium">{ev.username}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2">{roleBadge(ev.role)}</td>
                      <td className="px-3 py-2">
                        {ev.success
                          ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-semibold bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]"><CheckCircle2 className="w-3 h-3" /> EXITOSO</span>
                          : <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-semibold bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]"><XCircle className="w-3 h-3" /> FALLIDO</span>
                        }
                      </td>
                      <td className="px-3 py-2 font-mono">
                        {ev.ip_origin
                          ? <span className={bruteForceIPs.includes(ev.ip_origin) ? 'text-[#f59e0b] font-semibold' : 'text-[#9ca3af]'}>
                              {ev.ip_origin}{bruteForceIPs.includes(ev.ip_origin) && <span className="ml-1">⚠</span>}
                            </span>
                          : <span className="text-[#4b5563]">—</span>
                        }
                      </td>
                      <td className="px-3 py-2">
                        <button onClick={() => setExpandedIdx(expandedIdx === idx ? null : idx)} className="text-[#6b7280] hover:text-[#00d4ff] transition-colors">
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                    {expandedIdx === idx && (
                      <tr key={`${idx}-detail`}>
                        <td colSpan={6} className="px-4 py-3 bg-[#0f1117] border-l-2 border-[#00d4ff]">
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                            {ev.reason && <div><span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">Motivo del fallo</span><span className="text-[#f59e0b]">{ev.reason}</span></div>}
                            {ev.user_agent && (
                              <div>
                                <div className="flex items-center gap-1 text-[10px] text-[#6b7280] uppercase tracking-wider mb-0.5"><Monitor className="w-3 h-3" /> User-Agent</div>
                                <span className="text-[#9ca3af] font-mono break-all">{ev.user_agent}</span>
                              </div>
                            )}
                            <div><span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">Timestamp UTC</span><span className="text-white font-mono">{ev.timestamp}</span></div>
                          </div>
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
          {filtered.length} eventos · buffer máx 500 · ENS op.acc.1, op.exp.5
        </div>
      </div>

      {/* ── Logins en Servidores (Wazuh/M5) ── */}
      <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2530]">
          <div className="flex items-center gap-2">
            <Monitor className="w-4 h-4 text-[#a78bfa]" />
            <span className="text-sm font-semibold text-white">Logins en Servidores</span>
            <span className="text-xs text-[#4b5563]">· SSH · ENS op.exp.5</span>
          </div>
          <div className="flex items-center gap-2">
            {srvLoading && <Loader2 className="w-3.5 h-3.5 animate-spin text-[#9ca3af]" />}
            {!srvLoading && srvFiltered.length > 0 && (
              <button
                onClick={exportSrvCSV}
                className="flex items-center gap-1.5 text-xs text-[#9ca3af] hover:text-[#a78bfa] transition-colors px-2 py-1 rounded border border-[#1e2530] hover:border-[#a78bfa]"
                title={`Exportar ${srvFiltered.length} eventos a CSV`}
              >
                <Download className="w-3.5 h-3.5" />
                Exportar CSV
              </button>
            )}
          </div>
        </div>

        {/* Filtros servidores */}
        <div className="px-4 py-3 border-b border-[#1e2530] flex flex-wrap gap-2">
          <div className="relative flex-1 min-w-32">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#4b5563]" />
            <input
              value={srvSearch}
              onChange={e => setSrvSearch(e.target.value)}
              placeholder="Buscar usuario, mensaje, IP..."
              className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-[#374151] focus:outline-none focus:border-[#a78bfa]"
            />
          </div>
          <select value={srvFilterServer} onChange={e => setSrvFilterServer(e.target.value)}
            className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa]">
            <option value="ALL">Todos los servidores</option>
            {srvServers.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={srvFilterSeverity} onChange={e => setSrvFilterSeverity(e.target.value)}
            className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa]">
            <option value="ALL">Todas las severidades</option>
            {srvSeverities.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={srvFilterResult} onChange={e => setSrvFilterResult(e.target.value as 'ALL' | 'SUCCESS' | 'FAIL')}
            className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa]">
            <option value="ALL">Todos los resultados</option>
            <option value="SUCCESS">Solo exitosos</option>
            <option value="FAIL">Solo fallidos</option>
          </select>
          <select value={srvFilterIP} onChange={e => setSrvFilterIP(e.target.value)}
            className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa]">
            <option value="ALL">Todas las IPs origen</option>
            {srvSourceIPs.map(ip => <option key={ip} value={ip}>{ip}</option>)}
          </select>
        </div>

        <div className="flex-1 overflow-auto min-h-[200px]">
          {srvLoading && (
            <div className="flex justify-center items-center py-10">
              <Loader2 className="w-5 h-5 animate-spin text-[#a78bfa]" />
            </div>
          )}
          {!srvLoading && srvError && (
            <div className="m-4 flex items-center gap-2 px-4 py-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg text-sm text-[#ff3b3b]">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              M5 SIEM no disponible — no se pudo conectar a <code className="font-mono text-xs">localhost:8006</code>.
            </div>
          )}
          {!srvLoading && !srvError && srvEvents.length === 0 && (
            <p className="text-[#6b7280] text-sm text-center py-8">Sin eventos de autenticación en servidores.</p>
          )}
          {!srvLoading && !srvError && srvEvents.length > 0 && srvFiltered.length === 0 && (
            <p className="text-[#6b7280] text-sm text-center py-8">Sin resultados para los filtros aplicados.</p>
          )}
          {!srvLoading && !srvError && srvFiltered.length > 0 && (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[#1a1d27]">
                <tr className="text-left text-[#6b7280] border-b border-[#1e2530]">
                  <th className="px-3 py-2 font-medium">Timestamp</th>
                  <th className="px-3 py-2 font-medium">Servidor</th>
                  <th className="px-3 py-2 font-medium">Evento</th>
                  <th className="px-3 py-2 font-medium">Severidad</th>
                  <th className="px-3 py-2 font-medium">MITRE</th>
                  <th className="px-3 py-2 font-medium">Det.</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2530]">
                {srvPaged.map(ev => {
                  const sevColor: Record<string, string> = {
                    CRITICAL: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',
                    HIGH:     'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',
                    MEDIUM:   'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]',
                    LOW:      'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]',
                    INFO:     'bg-[#374151]/30 border-[#4b5563]/30 text-[#9ca3af]',
                  };
                  return (
                    <>
                      <tr key={ev.alert_id} className="hover:bg-[#1e2530]/40 transition-colors">
                        <td className="px-3 py-2 font-mono text-[#9ca3af] whitespace-nowrap">{fmtDatetime(ev.timestamp)}</td>
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-1.5">
                            <Monitor className="w-3 h-3 text-[#4b5563] shrink-0" />
                            <span className="text-[#a78bfa] font-mono">{ev.agent_name}</span>
                            {ev.agent_ip && <span className="text-[#4b5563] font-mono text-[10px]">{ev.agent_ip}</span>}
                          </div>
                        </td>
                        <td className="px-3 py-2 text-white max-w-xs truncate" title={ev.rule_desc}>{ev.rule_desc}</td>
                        <td className="px-3 py-2">
                          <span className={`inline-flex px-2 py-0.5 rounded-full border text-[10px] font-semibold ${sevColor[ev.severity] ?? sevColor.INFO}`}>
                            {ev.severity}
                          </span>
                        </td>
                        <td className="px-3 py-2 font-mono text-[#6b7280] text-[10px]">
                          {ev.mitre_technique ?? '—'}
                        </td>
                        <td className="px-3 py-2">
                          <button onClick={() => setSrvExpanded(srvExpanded === ev.alert_id ? null : ev.alert_id)}
                            className="text-[#6b7280] hover:text-[#a78bfa] transition-colors">
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                      {srvExpanded === ev.alert_id && (
                        <tr key={`${ev.alert_id}-detail`}>
                          <td colSpan={6} className="px-4 py-3 bg-[#0f1117] border-l-2 border-[#a78bfa]">
                            <div className="space-y-2 text-xs">
                              <div>
                                <span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">Raw Log</span>
                                <code className="text-[#9ca3af] font-mono break-all">{ev.raw_log}</code>
                              </div>
                              <div className="grid grid-cols-2 gap-2">
                                <div><span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">Rule ID</span><span className="text-white font-mono">{ev.rule_id}</span></div>
                                <div><span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">Agent ID</span><span className="text-white font-mono">{ev.agent_id}</span></div>
                                {ev.mitre_tactic && <div><span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">MITRE Tactic</span><span className="text-white">{ev.mitre_tactic}</span></div>}
                                {ev.mitre_technique && <div><span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">MITRE Technique</span><span className="text-white font-mono">{ev.mitre_technique}</span></div>}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {srvTotalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-2 border-t border-[#1e2530]">
            <button
              onClick={() => setSrvPage(p => Math.max(1, p - 1))}
              disabled={srvPage === 1}
              className="text-xs text-[#9ca3af] hover:text-white disabled:opacity-30 disabled:cursor-not-allowed px-2 py-1 rounded border border-[#1e2530] hover:border-[#a78bfa] transition-colors"
            >
              ← Anterior
            </button>
            <span className="text-xs text-[#6b7280]">
              Página {srvPage} de {srvTotalPages} · {srvFiltered.length} eventos
            </span>
            <button
              onClick={() => setSrvPage(p => Math.min(srvTotalPages, p + 1))}
              disabled={srvPage === srvTotalPages}
              className="text-xs text-[#9ca3af] hover:text-white disabled:opacity-30 disabled:cursor-not-allowed px-2 py-1 rounded border border-[#1e2530] hover:border-[#a78bfa] transition-colors"
            >
              Siguiente →
            </button>
          </div>
        )}

        <div className="px-4 py-2 border-t border-[#1e2530] text-[10px] text-[#4b5563] font-mono">
          {srvFiltered.length} eventos · mostrando {srvPaged.length} · págs {srvTotalPages} · ENS op.exp.5
        </div>
      </div>
    </div>
  );
}

export function AuditLogsPage() {
  const [activeTab, setActiveTab]               = useState<'system' | 'assets' | 'sessions'>('system');
  const [orchestratorLogs, setOrchestratorLogs] = useState<OrchestratorLog[]>([]);
  const [sseConnected, setSseConnected]         = useState(false);
  const [assetLogs, setAssetLogs]               = useState<AssetAuditLog[]>([]);
  const [assetLoading, setAssetLoading]         = useState(true);
  const [assetError, setAssetError]             = useState(false);
  const [searchTerm, setSearchTerm]             = useState('');
  const [filterAction, setFilterAction]         = useState('ALL');
  const [filterAsset, setFilterAsset]           = useState('ALL');
  const [expandedRow, setExpandedRow]           = useState<number | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const token = getToken();
    const url = token
      ? `${ORCHESTRATOR_BASE}/orchestrator/logs/stream?token=${encodeURIComponent(token)}`
      : `${ORCHESTRATOR_BASE}/orchestrator/logs/stream`;
    const evtSource = new EventSource(url);
    evtSource.onopen    = () => setSseConnected(true);
    evtSource.onerror   = () => setSseConnected(false);
    evtSource.onmessage = (e) => {
      try {
        const entry: OrchestratorLog = { ...JSON.parse(e.data as string), _source: 'orchestrator' };
        setOrchestratorLogs(prev => [entry, ...prev].slice(0, 200));
      } catch { /* malformed */ }
    };
    return () => evtSource.close();
  }, []);

  useEffect(() => {
    if (logEndRef.current) logEndRef.current.scrollTop = logEndRef.current.scrollHeight;
  }, [orchestratorLogs]);

  useEffect(() => {
    const load = async () => {
      setAssetLoading(true); setAssetError(false);
      try {
        const assetsRes = await fetch(`${M1_BASE}/api/v1/assets?page=1&page_size=200`, { headers: authH(), signal: AbortSignal.timeout(10000) });
        if (!assetsRes.ok) throw new Error();
        const assetsData = await assetsRes.json() as { items?: { id: number; ip?: string }[] };
        const assets = (assetsData.items ?? []).slice(0, 10);
        const results = await Promise.allSettled(
          assets.map(async (asset) => {
            const res = await fetch(`${M1_BASE}/api/v1/assets/${asset.id}/audit?limit=50`, { headers: authH(), signal: AbortSignal.timeout(8000) });
            if (!res.ok) return [];
            const data = await res.json() as (Omit<AssetAuditLog, '_source' | '_asset_ip'>)[];
            return (Array.isArray(data) ? data : []).map(entry => ({ ...entry, _source: 'asset' as const, _asset_ip: asset.ip ?? String(asset.id) }));
          }),
        );
        const entries: AssetAuditLog[] = results.flatMap(r => r.status === 'fulfilled' ? r.value : []);
        entries.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        setAssetLogs(entries);
      } catch { setAssetError(true); }
      finally { setAssetLoading(false); }
    };
    load();
  }, []);

  const totalEntries  = orchestratorLogs.length + assetLogs.length;
  const errorCount    = orchestratorLogs.filter(l => l.level?.toUpperCase() === 'ERROR').length;
  const assetOpsCount = assetLogs.length;
  const lastActivity  = (() => {
    const allTs = [...orchestratorLogs.map(l => l.timestamp), ...assetLogs.map(l => l.timestamp)].filter(Boolean);
    if (!allTs.length) return '—';
    return fmtTime(allTs.reduce((a, b) => (a > b ? a : b)));
  })();

  const assetIPs      = [...new Set(assetLogs.map(l => l._asset_ip).filter(Boolean))];
  const filteredAsset = assetLogs.filter(l => {
    const q = searchTerm.toLowerCase();
    const matchSearch = !q || (l.user_id ?? '').toLowerCase().includes(q) || (l.action ?? '').toLowerCase().includes(q) || (l.ip_origin ?? '').toLowerCase().includes(q) || (l._asset_ip ?? '').toLowerCase().includes(q);
    return matchSearch && (filterAction === 'ALL' || l.action === filterAction) && (filterAsset === 'ALL' || l._asset_ip === filterAsset);
  });

  const actionBadge = (action: string) => {
    const cfg: Record<string, { cls: string; icon: React.ReactNode; label: string }> = {
      CREATE: { cls: 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]', icon: <Plus className="w-3 h-3" />,   label: 'CREATE' },
      UPDATE: { cls: 'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]', icon: <Pencil className="w-3 h-3" />, label: 'UPDATE' },
      DELETE: { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]', icon: <Trash2 className="w-3 h-3" />, label: 'DELETE' },
    };
    const c = cfg[action] ?? { cls: 'bg-[#374151]/30 border-[#4b5563]/30 text-[#6b7280]', icon: null, label: action };
    return <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-xs font-semibold ${c.cls}`}>{c.icon}{c.label}</span>;
  };

  const Tab = ({ id, label, icon: Icon }: { id: typeof activeTab; label: string; icon: React.ElementType }) => (
    <button onClick={() => setActiveTab(id)}
      className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === id ? 'border-[#00d4ff] text-[#00d4ff]' : 'border-transparent text-[#9ca3af] hover:text-white hover:border-[#374151]'}`}>
      <Icon className="w-4 h-4" />{label}
    </button>
  );

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="Auditor" />
        <main className="flex-1 overflow-auto p-6 space-y-6">

          <div>
            <h1 className="text-2xl font-semibold text-white mb-1">Logs de Auditoría</h1>
            <p className="text-[#9ca3af] text-sm">Trazabilidad completa del sistema · ENS op.exp.5 · RD 311/2022</p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4"><div className="text-2xl font-bold text-white">{totalEntries}</div><div className="text-xs text-[#9ca3af] mt-0.5">Total entradas sistema</div></div>
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4"><div className="text-2xl font-bold text-[#ff3b3b]">{errorCount}</div><div className="text-xs text-[#9ca3af] mt-0.5">Errores del sistema</div></div>
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4"><div className="text-2xl font-bold text-[#00d4ff]">{assetOpsCount}</div><div className="text-xs text-[#9ca3af] mt-0.5">Operaciones sobre activos</div></div>
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4"><div className="text-2xl font-bold text-white font-mono">{lastActivity}</div><div className="text-xs text-[#9ca3af] mt-0.5">Última actividad</div></div>
          </div>

          <div className="border-b border-[#1e2530] flex gap-0 -mb-2">
            <Tab id="system"   label="Sistema — Live"     icon={Activity} />
            <Tab id="assets"   label="Auditoría Activos"  icon={Search} />
            <Tab id="sessions" label="Sesiones de Acceso" icon={LogIn} />
          </div>

          {activeTab === 'system' && (
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl overflow-hidden flex flex-col">
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2530]">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#00d4ff]" />
                  <span className="text-sm font-semibold text-white">Orchestrator — Live</span>
                  <span className={`flex items-center gap-1 text-xs ${sseConnected ? 'text-[#22c55e]' : 'text-[#ff3b3b]'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${sseConnected ? 'bg-[#22c55e] animate-pulse' : 'bg-[#ff3b3b]'}`} />
                    {sseConnected ? 'Conectado' : 'Desconectado'}
                  </span>
                </div>
                <button onClick={() => setOrchestratorLogs([])} className="text-[#6b7280] hover:text-[#ff3b3b] transition-colors p-1 rounded">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
              <div ref={logEndRef} className="flex-1 bg-[#0f1117] p-3 font-mono text-xs overflow-y-auto h-80 space-y-0.5">
                {orchestratorLogs.length === 0 && <div className="text-[#4b5563] italic">Esperando logs del orchestrator...</div>}
                {[...orchestratorLogs].reverse().map((log, i) => (
                  <div key={i} className={`leading-5 ${levelColor(log.level)}`}>
                    <span className="text-[#4b5563]">[{fmtTime(log.timestamp)}]</span>{' '}
                    <span className="text-[#6b7280]">[{log.module}]</span>{' '}{log.message}
                  </div>
                ))}
              </div>
              <div className="px-4 py-2 border-t border-[#1e2530] text-[10px] text-[#4b5563] font-mono">{orchestratorLogs.length} entradas · máx 200</div>
            </div>
          )}

          {activeTab === 'assets' && (
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl overflow-hidden flex flex-col">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1e2530]">
                <Search className="w-4 h-4 text-[#00d4ff]" />
                <span className="text-sm font-semibold text-white">Auditoría de Activos (M1)</span>
              </div>
              <div className="px-4 py-3 border-b border-[#1e2530] flex flex-wrap gap-2">
                <div className="relative flex-1 min-w-32">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#4b5563]" />
                  <input value={searchTerm} onChange={e => setSearchTerm(e.target.value)} placeholder="Buscar..."
                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-[#374151] focus:outline-none focus:border-[#00d4ff]" />
                </div>
                <select value={filterAction} onChange={e => setFilterAction(e.target.value)}
                  className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#00d4ff]">
                  <option value="ALL">Todas las acciones</option>
                  <option value="CREATE">CREATE</option>
                  <option value="UPDATE">UPDATE</option>
                  <option value="DELETE">DELETE</option>
                </select>
                <select value={filterAsset} onChange={e => setFilterAsset(e.target.value)}
                  className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#00d4ff]">
                  <option value="ALL">Todos los activos</option>
                  {assetIPs.map(ip => <option key={ip} value={ip}>{ip}</option>)}
                </select>
              </div>
              <div className="flex-1 overflow-auto">
                {assetLoading && <div className="flex justify-center items-center py-12"><Loader2 className="w-6 h-6 animate-spin text-[#00d4ff]" /></div>}
                {!assetLoading && assetError && (
                  <div className="m-4 flex items-center gap-2 px-4 py-3 bg-[#f59e0b]/10 border border-[#f59e0b]/20 rounded-lg text-sm text-[#f59e0b]">
                    <AlertTriangle className="w-4 h-4 shrink-0" /> M1 no disponible — no se pudo cargar el historial de auditoría.
                  </div>
                )}
                {!assetLoading && !assetError && filteredAsset.length === 0 && <p className="text-[#6b7280] text-sm text-center py-8">Sin registros de auditoría disponibles.</p>}
                {!assetLoading && !assetError && filteredAsset.length > 0 && (
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-[#1a1d27]">
                      <tr className="text-left text-[#6b7280] border-b border-[#1e2530]">
                        <th className="px-3 py-2 font-medium">Timestamp</th><th className="px-3 py-2 font-medium">Activo</th>
                        <th className="px-3 py-2 font-medium">Acción</th><th className="px-3 py-2 font-medium">Usuario</th>
                        <th className="px-3 py-2 font-medium">Rol</th><th className="px-3 py-2 font-medium">IP Origen</th>
                        <th className="px-3 py-2 font-medium">Det.</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2530]">
                      {filteredAsset.map(log => (
                        <>
                          <tr key={log.id} className="hover:bg-[#1e2530]/40 transition-colors">
                            <td className="px-3 py-2 font-mono text-[#9ca3af] whitespace-nowrap">{fmtDatetime(log.timestamp)}</td>
                            <td className="px-3 py-2 font-mono text-[#00d4ff]">{log._asset_ip ?? String(log.asset_id)}</td>
                            <td className="px-3 py-2">{actionBadge(log.action)}</td>
                            <td className="px-3 py-2 text-white">{log.user_id}</td>
                            <td className="px-3 py-2">
                              {log.user_role
                                ? <span className="px-1.5 py-0.5 bg-[#374151]/40 text-[#9ca3af] border border-[#4b5563]/30 rounded text-[10px]">{log.user_role}</span>
                                : <span className="text-[#4b5563]">—</span>}
                            </td>
                            <td className="px-3 py-2 font-mono text-[#9ca3af]">{log.ip_origin ?? '—'}</td>
                            <td className="px-3 py-2">
                              <button onClick={() => setExpandedRow(expandedRow === log.id ? null : log.id)} className="text-[#6b7280] hover:text-[#00d4ff] transition-colors">
                                <Eye className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>
                          {expandedRow === log.id && (
                            <tr key={`${log.id}-detail`}>
                              <td colSpan={7} className="px-4 py-3 bg-[#0f1117] border-l-2 border-[#00d4ff]">
                                {log.reason && <div className="mb-2"><span className="text-[10px] text-[#6b7280] uppercase tracking-wider">Motivo: </span><span className="text-xs text-white">{log.reason}</span></div>}
                                {log.changes && Object.keys(log.changes).length > 0
                                  ? <div><div className="text-[10px] text-[#6b7280] uppercase tracking-wider mb-1">Cambios</div><pre className="bg-[#080a10] rounded p-3 font-mono text-xs text-[#9ca3af] max-h-40 overflow-y-auto">{JSON.stringify(log.changes, null, 2)}</pre></div>
                                  : !log.reason ? <span className="text-xs text-[#4b5563]">Sin detalles adicionales.</span> : null}
                              </td>
                            </tr>
                          )}
                        </>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
              <div className="px-4 py-2 border-t border-[#1e2530] text-[10px] text-[#4b5563] font-mono">{filteredAsset.length} entradas · máx 500 por carga</div>
            </div>
          )}

          {activeTab === 'sessions' && <LoginSessionsTab />}

          <div className="text-center text-xs text-[#4b5563]">Logs inmutables · ENS op.exp.5 · RD 311/2022 · Retención mínima 2 años</div>

        </main>
      </div>
    </div>
  );
}
