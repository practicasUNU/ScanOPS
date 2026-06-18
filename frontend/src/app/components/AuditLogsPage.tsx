// frontend/src/app/components/AuditLogsPage.tsx
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  Search, Loader2, AlertTriangle, Trash2, Eye,
  Plus, Pencil, Activity, LogIn, ShieldAlert, RefreshCw,
  CheckCircle2, XCircle, User, Monitor, Download, Filter,
} from 'lucide-react';
import { useState, useEffect, useRef } from 'react';

const ORCHESTRATOR_BASE = '/api/orchestrator';
const M1_BASE           = '/api/m1';
const AUTH_BASE         = '/api/orchestrator';

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
  action_type?: string;
  command?: string;
  port?: string;
}

interface ServerStat {
  agent_name: string;
  agent_ip: string;
  total: number;
  failures: number;
  successes: number;
  sudo_cmds: number;
  unique_ips: string[];
  unique_users: string[];
  critical_count: number;
  high_count: number;
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return ts; }
}
function fmtDatetime(ts: string): string {
  try { return new Date(ts).toLocaleString('es-ES', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return ts; }
}
function DateTimeCell({ ts }: { ts: string }) {
  try {
    const d = new Date(ts);
    const date = d.toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit', year: 'numeric' });
    const time = d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    return (
      <div className="whitespace-nowrap">
        <div className="font-mono text-sm text-white font-semibold">{time}</div>
        <div className="font-mono text-[11px] text-[#475569]">{date}</div>
      </div>
    );
  } catch {
    return <span className="font-mono text-[#64748B] text-xs">{ts}</span>;
  }
}
function levelColor(level: string): string {
  switch (level?.toUpperCase()) {
    case 'ERROR': return 'text-[#ff3b3b]';
    case 'WARN':  return 'text-[#f59e0b]';
    case 'SUCCESS': return 'text-[#22c55e]';
    default: return 'text-[#64748B]';
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
  const [srvStats, setSrvStats]           = useState<ServerStat[]>([]);
  const [srvBruteIPs, setSrvBruteIPs]     = useState<string[]>([]);
  const [srvLastLoad, setSrvLastLoad]     = useState<Date | null>(null);

  const [srvSearch, setSrvSearch]               = useState('');
  const [srvFilterServer, setSrvFilterServer]   = useState('ALL');
  const [srvFilterSeverity, setSrvFilterSeverity] = useState('ALL');
  const [srvFilterResult, setSrvFilterResult]   = useState<'ALL' | 'SUCCESS' | 'FAIL'>('ALL');
  const [srvFilterIP, setSrvFilterIP]           = useState('ALL');
  const [srvDateFrom, setSrvDateFrom]           = useState('');
  const [srvDateTo, setSrvDateTo]               = useState('');
  const [srvFilterAction, setSrvFilterAction]   = useState('ALL');
  const [srvPage, setSrvPage]                   = useState(1);
  const SRV_PAGE_SIZE = 20;
  const [liveMode, setLiveMode]           = useState(false);
  const [liveCountdown, setLiveCountdown] = useState(60);

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

  const loadSrv = async () => {
    setSrvLoading(true); setSrvError(false);
    try {
      const res = await fetch(
        '/api/m5/siem/auth-events?limit=500',
        { headers: authH(), signal: AbortSignal.timeout(45000) }
      );
      if (!res.ok) throw new Error();
      const data = await res.json() as {
        total: number;
        events: SIEMAlert[];
        server_stats?: ServerStat[];
        brute_force_ips?: string[];
      };
      setSrvEvents(data.events ?? []);
      setSrvStats(data.server_stats ?? []);
      setSrvBruteIPs(data.brute_force_ips ?? []);
      setSrvLastLoad(new Date());
    } catch { setSrvError(true); }
    finally { setSrvLoading(false); }
  };

  useEffect(() => { loadSrv(); }, []);

  useEffect(() => { setSrvPage(1); }, [srvSearch, srvFilterServer, srvFilterSeverity, srvFilterResult, srvFilterIP, srvDateFrom, srvDateTo, srvFilterAction]);

  useEffect(() => {
    if (!liveMode) { setLiveCountdown(60); return; }
    setLiveCountdown(60);
    const countdown = setInterval(() => {
      setLiveCountdown(prev => (prev <= 1 ? 60 : prev - 1));
    }, 1000);
    const refresh = setInterval(() => { loadSrv(); }, 60000);
    return () => { clearInterval(countdown); clearInterval(refresh); };
  }, [liveMode]);

  const srvServers    = [...new Set(srvEvents.map(e => e.agent_name).filter(Boolean))];
  const srvSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const srvSourceIPs  = [...new Set(srvEvents.map(e => e.src_ip).filter(Boolean))] as string[];

  const srvFiltered = srvEvents.filter(e => {
    const q = srvSearch.toLowerCase();
    const matchSearch = !q ||
      (e.agent_name ?? '').toLowerCase().includes(q) ||
      (e.rule_desc ?? '').toLowerCase().includes(q) ||
      (e.raw_log ?? '').toLowerCase().includes(q) ||
      (e.src_ip ?? '').toLowerCase().includes(q) ||
      (e.src_user ?? '').toLowerCase().includes(q) ||
      (e.command ?? '').toLowerCase().includes(q);
    const matchServer   = srvFilterServer === 'ALL' || e.agent_name === srvFilterServer;
    const matchSeverity = srvFilterSeverity === 'ALL' || e.severity === srvFilterSeverity;
    const matchResult   = srvFilterResult === 'ALL' ||
      (srvFilterResult === 'SUCCESS' && !!e.success) ||
      (srvFilterResult === 'FAIL' && !e.success);
    const matchIP     = srvFilterIP === 'ALL' || e.src_ip === srvFilterIP;
    const matchAction = srvFilterAction === 'ALL' || e.action_type === srvFilterAction;
    const matchDateFrom = !srvDateFrom || e.timestamp >= srvDateFrom;
    const matchDateTo   = !srvDateTo   || e.timestamp <= srvDateTo + 'T23:59:59';
    return matchSearch && matchServer && matchSeverity && matchResult && matchIP && matchAction && matchDateFrom && matchDateTo;
  });

  const srvTotalPages = Math.max(1, Math.ceil(srvFiltered.length / SRV_PAGE_SIZE));
  const srvPaged = srvFiltered.slice((srvPage - 1) * SRV_PAGE_SIZE, srvPage * SRV_PAGE_SIZE);

  const exportSrvCSV = () => {
    const headers = [
      'Timestamp', 'Servidor', 'IP Servidor', 'Agent ID',
      'Tipo Acción', 'Resultado', 'Severidad',
      'IP Origen', 'Puerto', 'Usuario', 'Comando',
      'Evento', 'MITRE Táctica', 'MITRE Técnica', 'Raw Log',
    ];
    const escape = (val: unknown): string => {
      const str = val == null ? '' : String(val);
      if (str.includes(',') || str.includes('"') || str.includes('\n'))
        return `"${str.replace(/"/g, '""')}"`;
      return str;
    };
    const rows = srvFiltered.map(e => [
      escape(e.timestamp), escape(e.agent_name), escape(e.agent_ip), escape(e.agent_id),
      escape(e.action_type ?? ''), escape(e.success ? 'EXITOSO' : 'FALLIDO'), escape(e.severity),
      escape(e.src_ip ?? ''), escape(e.port ?? ''), escape(e.src_user ?? ''), escape(e.command ?? ''),
      escape(e.rule_desc), escape(e.mitre_tactic ?? ''), escape(e.mitre_technique ?? ''), escape(e.raw_log),
    ].join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scanops_server_logins_ENS_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
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

  const actionBadgeSrv = (action: string | undefined) => {
    const cfg: Record<string, { cls: string; label: string }> = {
      SSH_LOGIN_OK:     { cls: 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]',   label: '✓ SSH OK' },
      SSH_LOGIN_FAIL:   { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',   label: '✗ SSH FAIL' },
      SSH_INVALID_USER: { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',   label: '✗ INVÁLIDO' },
      SSH_ABORT:        { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',   label: '⚡ ABORT' },
      SESSION_OPEN:     { cls: 'bg-[#8B5CF6]/10 border-[#8B5CF6]/30 text-[#8B5CF6]',   label: '▶ SESIÓN' },
      SESSION_CLOSE:    { cls: 'bg-[#374151]/30 border-[#334155]/30 text-[#64748B]',   label: '■ FIN SESIÓN' },
      SUDO_COMMAND:     { cls: 'bg-[#a78bfa]/10 border-[#a78bfa]/30 text-[#a78bfa]',   label: '⚡ SUDO' },
      SUDO_FAIL:        { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',   label: '✗ SUDO FAIL' },
      SU_OK:            { cls: 'bg-[#a78bfa]/10 border-[#a78bfa]/30 text-[#a78bfa]',   label: '▲ SU OK' },
      SU_FAIL:          { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',   label: '✗ SU FAIL' },
      USER_CREATED:     { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',   label: '+ USUARIO' },
      USER_DELETED:     { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',   label: '− USUARIO' },
      USER_MODIFIED:    { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',   label: '✎ USUARIO' },
      GROUP_CREATED:    { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',   label: '+ GRUPO' },
      PASSWORD_CHANGED: { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',   label: '🔑 PASSWD' },
      ACCOUNT_LOCKED:   { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',   label: '🔒 BLOQUEADO' },
      ACCOUNT_LOCKOUT:  { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',   label: '🔒 LOCKOUT' },
      AUTH_FAILURE:     { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',   label: '✗ AUTH FAIL' },
      PRIV_ESCALATION:  { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',   label: '⚠ ESCALADA' },
      OTHER:            { cls: 'bg-[#374151]/30 border-[#334155]/30 text-[#475569]',   label: 'OTRO' },
    };
    const c = cfg[action ?? 'OTHER'] ?? cfg['OTHER'];
    return (
      <span className={`inline-flex px-2 py-0.5 rounded-full border text-[10px] font-semibold whitespace-nowrap ${c.cls}`}>
        {c.label}
      </span>
    );
  };

  const roleBadge = (role: string | null) => {
    if (!role) return <span className="text-[#334155]">—</span>;
    const colors: Record<string, string> = {
      system_manager:   'bg-[#8B5CF6]/10 border-[#8B5CF6]/30 text-[#8B5CF6]',
      security_officer: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',
      auditor:          'bg-[#a78bfa]/10 border-[#a78bfa]/30 text-[#a78bfa]',
    };
    const cls = colors[role] ?? 'bg-[#374151]/30 border-[#334155]/30 text-[#475569]';
    return <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-semibold ${cls}`}>{role}</span>;
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4">
          <div className="text-2xl font-bold text-white">{total}</div>
          <div className="text-xs text-[#64748B] mt-0.5">Intentos totales</div>
        </div>
        <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4">
          <div className="text-2xl font-bold text-[#22c55e]">{successes}</div>
          <div className="text-xs text-[#64748B] mt-0.5">Sesiones exitosas</div>
        </div>
        <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4">
          <div className={`text-2xl font-bold ${failures > 0 ? 'text-[#ff3b3b]' : 'text-white'}`}>{failures}</div>
          <div className="text-xs text-[#64748B] mt-0.5">Intentos fallidos</div>
        </div>
        <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4">
          <div className={`text-2xl font-bold ${bruteForceIPs.length > 0 ? 'text-[#f59e0b]' : 'text-white'}`}>{bruteForceIPs.length}</div>
          <div className="text-xs text-[#64748B] mt-0.5">IPs sospechosas (10 min)</div>
        </div>
      </div>

      {bruteForceIPs.length > 0 && (
        <div className="flex items-start gap-3 px-4 py-3 bg-[#f59e0b]/10 border border-[#f59e0b]/30 rounded-xl">
          <ShieldAlert className="w-4 h-4 text-[#f59e0b] mt-0.5 shrink-0" />
          <div>
            <div className="text-sm font-semibold text-[#f59e0b]">Posible fuerza bruta detectada</div>
            <div className="text-xs text-[#64748B] mt-0.5">IPs con ≥5 fallos en los últimos 10 min: <span className="font-mono text-white">{bruteForceIPs.join(', ')}</span></div>
          </div>
        </div>
      )}

      <div className="bg-[#111318] border border-[#1C2030] rounded-xl overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#1C2030]">
          <div className="flex items-center gap-2">
            <LogIn className="w-4 h-4 text-[#8B5CF6]" />
            <span className="text-sm font-semibold text-white">Eventos de Inicio de Sesión</span>
            <span className="text-xs text-[#334155]">· ENS op.acc.1, op.exp.5</span>
          </div>
          <button onClick={load} disabled={loading} className="flex items-center gap-1.5 text-xs text-[#64748B] hover:text-[#8B5CF6] transition-colors disabled:opacity-50">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Actualizar
          </button>
        </div>

        <div className="px-4 py-3 border-b border-[#1C2030] flex flex-wrap gap-2">
          <div className="relative flex-1 min-w-32">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#334155]" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Buscar por usuario, IP, rol..."
              className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-[#374151] focus:outline-none focus:border-[#8B5CF6]" />
          </div>
          <select value={filterResult} onChange={e => setFilterResult(e.target.value as 'ALL' | 'SUCCESS' | 'FAIL')}
            className="bg-[#0A0C10] border border-[#1C2030] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#8B5CF6]">
            <option value="ALL">Todos los resultados</option>
            <option value="SUCCESS">Solo exitosos</option>
            <option value="FAIL">Solo fallidos</option>
          </select>
          <select value={filterUser} onChange={e => setFilterUser(e.target.value)}
            className="bg-[#0A0C10] border border-[#1C2030] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#8B5CF6]">
            <option value="ALL">Todos los usuarios</option>
            {uniqueUsers.map(u => <option key={u} value={u}>{u}</option>)}
          </select>
        </div>

        <div className="flex-1 overflow-auto min-h-[300px]">
          {loading && <div className="flex justify-center items-center py-16"><Loader2 className="w-6 h-6 animate-spin text-[#8B5CF6]" /></div>}
          {!loading && error && (
            <div className="m-4 flex items-center gap-2 px-4 py-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg text-sm text-[#ff3b3b]">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              No se pudo obtener el historial. Comprueba que <code className="font-mono text-xs">/auth/login-events</code> está disponible.
            </div>
          )}
          {!loading && !error && filtered.length === 0 && (
            <p className="text-[#475569] text-sm text-center py-12">
              {events.length === 0 ? 'Sin eventos de sesión registrados aún.' : 'Sin resultados para los filtros aplicados.'}
            </p>
          )}
          {!loading && !error && filtered.length > 0 && (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[#111318]">
                <tr className="text-left text-[#475569] border-b border-[#1C2030]">
                  <th className="px-3 py-2 font-medium">Timestamp</th>
                  <th className="px-3 py-2 font-medium">Usuario</th>
                  <th className="px-3 py-2 font-medium">Rol</th>
                  <th className="px-3 py-2 font-medium">Resultado</th>
                  <th className="px-3 py-2 font-medium">IP Origen</th>
                  <th className="px-3 py-2 font-medium">Det.</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1C2030]">
                {filtered.map((ev, idx) => (
                  <>
                    <tr key={idx} className={`hover:bg-[#1C2030]/40 transition-colors ${!ev.success ? 'border-l-2 border-[#ff3b3b]/40' : ''}`}>
                      <td className="px-3 py-2"><DateTimeCell ts={ev.timestamp} /></td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5">
                          <User className="w-3 h-3 text-[#334155] shrink-0" />
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
                          ? <span className={bruteForceIPs.includes(ev.ip_origin) ? 'text-[#f59e0b] font-semibold' : 'text-[#64748B]'}>
                              {ev.ip_origin}{bruteForceIPs.includes(ev.ip_origin) && <span className="ml-1">⚠</span>}
                            </span>
                          : <span className="text-[#334155]">—</span>
                        }
                      </td>
                      <td className="px-3 py-2">
                        <button onClick={() => setExpandedIdx(expandedIdx === idx ? null : idx)} className="text-[#475569] hover:text-[#8B5CF6] transition-colors">
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                    {expandedIdx === idx && (
                      <tr key={`${idx}-detail`}>
                        <td colSpan={6} className="px-4 py-3 bg-[#0A0C10] border-l-2 border-[#8B5CF6]">
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                            {ev.reason && <div><span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-0.5">Motivo del fallo</span><span className="text-[#f59e0b]">{ev.reason}</span></div>}
                            {ev.user_agent && (
                              <div>
                                <div className="flex items-center gap-1 text-[10px] text-[#475569] uppercase tracking-wider mb-0.5"><Monitor className="w-3 h-3" /> User-Agent</div>
                                <span className="text-[#64748B] font-mono break-all">{ev.user_agent}</span>
                              </div>
                            )}
                            <div><span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-0.5">Timestamp UTC</span><span className="text-white font-mono">{ev.timestamp}</span></div>
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
        <div className="px-4 py-2 border-t border-[#1C2030] text-[10px] text-[#334155] font-mono">
          {filtered.length} eventos · buffer máx 500 · ENS op.acc.1, op.exp.5
        </div>
      </div>

      {/* ── Logins en Servidores ── */}
      <div className="space-y-3">

        {/* KPIs por servidor */}
        {srvStats.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {srvStats.map(s => (
              <div key={s.agent_ip} className={`bg-[#111318] border rounded-xl p-4 ${s.critical_count > 0 ? 'border-[#ff3b3b]/40' : s.high_count > 0 ? 'border-[#f59e0b]/30' : 'border-[#1C2030]'}`}>
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <div className="text-sm font-semibold text-[#a78bfa]">{s.agent_name}</div>
                    <div className="text-[10px] font-mono text-[#334155]">{s.agent_ip}</div>
                  </div>
                  {(s.critical_count > 0 || s.high_count > 0) && (
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${s.critical_count > 0 ? 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]' : 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]'}`}>
                      {s.critical_count > 0 ? `${s.critical_count} CRITICAL` : `${s.high_count} HIGH`}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="bg-[#0A0C10] rounded-lg p-2">
                    <div className="text-lg font-bold text-white">{s.total}</div>
                    <div className="text-[10px] text-[#475569]">Total</div>
                  </div>
                  <div className="bg-[#0A0C10] rounded-lg p-2">
                    <div className={`text-lg font-bold ${s.failures > 0 ? 'text-[#ff3b3b]' : 'text-white'}`}>{s.failures}</div>
                    <div className="text-[10px] text-[#475569]">Fallos</div>
                  </div>
                  <div className="bg-[#0A0C10] rounded-lg p-2">
                    <div className={`text-lg font-bold ${s.sudo_cmds > 0 ? 'text-[#a78bfa]' : 'text-white'}`}>{s.sudo_cmds}</div>
                    <div className="text-[10px] text-[#475569]">Sudo</div>
                  </div>
                </div>
                <div className="mt-2 flex gap-3 text-[10px] text-[#475569]">
                  <span>{s.unique_users.length} usuario{s.unique_users.length !== 1 ? 's' : ''}</span>
                  <span>·</span>
                  <span>{s.unique_ips.length} IP{s.unique_ips.length !== 1 ? 's' : ''} origen</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Alerta brute force servidores */}
        {srvBruteIPs.length > 0 && (
          <div className="flex items-start gap-3 px-4 py-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 rounded-xl">
            <ShieldAlert className="w-4 h-4 text-[#ff3b3b] mt-0.5 shrink-0" />
            <div>
              <div className="text-sm font-semibold text-[#ff3b3b]">⚠ Ataque de fuerza bruta detectado en servidores</div>
              <div className="text-xs text-[#64748B] mt-0.5">
                IPs con ≥5 fallos SSH en los últimos 10 min:{' '}
                <span className="font-mono text-white">{srvBruteIPs.join(', ')}</span>
              </div>
              <div className="text-[10px] text-[#475569] mt-1">ENS op.acc.6 — Bloqueo recomendado · Registrar como incidente</div>
            </div>
          </div>
        )}

        {/* Tabla principal */}
        <div className="bg-[#111318] border border-[#1C2030] rounded-xl overflow-hidden flex flex-col">

          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#1C2030]">
            <div className="flex items-center gap-2">
              <Monitor className="w-4 h-4 text-[#a78bfa]" />
              <span className="text-sm font-semibold text-white">Logins en Servidores</span>
              <span className="text-xs text-[#334155]">· SSH auth.log · ENS op.acc.1, op.acc.6, op.exp.5</span>
            </div>
            <div className="flex items-center gap-2">
              {srvLastLoad && (
                <span className="text-[10px] text-[#334155] font-mono">
                  Última carga: {fmtTime(srvLastLoad.toISOString())}
                </span>
              )}
              <button
                onClick={() => setLiveMode(m => !m)}
                className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded border transition-colors ${
                  liveMode
                    ? 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]'
                    : 'border-[#1C2030] text-[#64748B] hover:text-white hover:border-[#374151]'
                }`}
                title={liveMode ? 'Desactivar refresco automático' : 'Activar refresco automático cada 60s'}
              >
                {liveMode && <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] animate-pulse" />}
                {liveMode ? `Live · ${liveCountdown}s` : 'Live'}
              </button>
              <button
                onClick={() => { setSrvLoading(true); loadSrv(); }}
                disabled={srvLoading}
                className="flex items-center gap-1.5 text-xs text-[#64748B] hover:text-[#a78bfa] transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${srvLoading ? 'animate-spin' : ''}`} />
                Actualizar
              </button>
              {!srvLoading && srvFiltered.length > 0 && (
                <button
                  onClick={exportSrvCSV}
                  className="flex items-center gap-1.5 text-xs font-semibold text-white bg-[#a78bfa] hover:bg-[#9061f9] transition-colors px-3 py-1.5 rounded-lg"
                  title={`Exportar ${srvFiltered.length} eventos a CSV — evidencia ENS`}
                >
                  <Download className="w-3.5 h-3.5" />
                  Exportar CSV
                </button>
              )}
            </div>
          </div>

          {/* Filtros */}
          <div className="px-4 py-3 border-b border-[#1C2030] grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2 items-end">
            <div className="col-span-2 flex flex-col gap-1">
              <label className="text-[10px] text-[#475569] uppercase tracking-wider">Búsqueda</label>
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#334155]" />
                <input value={srvSearch} onChange={e => setSrvSearch(e.target.value)}
                  placeholder="usuario, IP, comando..."
                  className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-[#374151] focus:outline-none focus:border-[#a78bfa]" />
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-[#475569] uppercase tracking-wider">Desde</label>
              <input type="date" value={srvDateFrom} onChange={e => setSrvDateFrom(e.target.value)}
                className="bg-[#0A0C10] border border-[#1C2030] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa] [color-scheme:dark]" />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-[#475569] uppercase tracking-wider">Hasta</label>
              <input type="date" value={srvDateTo} onChange={e => setSrvDateTo(e.target.value)}
                className="bg-[#0A0C10] border border-[#1C2030] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa] [color-scheme:dark]" />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-[#475569] uppercase tracking-wider">Servidor</label>
              <select value={srvFilterServer} onChange={e => setSrvFilterServer(e.target.value)}
                className="bg-[#0A0C10] border border-[#1C2030] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa]">
                <option value="ALL">Todos</option>
                {srvServers.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-[#475569] uppercase tracking-wider">Tipo acción</label>
              <select value={srvFilterAction} onChange={e => setSrvFilterAction(e.target.value)}
                className="bg-[#0A0C10] border border-[#1C2030] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa]">
                <option value="ALL">Todas</option>
                <option value="SSH_LOGIN_OK">SSH OK</option>
                <option value="SSH_LOGIN_FAIL">SSH Fail</option>
                <option value="SSH_INVALID_USER">Inválido</option>
                <option value="SESSION_OPEN">Sesión abierta</option>
                <option value="SESSION_CLOSE">Sesión cerrada</option>
                <option value="SUDO_COMMAND">Sudo</option>
                <option value="SUDO_FAIL">Sudo fail</option>
                <option value="SU_OK">Su OK</option>
                <option value="SU_FAIL">Su fail</option>
                <option value="USER_CREATED">Usuario creado</option>
                <option value="USER_DELETED">Usuario eliminado</option>
                <option value="USER_MODIFIED">Usuario modificado</option>
                <option value="PASSWORD_CHANGED">Passwd cambiada</option>
                <option value="ACCOUNT_LOCKED">Cuenta bloqueada</option>
                <option value="AUTH_FAILURE">Auth failure</option>
                <option value="PRIV_ESCALATION">Escalada</option>
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-[#475569] uppercase tracking-wider">Severidad</label>
              <select value={srvFilterSeverity} onChange={e => setSrvFilterSeverity(e.target.value)}
                className="bg-[#0A0C10] border border-[#1C2030] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa]">
                <option value="ALL">Todas</option>
                {srvSeverities.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div className="flex gap-1.5 items-end">
              <button onClick={() => setSrvPage(1)}
                className="flex-1 text-xs font-semibold text-white bg-[#8B5CF6] hover:bg-[#00b8d9] transition-colors px-3 py-1.5 rounded-lg">
                Filtrar
              </button>
              <button onClick={() => {
                setSrvSearch(''); setSrvFilterServer('ALL'); setSrvFilterSeverity('ALL');
                setSrvFilterResult('ALL'); setSrvFilterIP('ALL'); setSrvFilterAction('ALL');
                setSrvDateFrom(''); setSrvDateTo(''); setSrvPage(1);
              }}
                className="text-xs text-[#64748B] hover:text-white border border-[#1C2030] hover:border-[#334155] transition-colors px-2 py-1.5 rounded-lg"
                title="Limpiar filtros">
                <XCircle className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Contenido tabla */}
          <div className="flex-1 overflow-auto min-h-[200px]">
            {srvLoading && <div className="flex justify-center items-center py-10"><Loader2 className="w-5 h-5 animate-spin text-[#a78bfa]" /></div>}
            {!srvLoading && srvError && (
              <div className="m-4 flex items-center gap-2 px-4 py-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg text-sm text-[#ff3b3b]">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                M5 SIEM no disponible — no se pudo conectar a <code className="font-mono text-xs">localhost:8006/siem/auth-events</code>
              </div>
            )}
            {!srvLoading && !srvError && srvFiltered.length === 0 && (
              <p className="text-[#475569] text-sm text-center py-8">
                {srvEvents.length === 0 ? 'Sin eventos de autenticación en servidores.' : 'Sin resultados para los filtros aplicados.'}
              </p>
            )}
            {!srvLoading && !srvError && srvFiltered.length > 0 && (
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-[#111318] z-10">
                  <tr className="text-left text-[#475569] border-b border-[#1C2030]">
                    <th className="px-3 py-2 font-medium">Fecha / Hora</th>
                    <th className="px-3 py-2 font-medium">Servidor</th>
                    <th className="px-3 py-2 font-medium">Usuario</th>
                    <th className="px-3 py-2 font-medium">Tipo Acción</th>
                    <th className="px-3 py-2 font-medium">Severidad</th>
                    <th className="px-3 py-2 font-medium">IP Origen</th>
                    <th className="px-3 py-2 font-medium">Puerto</th>
                    <th className="px-3 py-2 font-medium"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1C2030]">
                  {srvPaged.map(ev => {
                    const sevColor: Record<string, string> = {
                      CRITICAL: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',
                      HIGH:     'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',
                      MEDIUM:   'bg-[#8B5CF6]/10 border-[#8B5CF6]/30 text-[#8B5CF6]',
                      LOW:      'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]',
                      INFO:     'bg-[#374151]/30 border-[#334155]/30 text-[#64748B]',
                    };
                    const isExpanded = srvExpanded === ev.alert_id;
                    const isBF = !!(ev.src_ip && srvBruteIPs.includes(ev.src_ip));
                    return (
                      <>
                        <tr
                          key={ev.alert_id}
                          onClick={() => setSrvExpanded(isExpanded ? null : ev.alert_id)}
                          className={`hover:bg-[#1C2030]/40 transition-colors cursor-pointer ${
                            ev.severity === 'CRITICAL' ? 'border-l-2 border-[#ff3b3b]' :
                            ev.severity === 'HIGH'     ? 'border-l-2 border-[#f59e0b]' : ''
                          }`}
                        >
                          <td className="px-3 py-2"><DateTimeCell ts={ev.timestamp} /></td>
                          <td className="px-3 py-2">
                            <div className="flex flex-col">
                              <span className="text-[#a78bfa] font-mono font-medium">{ev.agent_name}</span>
                              <span className="text-[#334155] font-mono text-[10px]">{ev.agent_ip}</span>
                            </div>
                          </td>
                          <td className="px-3 py-2 font-mono text-white">{ev.src_user ?? <span className="text-[#334155]">—</span>}</td>
                          <td className="px-3 py-2">
                            <div className="flex items-center gap-1">
                              <span className={`text-[10px] text-[#334155] transition-transform inline-block ${isExpanded ? 'rotate-90' : ''}`}>▶</span>
                              {actionBadgeSrv(ev.action_type)}
                            </div>
                          </td>
                          <td className="px-3 py-2">
                            <span className={`inline-flex px-2 py-0.5 rounded-full border text-[10px] font-semibold ${sevColor[ev.severity] ?? sevColor.INFO}`}>
                              {ev.severity}
                            </span>
                          </td>
                          <td className="px-3 py-2 font-mono text-xs">
                            {ev.src_ip ? (
                              <span className={isBF ? 'text-[#ff3b3b] font-semibold' : 'text-[#64748B]'}>
                                {ev.src_ip}{isBF && <span className="ml-1" title="IP en brute force activo">⚠</span>}
                              </span>
                            ) : <span className="text-[#334155]">—</span>}
                          </td>
                          <td className="px-3 py-2 font-mono text-[#475569]">{ev.port ?? '—'}</td>
                          <td className="px-3 py-2 w-4" />
                        </tr>
                        {isExpanded && (
                          <tr key={`${ev.alert_id}-detail`}>
                            <td colSpan={8} className="px-4 py-3 bg-[#0A0C10] border-l-2 border-[#a78bfa]">
                              <div className="space-y-3 text-xs">
                                <div>
                                  <span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-1">Raw Log</span>
                                  <code className="text-[#64748B] font-mono break-all leading-5">{ev.raw_log}</code>
                                </div>
                                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                                  <div>
                                    <span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-0.5">Resultado</span>
                                    <span className={ev.success ? 'text-[#22c55e] font-semibold' : 'text-[#ff3b3b] font-semibold'}>
                                      {ev.success ? '✓ EXITOSO' : '✗ FALLIDO'}
                                    </span>
                                  </div>
                                  <div>
                                    <span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-0.5">Timestamp UTC</span>
                                    <span className="text-white font-mono">{ev.timestamp}</span>
                                  </div>
                                  {ev.command && (
                                    <div className="col-span-2">
                                      <span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-0.5">Comando ejecutado</span>
                                      <code className="text-[#a78bfa] font-mono">{ev.command}</code>
                                    </div>
                                  )}
                                  {ev.mitre_tactic && (
                                    <div>
                                      <span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-0.5">MITRE Táctica</span>
                                      <span className="text-white">{ev.mitre_tactic}</span>
                                    </div>
                                  )}
                                  {ev.mitre_technique && (
                                    <div>
                                      <span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-0.5">MITRE Técnica</span>
                                      <span className="text-white font-mono">{ev.mitre_technique}</span>
                                    </div>
                                  )}
                                  <div>
                                    <span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-0.5">Agent ID (M1)</span>
                                    <span className="text-white font-mono">{ev.agent_id}</span>
                                  </div>
                                  <div>
                                    <span className="text-[10px] text-[#475569] uppercase tracking-wider block mb-0.5">Norma ENS</span>
                                    <span className="text-[#8B5CF6]">op.acc.1 · op.acc.6 · op.exp.5</span>
                                  </div>
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

          {/* Paginación */}
          {srvTotalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-2 border-t border-[#1C2030]">
              <button onClick={() => setSrvPage(p => Math.max(1, p - 1))} disabled={srvPage === 1}
                className="text-xs text-[#64748B] hover:text-white disabled:opacity-30 disabled:cursor-not-allowed px-3 py-1 rounded border border-[#1C2030] hover:border-[#a78bfa] transition-colors">
                ← Anterior
              </button>
              <span className="text-xs text-[#475569]">
                Página {srvPage} de {srvTotalPages} · {srvFiltered.length} de {srvEvents.length} eventos
              </span>
              <button onClick={() => setSrvPage(p => Math.min(srvTotalPages, p + 1))} disabled={srvPage === srvTotalPages}
                className="text-xs text-[#64748B] hover:text-white disabled:opacity-30 disabled:cursor-not-allowed px-3 py-1 rounded border border-[#1C2030] hover:border-[#a78bfa] transition-colors">
                Siguiente →
              </button>
            </div>
          )}

          {/* Footer ENS */}
          <div className="px-4 py-2 border-t border-[#1C2030] flex items-center justify-between text-[10px] text-[#334155] font-mono">
            <span>{srvFiltered.length} eventos filtrados · {srvEvents.length} total · pág {srvPage}/{srvTotalPages}</span>
            <span>ENS RD 311/2022 · op.acc.1 · op.acc.6 · op.exp.5 · Retención ≥2 años</span>
          </div>
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
      UPDATE: { cls: 'bg-[#8B5CF6]/10 border-[#8B5CF6]/30 text-[#8B5CF6]', icon: <Pencil className="w-3 h-3" />, label: 'UPDATE' },
      DELETE: { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]', icon: <Trash2 className="w-3 h-3" />, label: 'DELETE' },
    };
    const c = cfg[action] ?? { cls: 'bg-[#374151]/30 border-[#334155]/30 text-[#475569]', icon: null, label: action };
    return <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-xs font-semibold ${c.cls}`}>{c.icon}{c.label}</span>;
  };

  const Tab = ({ id, label, icon: Icon }: { id: typeof activeTab; label: string; icon: React.ElementType }) => (
    <button onClick={() => setActiveTab(id)}
      className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === id ? 'border-[#8B5CF6] text-[#8B5CF6]' : 'border-transparent text-[#64748B] hover:text-white hover:border-[#374151]'}`}>
      <Icon className="w-4 h-4" />{label}
    </button>
  );

  return (
    <div className="flex h-screen bg-[#0A0C10]">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="Auditor" />
        <main className="flex-1 overflow-auto p-6 space-y-6">

          <div>
            <h1 className="text-2xl font-semibold text-white mb-1">Logs de Auditoría</h1>
            <p className="text-[#64748B] text-sm">Trazabilidad completa del sistema · ENS op.exp.5 · RD 311/2022</p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4"><div className="text-2xl font-bold text-white">{totalEntries}</div><div className="text-xs text-[#64748B] mt-0.5">Total entradas sistema</div></div>
            <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4"><div className="text-2xl font-bold text-[#ff3b3b]">{errorCount}</div><div className="text-xs text-[#64748B] mt-0.5">Errores del sistema</div></div>
            <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4"><div className="text-2xl font-bold text-[#8B5CF6]">{assetOpsCount}</div><div className="text-xs text-[#64748B] mt-0.5">Operaciones sobre activos</div></div>
            <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4"><div className="text-2xl font-bold text-white font-mono">{lastActivity}</div><div className="text-xs text-[#64748B] mt-0.5">Última actividad</div></div>
          </div>

          <div className="border-b border-[#1C2030] flex gap-0 -mb-2">
            <Tab id="system"   label="Sistema — Live"     icon={Activity} />
            <Tab id="assets"   label="Auditoría Activos"  icon={Search} />
            <Tab id="sessions" label="Sesiones de Acceso" icon={LogIn} />
          </div>

          {activeTab === 'system' && (
            <div className="bg-[#111318] border border-[#1C2030] rounded-xl overflow-hidden flex flex-col">
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#1C2030]">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#8B5CF6]" />
                  <span className="text-sm font-semibold text-white">Orchestrator — Live</span>
                  <span className={`flex items-center gap-1 text-xs ${sseConnected ? 'text-[#22c55e]' : 'text-[#ff3b3b]'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${sseConnected ? 'bg-[#22c55e] animate-pulse' : 'bg-[#ff3b3b]'}`} />
                    {sseConnected ? 'Conectado' : 'Desconectado'}
                  </span>
                </div>
                <button onClick={() => setOrchestratorLogs([])} className="text-[#475569] hover:text-[#ff3b3b] transition-colors p-1 rounded">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
              <div ref={logEndRef} className="flex-1 bg-[#0A0C10] p-3 font-mono text-xs overflow-y-auto h-80 space-y-0.5">
                {orchestratorLogs.length === 0 && <div className="text-[#334155] italic">Esperando logs del orchestrator...</div>}
                {[...orchestratorLogs].reverse().map((log, i) => (
                  <div key={i} className={`leading-5 ${levelColor(log.level)}`}>
                    <span className="text-[#334155]">[{fmtTime(log.timestamp)}]</span>{' '}
                    <span className="text-[#475569]">[{log.module}]</span>{' '}{log.message}
                  </div>
                ))}
              </div>
              <div className="px-4 py-2 border-t border-[#1C2030] text-[10px] text-[#334155] font-mono">{orchestratorLogs.length} entradas · máx 200</div>
            </div>
          )}

          {activeTab === 'assets' && (
            <div className="bg-[#111318] border border-[#1C2030] rounded-xl overflow-hidden flex flex-col">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1C2030]">
                <Search className="w-4 h-4 text-[#8B5CF6]" />
                <span className="text-sm font-semibold text-white">Auditoría de Activos (M1)</span>
              </div>
              <div className="px-4 py-3 border-b border-[#1C2030] flex flex-wrap gap-2">
                <div className="relative flex-1 min-w-32">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#334155]" />
                  <input value={searchTerm} onChange={e => setSearchTerm(e.target.value)} placeholder="Buscar..."
                    className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-[#374151] focus:outline-none focus:border-[#8B5CF6]" />
                </div>
                <select value={filterAction} onChange={e => setFilterAction(e.target.value)}
                  className="bg-[#0A0C10] border border-[#1C2030] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#8B5CF6]">
                  <option value="ALL">Todas las acciones</option>
                  <option value="CREATE">CREATE</option>
                  <option value="UPDATE">UPDATE</option>
                  <option value="DELETE">DELETE</option>
                </select>
                <select value={filterAsset} onChange={e => setFilterAsset(e.target.value)}
                  className="bg-[#0A0C10] border border-[#1C2030] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#8B5CF6]">
                  <option value="ALL">Todos los activos</option>
                  {assetIPs.map(ip => <option key={ip} value={ip}>{ip}</option>)}
                </select>
              </div>
              <div className="flex-1 overflow-auto">
                {assetLoading && <div className="flex justify-center items-center py-12"><Loader2 className="w-6 h-6 animate-spin text-[#8B5CF6]" /></div>}
                {!assetLoading && assetError && (
                  <div className="m-4 flex items-center gap-2 px-4 py-3 bg-[#f59e0b]/10 border border-[#f59e0b]/20 rounded-lg text-sm text-[#f59e0b]">
                    <AlertTriangle className="w-4 h-4 shrink-0" /> M1 no disponible — no se pudo cargar el historial de auditoría.
                  </div>
                )}
                {!assetLoading && !assetError && filteredAsset.length === 0 && <p className="text-[#475569] text-sm text-center py-8">Sin registros de auditoría disponibles.</p>}
                {!assetLoading && !assetError && filteredAsset.length > 0 && (
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-[#111318]">
                      <tr className="text-left text-[#475569] border-b border-[#1C2030]">
                        <th className="px-3 py-2 font-medium">Timestamp</th><th className="px-3 py-2 font-medium">Activo</th>
                        <th className="px-3 py-2 font-medium">Acción</th><th className="px-3 py-2 font-medium">Usuario</th>
                        <th className="px-3 py-2 font-medium">Rol</th><th className="px-3 py-2 font-medium">IP Origen</th>
                        <th className="px-3 py-2 font-medium">Det.</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1C2030]">
                      {filteredAsset.map(log => (
                        <>
                          <tr key={log.id} className="hover:bg-[#1C2030]/40 transition-colors">
                            <td className="px-3 py-2"><DateTimeCell ts={log.timestamp} /></td>
                            <td className="px-3 py-2 font-mono text-[#8B5CF6]">{log._asset_ip ?? String(log.asset_id)}</td>
                            <td className="px-3 py-2">{actionBadge(log.action)}</td>
                            <td className="px-3 py-2 text-white">{log.user_id}</td>
                            <td className="px-3 py-2">
                              {log.user_role
                                ? <span className="px-1.5 py-0.5 bg-[#374151]/40 text-[#64748B] border border-[#334155]/30 rounded text-[10px]">{log.user_role}</span>
                                : <span className="text-[#334155]">—</span>}
                            </td>
                            <td className="px-3 py-2 font-mono text-[#64748B]">{log.ip_origin ?? '—'}</td>
                            <td className="px-3 py-2">
                              <button onClick={() => setExpandedRow(expandedRow === log.id ? null : log.id)} className="text-[#475569] hover:text-[#8B5CF6] transition-colors">
                                <Eye className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>
                          {expandedRow === log.id && (
                            <tr key={`${log.id}-detail`}>
                              <td colSpan={7} className="px-4 py-3 bg-[#0A0C10] border-l-2 border-[#8B5CF6]">
                                {log.reason && <div className="mb-2"><span className="text-[10px] text-[#475569] uppercase tracking-wider">Motivo: </span><span className="text-xs text-white">{log.reason}</span></div>}
                                {log.changes && Object.keys(log.changes).length > 0
                                  ? <div><div className="text-[10px] text-[#475569] uppercase tracking-wider mb-1">Cambios</div><pre className="bg-[#080a10] rounded p-3 font-mono text-xs text-[#64748B] max-h-40 overflow-y-auto">{JSON.stringify(log.changes, null, 2)}</pre></div>
                                  : !log.reason ? <span className="text-xs text-[#334155]">Sin detalles adicionales.</span> : null}
                              </td>
                            </tr>
                          )}
                        </>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
              <div className="px-4 py-2 border-t border-[#1C2030] text-[10px] text-[#334155] font-mono">{filteredAsset.length} entradas · máx 500 por carga</div>
            </div>
          )}

          {activeTab === 'sessions' && <LoginSessionsTab />}

          <div className="text-center text-xs text-[#334155]">Logs inmutables · ENS op.exp.5 · RD 311/2022 · Retención mínima 2 años</div>

        </main>
      </div>
    </div>
  );
}
