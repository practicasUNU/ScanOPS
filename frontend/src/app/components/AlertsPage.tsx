import { useState, useEffect } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  ShieldAlert,
  Activity,
  Lock,
  Server,
  Flame,
  Search,
  Filter,
  Wifi,
  AlertTriangle,
  Bug,
  ChevronDown,
  ChevronRight,
  Globe,
  Clock,
  Layers,
  Database
} from 'lucide-react';

const ORCHESTRATOR_BASE = '/api/orchestrator';
const M5_BASE = '/api/m5';

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

// Normaliza cualquier valor a texto seguro para render/.split().
// Cowrie puede devolver `detail` como string, array (p.ej. cowrie.session.params: [])
// u objeto; sin esto, llamar .split() sobre un array rompe el render (pantalla negra).
function asText(v: unknown): string {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v.map(asText).filter(Boolean).join('\n');
  if (typeof v === 'object') {
    try { return JSON.stringify(v); } catch { return String(v); }
  }
  return String(v);
}

// ─── TIPOS DE DATOS ───
type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
type AlertSource = 'Suricata (NIDS)' | 'Wazuh (HIDS)' | 'Cowrie (Honeypot)' | 'Orchestrator';

interface SiemAlert {
  id: string;
  timestamp: string;
  source: AlertSource;
  severity: AlertSeverity;
  message: string;
  target_ip: string;
  attacker_ip?: string;
  mitigated: boolean;
}

interface SiemKpis {
  suricata_blocked: number;
  wazuh_auth_failures: number;
  cowrie_interactions: number;
  sensor_health: 'ok' | 'degraded' | 'offline' | 'unknown';
  sensors_online: number;
  sensors_total: number;
}

interface HoneypotStatus {
  cowrie: { status: string; ports: number[]; type: string };
  beelzebub: { status: string; ports: number[]; type: string };
  isolation_network: string;
  ens_compliance: { op_exp_4: boolean; description: string };
  timestamp: string;
}

interface HoneypotEvent {
  source: 'cowrie' | 'beelzebub';
  timestamp: string;
  src_ip: string;
  event_type: string;
  detail: string;
}

interface HoneypotAttacker {
  ip: string;
  attempts: number;
  first_seen: string;
  last_seen: string;
}

interface M5Alert {
  id?: string;
  timestamp: string;
  source: string;
  severity?: string;
  message?: string;
  description?: string;
  src_ip?: string;
  target_ip?: string;
  attacker_ip?: string;
  mitigated?: boolean;
  event_type?: string;
}

// ─── DATOS MOCK: TELEMETRÍA EN VIVO ───
const MOCK_ALERTS: SiemAlert[] = [
  { id: 'AL-901', timestamp: '10:45:02', source: 'Suricata (NIDS)', severity: 'CRITICAL', message: '[DEMO] ET EXPLOIT Possible CVE-2021-44228 Apache Log4j RCE', target_ip: '10.202.15.15', attacker_ip: '185.15.56.22', mitigated: true },
  { id: 'AL-902', timestamp: '10:42:15', source: 'Wazuh (HIDS)', severity: 'HIGH', message: '[DEMO] Multiple authentication failures (SSH Brute Force)', target_ip: '10.202.15.10', attacker_ip: '112.54.22.1', mitigated: true },
  { id: 'AL-903', timestamp: '10:39:50', source: 'Cowrie (Honeypot)', severity: 'MEDIUM', message: '[DEMO] Unauthorized login success in Honeypot container', target_ip: '10.202.99.99', attacker_ip: '45.33.22.12', mitigated: false },
  { id: 'AL-904', timestamp: '10:35:12', source: 'Wazuh (HIDS)', severity: 'LOW', message: '[DEMO] System package updated globally', target_ip: '10.202.15.15', mitigated: false },
  { id: 'AL-905', timestamp: '10:30:05', source: 'Suricata (NIDS)', severity: 'HIGH', message: '[DEMO] ET SCAN Nmap OS Detection Probe', target_ip: '10.202.15.20', attacker_ip: '192.168.1.100', mitigated: false },
  { id: 'AL-906', timestamp: '10:25:33', source: 'Cowrie (Honeypot)', severity: 'CRITICAL', message: '[DEMO] Malware sample dropped via wget (Mirai variant)', target_ip: '10.202.99.99', attacker_ip: '89.22.33.1', mitigated: true },
];

// ─── COMPONENTES AUXILIARES ───
const getSeverityBadge = (severity: unknown) => {
  switch (String(severity ?? '').toUpperCase()) {
    case 'CRITICAL': return 'bg-[#ff3b3b]/10 text-[#ff3b3b] border-[#ff3b3b]/30';
    case 'HIGH':     return 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30';
    case 'MEDIUM':   return 'bg-[#8B5CF6]/10 text-[#8B5CF6] border-[#8B5CF6]/30';
    case 'LOW':      return 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30';
    default:         return 'bg-[#475569]/10 text-[#475569] border-[#475569]/30';
  }
};

const getSourceIcon = (source: string | undefined) => {
  switch (source) {
    case 'Suricata (NIDS)':   return <Activity className="w-4 h-4 text-[#8B5CF6]" />;
    case 'Wazuh (HIDS)':      return <Lock className="w-4 h-4 text-[#22c55e]" />;
    case 'Cowrie (Honeypot)': return <Flame className="w-4 h-4 text-[#ff3b3b]" />;
    case 'M4-Pipeline':       return <ShieldAlert className="w-4 h-4 text-[#a78bfa]" />;
    default:                  return <Server className="w-4 h-4 text-[#64748B]" />;
  }
};

function AlertDateTime({ ts }: { ts: string }) {
  try {
    const d = new Date(ts);
    const date = d.toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit', year: '2-digit' });
    const time = d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    return (
      <div className="whitespace-nowrap">
        <div className="font-mono text-xs text-white font-semibold">{time}</div>
        <div className="font-mono text-[10px] text-[#475569]">{date}</div>
      </div>
    );
  } catch {
    return <span className="font-mono text-[10px] text-[#64748B]">{ts}</span>;
  }
}

export function AlertsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [isLive, setIsLive] = useState(true);
  const [filterSource, setFilterSource] = useState<string>('ALL');
  const [kpis, setKpis] = useState<SiemKpis | null>(null);
  const [kpisLoading, setKpisLoading] = useState(true);
  const [liveAlerts, setLiveAlerts] = useState<M5Alert[]>([]);
  const [alertsLoading, setAlertsLoading] = useState(true);
  // m5Reachable: null=loading, true=up, false=down
  // Controlled ONLY by pipeline-events (authoritative M5 health check)
  const [m5Reachable, setM5Reachable] = useState<boolean | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [pipelineEvents, setPipelineEvents] = useState<any[]>([]);
  const [wazuhAlerts, setWazuhAlerts] = useState<M5Alert[]>([]);
  const [wazuhCount, setWazuhCount] = useState(0);
  const [refetchTick, setRefetchTick] = useState(0);
  const refetch = () => setRefetchTick(t => t + 1);
  const [honeypotStatus, setHoneypotStatus] = useState<HoneypotStatus | null>(null);
  const [honeypotEvents, setHoneypotEvents] = useState<HoneypotEvent[]>([]);
  const [honeypotAttackers, setHoneypotAttackers] = useState<HoneypotAttacker[]>([]);
  const [honeypotLoading, setHoneypotLoading] = useState(true);
  const [expandedSession, setExpandedSession] = useState<number | null>(null);
  const [honeypotTab, setHoneypotTab] = useState<'cowrie' | 'beelzebub'>('cowrie');

  // Host telemetry agentless
  interface HostTelemetryEvent {
    timestamp: string; source: string; log_source: string;
    action_type: string; severity: string; message: string;
    raw_log: string; src_ip?: string; src_user?: string;
    agent_name: string; agent_ip: string; agent_id: string;
    alert_id: string; rule_id: string; mitre_tactic: string; mitre_technique: string;
    http_status?: string; user_agent?: string;
  }
  interface HostSummary {
    asset_ip: string; asset_id: string; asset_name: string;
    reachable: boolean; collected_at: string; total_events: number;
    severity_counts: Record<string, number>;
    log_sources: string[]; processes: any[]; connections: any[];
    last_logins: string[]; disk_usage: any[]; errors: string[];
  }
  const [telemetryEvents, setTelemetryEvents] = useState<HostTelemetryEvent[]>([]);
  const [hostSummaries, setHostSummaries] = useState<HostSummary[]>([]);
  const [telemetryLoading, setTelemetryLoading] = useState(false);
  const [telemetryLoaded, setTelemetryLoaded] = useState(false);
  const [telemetryFilter, setTelemetryFilter] = useState<'ALL'|'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'>('ALL');
  const [telemetrySearch, setTelemetrySearch] = useState('');
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'alertas' | 'telemetria'>('alertas');

  // KPIs + top attackers polling (30s)
  useEffect(() => {
    const fetchKpis = async () => {
      try {
        const res = await fetch(`${ORCHESTRATOR_BASE}/orchestrator/siem/kpis`, {
          headers: authH(),
          signal: AbortSignal.timeout(8000),
        });
        if (res.ok) {
          setKpis(await res.json() as SiemKpis);
          setLastUpdated(new Date().toLocaleTimeString('es-ES'));
        }
      } catch { /* silencioso */ }
      finally { setKpisLoading(false); }
    };

    fetchKpis();
    const id = setInterval(fetchKpis, 30000);
    return () => clearInterval(id);
  }, []);

  // Honeypot polling (30s)
  useEffect(() => {
    const fetchHoneypot = async () => {
      try {
        const [statusRes, eventsRes, attackersRes] = await Promise.allSettled([
          fetch(`${M5_BASE}/siem/honeypots/status`, { headers: authH(), signal: AbortSignal.timeout(5000) }),
          fetch(`${M5_BASE}/siem/honeypots/events`, { headers: authH(), signal: AbortSignal.timeout(5000) }),
          fetch(`${M5_BASE}/siem/honeypots/attackers`, { headers: authH(), signal: AbortSignal.timeout(5000) }),
        ]);

        if (statusRes.status === 'fulfilled' && statusRes.value.ok) {
          setHoneypotStatus(await statusRes.value.json() as HoneypotStatus);
        }
        if (eventsRes.status === 'fulfilled' && eventsRes.value.ok) {
          const d = await eventsRes.value.json() as { events: HoneypotEvent[] };
          // Normaliza `detail` (Cowrie a veces lo manda como array/objeto) para que
          // .split() y el render nunca reciban un tipo inesperado.
          const safe = (d.events ?? []).map(e => ({
            ...e,
            detail: asText((e as { detail?: unknown }).detail),
            event_type: asText((e as { event_type?: unknown }).event_type),
          }));
          setHoneypotEvents(safe);
        }
        if (attackersRes.status === 'fulfilled' && attackersRes.value.ok) {
          const d = await attackersRes.value.json() as { attackers: HoneypotAttacker[] };
          setHoneypotAttackers(d.attackers ?? []);
        }
      } catch { /* silencioso */ }
      finally { setHoneypotLoading(false); }
    };

    fetchHoneypot();
    const id = setInterval(fetchHoneypot, 30000);
    return () => clearInterval(id);
  }, []);

  // Pipeline events polling (5s) — authoritative M5 health check
  useEffect(() => {
    const fetchPipelineEvents = async () => {
      try {
        const res = await fetch(`${M5_BASE}/siem/pipeline-events?limit=50`,
          { headers: authH(), signal: AbortSignal.timeout(6000) });
        if (res.ok) {
          const data = await res.json();
          setPipelineEvents(data.events ?? []);
          setM5Reachable(true);
          setLastUpdated(new Date().toLocaleTimeString('es-ES'));
        } else {
          setM5Reachable(false);
        }
      } catch {
        setM5Reachable(false);
      }
    };
    fetchPipelineEvents();
    const id = setInterval(fetchPipelineEvents, 5000);
    return () => clearInterval(id);
  }, []);

  // Live sensor alerts polling (15s) — Suricata + Cowrie
  // Does NOT touch m5Reachable (controlled by pipeline-events)
  useEffect(() => {
    if (!isLive) return;

    const fetchAlerts = async () => {
      try {
        const [suricataRes, cowrieRes] = await Promise.allSettled([
          fetch(`${M5_BASE}/siem/suricata/alerts`, {
            headers: authH(), signal: AbortSignal.timeout(5000),
          }),
          fetch(`${M5_BASE}/siem/honeypots/events`, {
            headers: authH(), signal: AbortSignal.timeout(5000),
          }),
        ]);

        const sensorAlerts: M5Alert[] = [];

        if (suricataRes.status === 'fulfilled' && suricataRes.value.ok) {
          const data = await suricataRes.value.json() as Record<string, unknown>;
          const rawAlerts = ((data.alerts as unknown[]) ?? []).slice(0, 30);
          const mapped = rawAlerts.map((a: unknown, i: number) => {
            const al = a as Record<string, unknown>;
            const nested = al.alert as Record<string, unknown> | undefined;
            const contentId = `suricata-${al.timestamp ?? i}-${al.src_ip ?? ''}-${(nested?.signature as string | undefined)?.slice(0, 30) ?? i}`;
            return {
              id: (al.id as string | undefined) ?? contentId,
              timestamp: (al.timestamp as string | undefined) ?? '',
              source: 'Suricata (NIDS)',
              severity: ((nested?.severity as number | undefined) === 1 ? 'CRITICAL'
                : (nested?.severity as number | undefined) === 2 ? 'HIGH'
                : 'MEDIUM'),
              message: (nested?.signature as string | undefined)
                ?? (al.message as string | undefined)
                ?? 'Suricata alert',
              src_ip: al.src_ip as string | undefined,
              target_ip: (al.dest_ip as string | undefined) ?? (al.target_ip as string | undefined),
              attacker_ip: al.src_ip as string | undefined,
              mitigated: al.action === 'blocked',
            } satisfies M5Alert;
          });
          sensorAlerts.push(...mapped);
        }

        if (cowrieRes.status === 'fulfilled' && cowrieRes.value.ok) {
          const data = await cowrieRes.value.json() as Record<string, unknown>;
          const rawEvents = ((data.events as unknown[]) ?? []).slice(0, 15);
          const mapped = rawEvents.map((e: unknown, i: number) => {
            const ev = e as Record<string, unknown>;
            const contentId = `cowrie-${ev.timestamp ?? i}-${ev.src_ip ?? ''}-${asText(ev.event_type).slice(0, 20)}`;
            return {
              id: contentId,
              timestamp: (ev.timestamp as string | undefined) ?? '',
              source: 'Cowrie (Honeypot)',
              severity: 'HIGH',
              message: asText(ev.detail) || asText(ev.event_type) || 'Honeypot interaction',
              src_ip: ev.src_ip as string | undefined,
              attacker_ip: ev.src_ip as string | undefined,
              mitigated: false,
            } satisfies M5Alert;
          });
          sensorAlerts.push(...mapped);
        }

        if (sensorAlerts.length > 0) {
          sensorAlerts.sort((a, b) =>
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
          );
          setLiveAlerts(sensorAlerts.slice(0, 50));
        }
      } catch { /* silent — m5Reachable controlled by pipeline-events */ }
      finally { setAlertsLoading(false); }
    };

    fetchAlerts();
    const id = setInterval(fetchAlerts, 15000);
    return () => clearInterval(id);
  }, [isLive, refetchTick]);

  // Wazuh HIDS alerts polling (60s)
  useEffect(() => {
    const fetchWazuh = async () => {
      try {
        const res = await fetch(`${M5_BASE}/siem/wazuh/alerts?limit=80&min_level=3`,
          { headers: authH(), signal: AbortSignal.timeout(15000) });
        if (!res.ok) return;
        const data = await res.json() as { alerts: Record<string, unknown>[]; count: number };
        setWazuhCount(data.count);
        const mapped: M5Alert[] = (data.alerts ?? []).map((a, i) => ({
          id: `wazuh-${i}`,
          timestamp: (a.timestamp as string | undefined) ?? '',
          source: 'Wazuh (HIDS)',
          severity: (a.severity as string | undefined) ?? 'LOW',
          message: (a.description as string | undefined) ?? 'Wazuh alert',
          src_ip: a.src_ip as string | undefined,
          attacker_ip: a.src_ip as string | undefined,
          target_ip: (a.agent as string | undefined),
          mitigated: false,
        }));
        setWazuhAlerts(mapped);
      } catch { /* silent */ }
    };
    fetchWazuh();
    const id = setInterval(fetchWazuh, 60000);
    return () => clearInterval(id);
  }, []);

  const fetchTelemetry = async () => {
    setTelemetryLoading(true);
    try {
      const res = await fetch(`${M5_BASE}/siem/host-telemetry?limit=300`, {
        headers: authH(), signal: AbortSignal.timeout(60000),
      });
      if (res.ok) {
        const data = await res.json();
        setTelemetryEvents(data.events ?? []);
        setHostSummaries(data.host_summaries ?? []);
        setTelemetryLoaded(true);
      }
    } catch { /* silent */ }
    finally { setTelemetryLoading(false); }
  };

  const pipelineAsAlerts: M5Alert[] = pipelineEvents.map((e: any) => ({
    id: `pipeline-${e.id}`,
    timestamp: e.timestamp,
    source: 'M4-Pipeline',
    severity: e.severity,
    message: e.description,
    src_ip: e.attacker_ip,
    target_ip: e.target_ip,
    attacker_ip: e.attacker_ip,
    mitigated: e.mitigated,
  }));

  // Merge all sources, deduplicate by id, sort by timestamp
  const allReal: M5Alert[] = [...pipelineAsAlerts, ...wazuhAlerts, ...liveAlerts];
  const seen = new Set<string>();
  const combined: M5Alert[] = allReal.filter(a => {
    const key = a.id ?? '';
    if (key && seen.has(key)) return false;
    if (key) seen.add(key);
    return true;
  });
  combined.sort((a, b) =>
    new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime()
  );

  // Only show mock when M5 is truly unreachable (pipeline failed) AND absolutely no data
  const isMock = m5Reachable === false && combined.length === 0;
  // Show "no sensor data" notice when M5 is up but sensors have no activity
  const sensorsEmpty = m5Reachable === true && liveAlerts.length === 0 && wazuhAlerts.length === 0;
  const alerts: M5Alert[] = isMock ? (MOCK_ALERTS as unknown as M5Alert[]) : combined;
  const filteredAlerts = alerts.filter(alert => {
    const a = alert as M5Alert;
    const msg = asText(a.message).toLowerCase();
    const desc = asText(a.description).toLowerCase();
    const matchesSearch =
      msg.includes(searchTerm.toLowerCase()) ||
      desc.includes(searchTerm.toLowerCase()) ||
      (a.attacker_ip ?? '').includes(searchTerm) ||
      (a.src_ip ?? '').includes(searchTerm);
    const matchesSource = filterSource === 'ALL' || alert.source === filterSource;
    return matchesSearch && matchesSource;
  });

  const cowrieEvents = honeypotEvents.filter(e => e.source === 'cowrie');
  const beelzebubEvents = honeypotEvents.filter(e => e.source === 'beelzebub');
  const maxAttacks = honeypotAttackers.length > 0 ? honeypotAttackers[0].attempts : 1;

  const telemetryFiltered = telemetryEvents.filter(ev => {
    if (telemetryFilter !== 'ALL' && ev.severity !== telemetryFilter) return false;
    if (telemetrySearch) {
      const q = telemetrySearch.toLowerCase();
      return asText(ev.message).toLowerCase().includes(q)
        || asText(ev.src_ip).includes(q)
        || asText(ev.agent_name).toLowerCase().includes(q)
        || asText(ev.action_type).toLowerCase().includes(q);
    }
    return true;
  });

  const SEVERITY_COLOR: Record<string, string> = {
    CRITICAL: '#ff3b3b', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#3b82f6', INFO: '#475569',
  };
  const SOURCE_COLOR: Record<string, string> = {
    'web_log': '#a855f7', 'syslog': '#06b6d4', 'auth_log': '#22c55e',
    'audit_log': '#f97316', 'process_list': '#ff3b3b', 'system': '#f59e0b',
  };
  const SOURCE_LABEL: Record<string, string> = {
    'web_log': 'WEB', 'syslog': 'SYSLOG', 'auth_log': 'AUTH',
    'audit_log': 'AUDIT', 'process_list': 'PROC', 'system': 'SYS',
  };

  const fmtDate = (iso: string) => {
    try { return new Date(iso).toLocaleString('es-ES', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
    catch { return iso; }
  };

  const containerStatusColor = (s: string) =>
    s === 'running' ? '#22c55e' : s === 'stopped' ? '#ff3b3b' : '#f59e0b';

  const containerStatusLabel = (s: string) =>
    s === 'running' ? 'ACTIVO' : s === 'stopped' ? 'DETENIDO' : 'DESCONOCIDO';

  return (
    <div className="flex h-screen bg-[#0A0C10]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />

        <main className="flex-1 overflow-hidden flex flex-col p-6 space-y-6">
          {/* ─── CABECERA ─── */}
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-xl flex items-center justify-center shrink-0">
                <ShieldAlert className="w-6 h-6 text-[#ff3b3b]" />
              </div>
              <div>
                <h1 className="text-2xl font-semibold text-white mb-1 flex items-center gap-3">
                  Centro de Monitoreo SIEM (M5)
                  {isLive && (
                    <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#22c55e]/10 border border-[#22c55e]/20 text-[#22c55e] text-xs font-mono uppercase tracking-wider">
                      <span className="w-2 h-2 bg-[#22c55e] rounded-full animate-pulse"></span>
                      Live Stream Activo
                    </span>
                  )}
                </h1>
                <div className="flex items-center gap-3">
                  <p className="text-[#64748B] text-sm">Correlación de eventos Wazuh, Suricata y Honeypots (ENS op.mon.1)</p>
                  {lastUpdated && (
                    <span className="text-xs text-[#475569] font-mono">Actualizado: {lastUpdated}</span>
                  )}
                </div>
              </div>
            </div>

            <button
              onClick={() => setIsLive(!isLive)}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex items-center gap-2 border cursor-pointer ${
                isLive
                  ? 'bg-[#111318] border-[#1C2030] text-[#475569] hover:text-white'
                  : 'bg-[#8B5CF6]/10 border-[#8B5CF6]/30 text-[#8B5CF6] hover:bg-[#8B5CF6]/20'
              }`}
            >
              <Wifi className="w-4 h-4" />
              {isLive ? 'Pausar Telemetría' : 'Reanudar Stream'}
            </button>
          </div>

          {/* ─── KPIS TOP ─── */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 shrink-0">
            {/* Card 1 — Ataques Perimetrales */}
            <div className="relative bg-[#111318] border border-[#1C2030] rounded-xl p-4 flex items-center justify-between overflow-hidden">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#8B5CF6] to-transparent" />
              <div>
                <p className="text-[11px] text-[#475569] uppercase tracking-wider font-semibold mb-1.5">Ataques Perimetrales Bloqueados</p>
                <h3 className="text-3xl font-bold text-white tabular-nums leading-none">
                  {kpisLoading ? '—' : ((kpis?.suricata_blocked ?? 0) + pipelineEvents.length).toLocaleString()}
                </h3>
                <p className="text-[11px] text-[#22c55e] mt-2 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] shrink-0" />
                  {kpis ? `Suricata IPS · ${lastUpdated}` : '+12% vs ayer (Suricata IPS)'}
                </p>
              </div>
              <div className="p-3.5 bg-[#8B5CF6]/10 rounded-xl border border-[#8B5CF6]/10 shrink-0">
                <Activity className="w-5 h-5 text-[#8B5CF6]" />
              </div>
            </div>

            {/* Card 2 — Alertas Wazuh HIDS */}
            <div className="relative bg-[#111318] border border-[#1C2030] rounded-xl p-4 flex items-center justify-between overflow-hidden">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#f59e0b] to-transparent" />
              <div>
                <p className="text-[11px] text-[#475569] uppercase tracking-wider font-semibold mb-1.5">Alertas Wazuh HIDS (hoy)</p>
                <h3 className="text-3xl font-bold text-white tabular-nums leading-none">
                  {wazuhCount > 0 ? wazuhCount : (kpisLoading ? '—' : (kpis?.wazuh_auth_failures ?? 0))}
                </h3>
                <p className="text-[11px] text-[#f59e0b] mt-2 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#f59e0b] shrink-0" />
                  {wazuhCount > 0 ? `${wazuhCount} eventos CIS/SCA` : 'Sin alertas activas'}
                </p>
              </div>
              <div className="p-3.5 bg-[#f59e0b]/10 rounded-xl border border-[#f59e0b]/10 shrink-0">
                <Lock className="w-5 h-5 text-[#f59e0b]" />
              </div>
            </div>

            {/* Card 3 — Honeypot */}
            <div className="relative bg-[#111318] border border-[#1C2030] rounded-xl p-4 flex items-center justify-between overflow-hidden">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#ff3b3b] to-transparent" />
              <div>
                <p className="text-[11px] text-[#475569] uppercase tracking-wider font-semibold mb-1.5">Interacciones en Honeypot</p>
                <h3
                  className="text-3xl font-bold tabular-nums leading-none"
                  style={{ color: kpis && kpis.cowrie_interactions > 0 ? '#ff3b3b' : 'white' }}
                >
                  {kpisLoading ? '—' : (kpis?.cowrie_interactions ?? 7)}
                </h3>
                <p className="text-[11px] text-[#ff3b3b] mt-2 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#ff3b3b] shrink-0" />
                  {kpis ? `${kpis.cowrie_interactions} capturados · Cowrie` : '2 payloads capturados'}
                </p>
              </div>
              <div className="p-3.5 bg-[#ff3b3b]/10 rounded-xl border border-[#ff3b3b]/10 shrink-0">
                <Flame className="w-5 h-5 text-[#ff3b3b]" />
              </div>
            </div>

            {/* Card 4 — Estado SIEM */}
            <div className="relative bg-[#111318] border border-[#1C2030] rounded-xl p-4 flex items-center justify-between overflow-hidden">
              <div
                className="absolute top-0 left-0 right-0 h-[2px]"
                style={{
                  background: kpis?.sensor_health === 'degraded'
                    ? 'linear-gradient(to right, #f59e0b, transparent)'
                    : kpis?.sensor_health === 'offline'
                    ? 'linear-gradient(to right, #ff3b3b, transparent)'
                    : 'linear-gradient(to right, #22c55e, transparent)',
                }}
              />
              <div>
                <p className="text-[11px] text-[#475569] uppercase tracking-wider font-semibold mb-1.5">Estado del Nodo SIEM</p>
                <h3
                  className="text-3xl font-bold tabular-nums leading-none"
                  style={{
                    color: kpis?.sensor_health === 'ok' ? '#22c55e'
                      : kpis?.sensor_health === 'degraded' ? '#f59e0b'
                      : kpis?.sensor_health === 'offline' ? '#ff3b3b'
                      : 'white',
                  }}
                >
                  {kpisLoading ? '—' : kpis ? `${kpis.sensors_online}/${kpis.sensors_total}` : '100%'}
                </h3>
                <p className="text-[11px] text-[#22c55e] mt-2 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] shrink-0 animate-pulse" />
                  {kpis?.sensor_health === 'ok'
                    ? 'Todos los sensores online'
                    : kpis?.sensor_health === 'degraded'
                    ? 'Sensores degradados'
                    : kpis?.sensor_health === 'offline'
                    ? 'Sensores offline'
                    : 'Agentes respondiendo'}
                </p>
              </div>
              <div className="p-3.5 bg-[#22c55e]/10 rounded-xl border border-[#22c55e]/10 shrink-0">
                <Server className="w-5 h-5 text-[#22c55e]" />
              </div>
            </div>
          </div>

          {/* Banner M5 offline — datos ficticios */}
          {isMock && !alertsLoading && (
            <div className="flex items-center gap-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg px-4 py-3">
              <AlertTriangle className="w-4 h-4 text-[#ff3b3b] shrink-0" />
              <div className="flex-1">
                <span className="text-sm font-bold text-[#ff3b3b]">M5 no disponible — mostrando datos de demostración</span>
                <p className="text-xs text-[#ff3b3b]/70 mt-0.5">
                  No se pudo conectar con el motor SIEM. Comprueba que el contenedor scanops-m5 está en ejecución.
                </p>
              </div>
              <button onClick={refetch} className="text-xs text-[#ff3b3b] underline hover:no-underline shrink-0 cursor-pointer">
                Reintentar
              </button>
            </div>
          )}

          {/* Banner sensores activos pero sin eventos de Suricata/Cowrie */}
          {sensorsEmpty && !alertsLoading && !isMock && (
            <div className="flex items-center gap-3 bg-[#f59e0b]/10 border border-[#f59e0b]/20 rounded-lg px-4 py-3">
              <AlertTriangle className="w-4 h-4 text-[#f59e0b] shrink-0" />
              <div className="flex-1">
                <span className="text-sm font-semibold text-[#f59e0b]">Suricata · Cowrie sin actividad</span>
                <p className="text-xs text-[#f59e0b]/70 mt-0.5">
                  M5 activo — Wazuh HIDS: {wazuhCount} alertas · Pipeline M4: {pipelineEvents.length} eventos · Suricata/Honeypot: sin eventos recientes (sensores o logs ausentes)
                </p>
              </div>
            </div>
          )}

          {/* ─── TABS ─── */}
          <div className="flex items-center gap-1 bg-[#111318] border border-[#1C2030] rounded-xl p-1 shrink-0 w-fit">
            <button
              onClick={() => setActiveTab('alertas')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${activeTab === 'alertas' ? 'bg-[#0A0C10] text-white shadow-sm' : 'text-[#475569] hover:text-white'}`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              Alertas &amp; Honeypots
              <span className="px-1.5 py-0.5 rounded-full text-[9px] bg-[#1C2030] text-[#475569] font-mono tabular-nums">{filteredAlerts.length}</span>
            </button>
            <button
              onClick={() => { setActiveTab('telemetria'); if (!telemetryLoaded && !telemetryLoading) fetchTelemetry(); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${activeTab === 'telemetria' ? 'bg-[#0A0C10] text-white shadow-sm' : 'text-[#475569] hover:text-white'}`}
            >
              <Server className="w-3.5 h-3.5" />
              Telemetría Agentless
              {telemetryLoaded && (
                <span className="px-1.5 py-0.5 rounded-full text-[9px] bg-[#a855f7]/20 text-[#a855f7] font-mono tabular-nums">{telemetryEvents.length}</span>
              )}
            </button>
          </div>

          <div className="flex-1 min-h-0 flex flex-col">
          {activeTab === 'alertas' && (
          <div className="flex gap-6 flex-1 min-h-0">

            {/* ─── PANEL IZQUIERDO: EVENT FEED ─── */}
            <div className="flex-[2] bg-[#111318] border border-[#1C2030] rounded-xl flex flex-col overflow-hidden">
              {/* Panel Header */}
              <div className="px-4 pt-3.5 pb-3 flex items-center justify-between border-b border-[#1C2030]">
                <div className="flex items-center gap-2.5">
                  <Activity className="w-4 h-4 text-[#8B5CF6]" />
                  <span className="text-sm font-semibold text-white">Eventos en Tiempo Real</span>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#0A0C10] text-[#475569] border border-[#1C2030] tabular-nums">
                    {filteredAlerts.length}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  {m5Reachable === true && (
                    <span className="flex items-center gap-1.5 text-[10px] text-[#22c55e] font-mono uppercase tracking-wider">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] animate-pulse" />
                      M5 Online
                    </span>
                  )}
                  {m5Reachable === false && (
                    <span className="flex items-center gap-1.5 text-[10px] text-[#ff3b3b] font-mono uppercase tracking-wider">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#ff3b3b]" />
                      M5 Offline
                    </span>
                  )}
                </div>
              </div>
              {/* Toolbar */}
              <div className="p-4 border-b border-[#1C2030] flex flex-wrap items-center justify-between gap-4">
                <div className="relative w-full max-w-xs">
                  <Search className="absolute left-3 top-2.5 w-4 h-4 text-[#475569]" />
                  <input
                    type="text"
                    placeholder="Buscar IP o CVE..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-[#8B5CF6] transition-colors"
                  />
                </div>

                <div className="flex items-center gap-2 bg-[#0A0C10] p-1 rounded-lg border border-[#1C2030]">
                  <Filter className="w-4 h-4 text-[#475569] ml-2 mr-1" />
                  {['ALL', 'Suricata (NIDS)', 'Wazuh (HIDS)', 'Cowrie (Honeypot)', 'M4-Pipeline'].map((src) => (
                    <button
                      key={src}
                      onClick={() => setFilterSource(src)}
                      className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                        filterSource === src
                          ? 'bg-[#1C2030] text-white'
                          : 'text-[#475569] hover:text-white hover:bg-[#111318]'
                      }`}
                    >
                      {src === 'ALL' ? 'Todos' : src === 'M4-Pipeline' ? 'Pipeline' : src.split(' ')[0]}
                    </button>
                  ))}
                </div>
              </div>

              {/* Cabeceras de columna */}
              {filteredAlerts.length > 0 && (
                <div className="px-4 py-2 grid grid-cols-[56px_1fr_120px] items-center gap-3 text-[9px] font-bold text-[#374151] uppercase tracking-widest bg-[#0d1117]/50 border-b border-[#1C2030]/50 select-none">
                  <span>Hora</span>
                  <span>Mensaje</span>
                  <span className="text-right">Fuente / IPs</span>
                </div>
              )}
              {/* Lista de Eventos */}
              <div className="flex-1 overflow-auto custom-scrollbar p-2">
                {filteredAlerts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-[#475569]">
                    <Search className="w-12 h-12 mb-3 opacity-20" />
                    <p className="text-sm">No se encontraron eventos con esos filtros.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {filteredAlerts.map((alert, idx) => {
                      const a = alert as M5Alert;
                      const alertId = a.id ?? `alert-${idx}`;
                      return (
                        <div
                          key={alertId}
                          className="flex items-start gap-3 px-3 py-3 rounded-lg bg-[#0A0C10]/50 hover:bg-[#1C2030]/60 border border-transparent hover:border-[#1C2030] transition-all"
                          style={{
                            borderLeft: `2px solid ${
                              a.severity === 'CRITICAL' ? '#ff3b3b' :
                              a.severity === 'HIGH'     ? '#f97316' :
                              a.severity === 'MEDIUM'   ? '#f59e0b' :
                              a.severity === 'LOW'      ? '#3b82f6' : '#374151'
                            }`,
                          }}
                        >
                          <AlertDateTime ts={a.timestamp} />

                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(a.severity)}`}>
                                {a.severity ?? 'UNKNOWN'}
                              </span>
                              <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-[#1C2030] text-[#64748B] text-[10px] font-semibold">
                                {getSourceIcon(a.source)}
                                <span>{a.source?.split(' ')?.[0]}</span>
                              </span>
                              {a.mitigated && (
                                <span className="px-2 py-0.5 rounded bg-[#22c55e]/10 text-[#22c55e] text-[10px] font-bold border border-[#22c55e]/20 flex items-center gap-1">
                                  <ShieldAlert className="w-3 h-3" /> Mitigado
                                </span>
                              )}
                              <span className="text-[10px] font-mono text-[#374151] ml-auto">{alertId}</span>
                            </div>

                            <p className="text-sm text-white font-medium truncate leading-snug">{a.message ?? a.description ?? ''}</p>

                            <div className="flex items-center gap-4 mt-1.5">
                              {a.target_ip && (
                                <div className="flex items-center gap-1 text-[11px]">
                                  <span className="text-[#334155]">dst</span>
                                  <span className="font-mono text-[#8B5CF6]">{a.target_ip}</span>
                                </div>
                              )}
                              {(a.attacker_ip ?? a.src_ip) && (
                                <div className="flex items-center gap-1 text-[11px]">
                                  <span className="text-[#334155]">src</span>
                                  <span className="font-mono text-[#ff3b3b]">{a.attacker_ip ?? a.src_ip}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* ─── PANEL DERECHO: HONEYPOT INTEL ─── */}
            <div className="flex-1 flex flex-col gap-4 min-h-0 overflow-y-auto custom-scrollbar">

              {/* ── TÍTULO DEL PANEL ── */}
              <div className="relative bg-[#111318] border border-[#1C2030] rounded-xl px-5 py-3 flex items-center justify-between shrink-0 overflow-hidden">
                <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#ff3b3b]/60 to-transparent" />
                <div className="flex items-center gap-2.5">
                  <div className="w-7 h-7 rounded-lg bg-[#ff3b3b]/10 border border-[#ff3b3b]/15 flex items-center justify-center shrink-0">
                    <Bug className="w-3.5 h-3.5 text-[#ff3b3b]" />
                  </div>
                  <div>
                    <span className="text-sm font-semibold text-white block leading-tight">Honeypot Intelligence</span>
                    <span className="text-[10px] text-[#475569]">Detección de intrusos por engaño</span>
                  </div>
                  <span className="text-[9px] px-2 py-0.5 rounded-full bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 text-[#ff3b3b] font-mono uppercase tracking-wider ml-1">ENS op.exp.4</span>
                </div>
                {honeypotLoading && (
                  <span className="text-[10px] text-[#334155] font-mono animate-pulse">cargando...</span>
                )}
              </div>

              {/* ── SECCIÓN 1: ESTADO DE CONTENEDORES ── */}
              <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4 shrink-0">
                <h4 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5" /> Estado de Contenedores
                </h4>
                <div className="space-y-2">
                  {/* Cowrie */}
                  <div className="flex items-center justify-between p-3 bg-[#0A0C10] rounded-lg border border-[#1C2030]">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-[#ff3b3b]/10 flex items-center justify-center">
                        <Flame className="w-4 h-4 text-[#ff3b3b]" />
                      </div>
                      <div>
                        <div className="text-sm font-medium text-white">Cowrie SSH/Telnet</div>
                        <div className="text-[10px] text-[#475569] font-mono">
                          {honeypotStatus?.cowrie?.ports?.length
                            ? `Puertos: ${honeypotStatus.cowrie.ports.join(', ')}`
                            : 'puertos: 2222, 2223'}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className="text-[10px] font-bold px-2 py-0.5 rounded border"
                        style={{
                          color: containerStatusColor(honeypotStatus?.cowrie?.status ?? 'unknown'),
                          borderColor: containerStatusColor(honeypotStatus?.cowrie?.status ?? 'unknown') + '40',
                          backgroundColor: containerStatusColor(honeypotStatus?.cowrie?.status ?? 'unknown') + '15',
                        }}
                      >
                        {containerStatusLabel(honeypotStatus?.cowrie?.status ?? 'unknown')}
                      </span>
                      {(honeypotStatus?.cowrie?.status ?? 'unknown') === 'running' && (
                        <span className="flex h-2 w-2 relative">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#22c55e] opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-[#22c55e]"></span>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Beelzebub */}
                  <div className="flex items-center justify-between p-3 bg-[#0A0C10] rounded-lg border border-[#1C2030]">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-[#a855f7]/10 flex items-center justify-center">
                        <Database className="w-4 h-4 text-[#a855f7]" />
                      </div>
                      <div>
                        <div className="text-sm font-medium text-white">Beelzebub HTTP/MySQL</div>
                        <div className="text-[10px] text-[#475569] font-mono">
                          {honeypotStatus?.beelzebub?.ports?.length
                            ? `Puertos: ${honeypotStatus.beelzebub.ports.join(', ')}`
                            : 'puertos: 8880, 3306'}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className="text-[10px] font-bold px-2 py-0.5 rounded border"
                        style={{
                          color: containerStatusColor(honeypotStatus?.beelzebub?.status ?? 'unknown'),
                          borderColor: containerStatusColor(honeypotStatus?.beelzebub?.status ?? 'unknown') + '40',
                          backgroundColor: containerStatusColor(honeypotStatus?.beelzebub?.status ?? 'unknown') + '15',
                        }}
                      >
                        {containerStatusLabel(honeypotStatus?.beelzebub?.status ?? 'unknown')}
                      </span>
                      {(honeypotStatus?.beelzebub?.status ?? 'unknown') === 'running' && (
                        <span className="flex h-2 w-2 relative">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#22c55e] opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-[#22c55e]"></span>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Red de aislamiento */}
                  {honeypotStatus && (
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-[#0A0C10] rounded-lg border border-[#1C2030]">
                      <Globe className="w-3 h-3 text-[#475569]" />
                      <span className="text-[10px] text-[#475569] font-mono">
                        Red aislada: <span className="text-[#64748B]">{honeypotStatus.isolation_network}</span>
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* ── SECCIÓN 2: SESIONES CAPTURADAS (TABS Cowrie / Beelzebub) ── */}
              <div className="bg-[#111318] border border-[#1C2030] rounded-xl flex flex-col">
                {/* Tab switcher */}
                <div className="flex border-b border-[#1C2030]">
                  <button
                    onClick={() => { setHoneypotTab('cowrie'); setExpandedSession(null); }}
                    className={`flex-1 py-2.5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer rounded-tl-xl ${
                      honeypotTab === 'cowrie'
                        ? 'text-[#ff3b3b] border-b-2 border-[#ff3b3b] bg-[#ff3b3b]/5'
                        : 'text-[#475569] hover:text-white'
                    }`}
                  >
                    <Flame className="w-3.5 h-3.5" />
                    Cowrie SSH
                    <span className="ml-1 px-1.5 py-0.5 rounded-full text-[9px] bg-[#ff3b3b]/20 text-[#ff3b3b] font-mono">{cowrieEvents.length}</span>
                  </button>
                  <button
                    onClick={() => { setHoneypotTab('beelzebub'); setExpandedSession(null); }}
                    className={`flex-1 py-2.5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer rounded-tr-xl ${
                      honeypotTab === 'beelzebub'
                        ? 'text-[#a855f7] border-b-2 border-[#a855f7] bg-[#a855f7]/5'
                        : 'text-[#475569] hover:text-white'
                    }`}
                  >
                    <Database className="w-3.5 h-3.5" />
                    Beelzebub HTTP
                    <span className="ml-1 px-1.5 py-0.5 rounded-full text-[9px] bg-[#a855f7]/20 text-[#a855f7] font-mono">{beelzebubEvents.length}</span>
                  </button>
                </div>

                {/* Lista de eventos del tab activo */}
                <div className="overflow-y-auto max-h-64 custom-scrollbar p-2 space-y-1">
                  {(honeypotTab === 'cowrie' ? cowrieEvents : beelzebubEvents).length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-8 text-[#475569]">
                      <Bug className="w-8 h-8 mb-2 opacity-20" />
                      <p className="text-xs">
                        {honeypotLoading ? 'Cargando eventos...' : 'Sin eventos capturados'}
                      </p>
                    </div>
                  ) : (
                    (honeypotTab === 'cowrie' ? cowrieEvents : beelzebubEvents).slice(0, 20).map((ev, idx) => {
                      const isExpanded = expandedSession === idx;
                      const commands = ev.detail ? ev.detail.split('\n').filter(Boolean) : [];
                      const accentColor = honeypotTab === 'cowrie' ? '#ff3b3b' : '#a855f7';

                      return (
                        <div key={idx} className="rounded-lg overflow-hidden border border-[#1C2030]">
                          {/* Fila principal */}
                          <button
                            onClick={() => setExpandedSession(isExpanded ? null : idx)}
                            className="w-full flex items-center gap-3 p-2.5 bg-[#0A0C10] hover:bg-[#1C2030]/60 transition-colors cursor-pointer text-left"
                          >
                            <div
                              className="w-1.5 h-1.5 rounded-full shrink-0"
                              style={{ backgroundColor: accentColor }}
                            />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-[10px] font-mono text-[#64748B]" style={{ color: accentColor }}>
                                  {ev.src_ip ?? '—'}
                                </span>
                                <span className="text-[10px] text-[#475569] truncate">{ev.event_type}</span>
                              </div>
                              {ev.detail && (
                                <p className="text-[10px] text-[#475569] truncate mt-0.5">{ev.detail}</p>
                              )}
                            </div>
                            <div className="flex items-center gap-1.5 shrink-0">
                              {ev.timestamp && <AlertDateTime ts={ev.timestamp} />}
                              {commands.length > 1
                                ? (isExpanded
                                    ? <ChevronDown className="w-3 h-3 text-[#475569]" />
                                    : <ChevronRight className="w-3 h-3 text-[#475569]" />)
                                : null
                              }
                            </div>
                          </button>

                          {/* Panel expandible — comandos ejecutados */}
                          {isExpanded && commands.length > 0 && (
                            <div className="bg-[#0a0d14] border-t border-[#1C2030] p-2.5">
                              <p className="text-[9px] text-[#475569] uppercase tracking-wider mb-1.5 font-semibold">Comandos ejecutados</p>
                              <div className="space-y-1">
                                {commands.map((cmd, ci) => (
                                  <div key={ci} className="flex items-start gap-2">
                                    <span className="text-[#22c55e] text-[10px] font-mono shrink-0">$</span>
                                    <code className="text-[10px] font-mono text-[#e5e7eb] break-all">{cmd}</code>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              {/* ── SECCIÓN 3: TIMELINE DE ATACANTES ── */}
              <div className="bg-[#111318] border border-[#1C2030] rounded-xl p-4">
                <h4 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Clock className="w-3.5 h-3.5" /> Timeline Atacantes (7d)
                </h4>
                {honeypotAttackers.length === 0 ? (
                  <p className="text-xs text-[#475569] text-center py-4">
                    {honeypotLoading ? 'Cargando...' : 'Sin datos de atacantes'}
                  </p>
                ) : (
                  <div className="space-y-3">
                    {honeypotAttackers.slice(0, 5).map((atk, idx) => {
                      const pct = Math.round((atk.attempts / maxAttacks) * 100);
                      return (
                        <div key={idx}>
                          <div className="flex justify-between items-start mb-1">
                            <span className="text-[11px] font-mono text-[#64748B]">{atk.ip}</span>
                            <span className="text-[10px] font-bold" style={{ color: idx === 0 ? '#ff3b3b' : '#f59e0b' }}>
                              {atk.attempts} intentos
                            </span>
                          </div>
                          <div className="w-full bg-[#0A0C10] rounded-full h-1.5 mb-1">
                            <div
                              className="h-1.5 rounded-full transition-all"
                              style={{
                                width: `${pct}%`,
                                background: idx === 0
                                  ? 'linear-gradient(to right, #ff3b3b80, #ff3b3b)'
                                  : 'linear-gradient(to right, #f59e0b60, #f59e0b)',
                              }}
                            />
                          </div>
                          <div className="flex justify-between text-[9px] text-[#334155] font-mono">
                            <span>Primero: {fmtDate(atk.first_seen)}</span>
                            <span>Último: {fmtDate(atk.last_seen)}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

            </div>
          </div>
          )}

          {activeTab === 'telemetria' && (
          <div className="flex-1 overflow-y-auto custom-scrollbar">
          <div className="bg-[#0d1117] border border-[#1C2030] rounded-xl overflow-hidden">

            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1C2030]">
              <div className="flex items-center gap-3">
                <Server className="w-5 h-5 text-[#a855f7]" />
                <div>
                  <h2 className="text-white font-semibold text-sm">Telemetría Agentless de Activos</h2>
                  <p className="text-[#475569] text-xs mt-0.5">
                    Recolección vía SSH — logs web, syslog, auth, audit, procesos · ENS op.exp.4 · op.mon.1
                  </p>
                </div>
              </div>
              <button
                onClick={fetchTelemetry}
                disabled={telemetryLoading}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all
                  bg-[#a855f7]/10 text-[#a855f7] border border-[#a855f7]/20
                  hover:bg-[#a855f7]/20 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Activity className={`w-3.5 h-3.5 ${telemetryLoading ? 'animate-spin' : ''}`} />
                {telemetryLoading ? 'Escaneando activos…' : telemetryLoaded ? 'Actualizar Telemetría' : 'Iniciar Escaneo'}
              </button>
            </div>

            {!telemetryLoaded && !telemetryLoading && (
              <div className="flex flex-col items-center justify-center py-14 text-[#334155]">
                <Server className="w-10 h-10 mb-3 opacity-30" />
                <p className="text-sm">Pulsa "Iniciar Escaneo" para recolectar telemetría de todos los activos</p>
                <p className="text-xs mt-1 text-[#374151]">Se conectará vía SSH y analizará logs web, syslog, procesos y conexiones</p>
              </div>
            )}

            {telemetryLoading && (
              <div className="flex items-center justify-center py-14 gap-3 text-[#a855f7]">
                <Activity className="w-5 h-5 animate-spin" />
                <span className="text-sm">Recolectando telemetría de activos vía SSH…</span>
              </div>
            )}

            {telemetryLoaded && !telemetryLoading && (
              <div className="p-5 space-y-5">

                {/* Resumen por host */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {hostSummaries.map(h => (
                    <div
                      key={h.asset_ip}
                      onClick={() => setExpandedHost(expandedHost === h.asset_ip ? null : h.asset_ip)}
                      className="cursor-pointer rounded-lg border border-[#1C2030] bg-[#0A0C10]/60 p-4
                        hover:border-[#a855f7]/30 transition-all"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${h.reachable ? 'bg-[#22c55e]' : 'bg-[#ef4444]'}`} />
                          <span className="text-white text-xs font-semibold">{h.asset_name}</span>
                        </div>
                        <span className="text-[10px] font-mono text-[#475569]">{h.asset_ip}</span>
                      </div>
                      {h.reachable ? (
                        <>
                          <div className="flex items-center gap-2 flex-wrap mt-2">
                            {h.severity_counts.CRITICAL > 0 && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#ff3b3b]/10 text-[#ff3b3b] border border-[#ff3b3b]/20">
                                {h.severity_counts.CRITICAL} CRITICAL
                              </span>
                            )}
                            {h.severity_counts.HIGH > 0 && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#f97316]/10 text-[#f97316] border border-[#f97316]/20">
                                {h.severity_counts.HIGH} HIGH
                              </span>
                            )}
                            {h.severity_counts.MEDIUM > 0 && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#f59e0b]/10 text-[#f59e0b] border border-[#f59e0b]/20">
                                {h.severity_counts.MEDIUM} MED
                              </span>
                            )}
                            {h.total_events === 0 && (
                              <span className="text-[10px] text-[#475569]">Sin eventos detectados</span>
                            )}
                          </div>
                          <div className="flex gap-3 mt-2 text-[10px] text-[#475569]">
                            <span>{h.processes.length} procs</span>
                            <span>{h.connections.length} conex</span>
                            <span>{h.log_sources.join(', ') || '—'}</span>
                          </div>
                        </>
                      ) : (
                        <p className="text-[10px] text-[#ef4444] mt-1">Sin acceso SSH</p>
                      )}

                      {/* Detalle expandido del host */}
                      {expandedHost === h.asset_ip && h.reachable && (
                        <div className="mt-3 pt-3 border-t border-[#1C2030] space-y-2">
                          {h.last_logins.length > 0 && (
                            <div>
                              <p className="text-[10px] text-[#475569] mb-1 uppercase tracking-wider">Últimos logins</p>
                              {h.last_logins.slice(0, 5).map((l, i) => (
                                <p key={i} className="text-[10px] font-mono text-[#64748B] truncate">{l}</p>
                              ))}
                            </div>
                          )}
                          {h.disk_usage.filter(d => d.used_pct >= 80).map((d, i) => (
                            <div key={i} className="flex items-center gap-2">
                              <span className="text-[10px] text-[#f59e0b]">⚠ Disco {d.mount}: {d.used_pct}%</span>
                            </div>
                          ))}
                          {h.processes.filter(p => p.suspicious).slice(0, 3).map((p, i) => (
                            <p key={i} className="text-[10px] font-mono text-[#ff3b3b] truncate">⚠ {p.command}</p>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                {/* Filtros de eventos */}
                {telemetryEvents.length > 0 && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <Search className="w-3.5 h-3.5 text-[#475569]" />
                    <input
                      value={telemetrySearch}
                      onChange={e => setTelemetrySearch(e.target.value)}
                      placeholder="Buscar IP, acción, activo…"
                      className="bg-[#0A0C10] border border-[#1C2030] rounded px-3 py-1 text-xs text-white
                        placeholder-[#334155] focus:outline-none focus:border-[#a855f7]/40 w-48"
                    />
                    {(['ALL','CRITICAL','HIGH','MEDIUM','LOW'] as const).map(s => (
                      <button
                        key={s}
                        onClick={() => setTelemetryFilter(s)}
                        className={`px-3 py-1 rounded text-[10px] font-bold border transition-all ${
                          telemetryFilter === s
                            ? 'bg-[#a855f7]/20 text-[#a855f7] border-[#a855f7]/40'
                            : 'bg-transparent text-[#475569] border-[#1C2030] hover:border-[#374151]'
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                    <span className="text-[10px] text-[#334155] ml-auto">
                      {telemetryFiltered.length} / {telemetryEvents.length} eventos
                    </span>
                  </div>
                )}

                {/* Tabla de eventos */}
                {telemetryFiltered.length === 0 ? (
                  <div className="text-center py-8 text-[#334155] text-sm">
                    {telemetryEvents.length === 0
                      ? '✅ Sin eventos de seguridad detectados en los activos'
                      : 'Sin resultados para el filtro aplicado'}
                  </div>
                ) : (
                  <>
                  <div className="flex items-center gap-3 px-3 py-2 text-[9px] font-bold text-[#374151] uppercase tracking-widest rounded-lg bg-[#0d1117]/70 border border-[#1C2030]/60 select-none">
                    <span className="w-[68px] shrink-0">Hora</span>
                    <span className="w-[104px] shrink-0">Severidad / Tipo</span>
                    <span className="flex-1">Mensaje</span>
                    <span className="w-36 text-right shrink-0">Activo / IP</span>
                  </div>
                  <div className="space-y-1 max-h-[600px] overflow-y-auto pr-1">
                    {telemetryFiltered.slice(0, 100).map((ev, i) => (
                      <div
                        key={ev.alert_id || i}
                        className="flex items-start gap-3 p-3 rounded-lg bg-[#0A0C10]/50
                          hover:bg-[#1C2030]/40 border border-transparent hover:border-[#1C2030] transition-all"
                      >
                        {/* Fecha/hora */}
                        <AlertDateTime ts={ev.timestamp} />

                        {/* Badges */}
                        <div className="flex flex-col gap-1 shrink-0 pt-0.5">
                          <span
                            className="px-2 py-0.5 rounded text-[10px] font-bold border"
                            style={{
                              color: SEVERITY_COLOR[ev.severity] || '#475569',
                              borderColor: (SEVERITY_COLOR[ev.severity] || '#475569') + '40',
                              backgroundColor: (SEVERITY_COLOR[ev.severity] || '#475569') + '12',
                            }}
                          >
                            {ev.severity}
                          </span>
                          <span
                            className="px-2 py-0.5 rounded text-[10px] font-bold border"
                            style={{
                              color: SOURCE_COLOR[ev.source] || '#475569',
                              borderColor: (SOURCE_COLOR[ev.source] || '#475569') + '40',
                              backgroundColor: (SOURCE_COLOR[ev.source] || '#475569') + '12',
                            }}
                          >
                            {SOURCE_LABEL[ev.source] || (ev.source ?? '').toUpperCase()}
                          </span>
                        </div>

                        {/* Contenido */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="text-white text-xs font-medium truncate">{ev.message}</span>
                          </div>
                          <div className="flex items-center gap-3 text-[10px] text-[#475569]">
                            <span className="font-mono text-[#a855f7]">{ev.agent_name}</span>
                            {ev.src_ip && <span>Origen: <span className="text-[#f97316] font-mono">{ev.src_ip}</span></span>}
                            {ev.action_type && <span className="font-mono">{ev.action_type}</span>}
                            {ev.mitre_technique && (
                              <span className="px-1.5 py-0.5 rounded bg-[#1C2030] font-mono text-[#475569]">
                                {ev.mitre_technique}
                              </span>
                            )}
                          </div>
                          {ev.raw_log && ev.raw_log !== ev.message && (
                            <p className="text-[10px] font-mono text-[#334155] truncate mt-0.5">{ev.raw_log}</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                  </>
                )}
              </div>
            )}
          </div>
          </div>
          )}

          </div>

        </main>
      </div>
    </div>
  );
}
