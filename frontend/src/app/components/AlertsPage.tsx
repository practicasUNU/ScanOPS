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
  Skull,
  Terminal
} from 'lucide-react';

const ORCHESTRATOR_BASE = 'http://localhost:8009';
const M5_BASE = 'http://localhost:8006';

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

interface TopAttacker {
  ip: string;
  count: number;
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
  { id: 'AL-901', timestamp: '10:45:02', source: 'Suricata (NIDS)', severity: 'CRITICAL', message: 'ET EXPLOIT Possible CVE-2021-44228 Apache Log4j RCE', target_ip: '10.202.15.15', attacker_ip: '185.15.56.22', mitigated: true },
  { id: 'AL-902', timestamp: '10:42:15', source: 'Wazuh (HIDS)', severity: 'HIGH', message: 'Multiple authentication failures (SSH Brute Force)', target_ip: '10.202.15.10', attacker_ip: '112.54.22.1', mitigated: true },
  { id: 'AL-903', timestamp: '10:39:50', source: 'Cowrie (Honeypot)', severity: 'MEDIUM', message: 'Unauthorized login success in Honeypot container', target_ip: '10.202.99.99', attacker_ip: '45.33.22.12', mitigated: false },
  { id: 'AL-904', timestamp: '10:35:12', source: 'Wazuh (HIDS)', severity: 'LOW', message: 'System package updated globally', target_ip: '10.202.15.15', mitigated: false },
  { id: 'AL-905', timestamp: '10:30:05', source: 'Suricata (NIDS)', severity: 'HIGH', message: 'ET SCAN Nmap OS Detection Probe', target_ip: '10.202.15.20', attacker_ip: '192.168.1.100', mitigated: false },
  { id: 'AL-906', timestamp: '10:25:33', source: 'Cowrie (Honeypot)', severity: 'CRITICAL', message: 'Malware sample dropped via wget (Mirai variant)', target_ip: '10.202.99.99', attacker_ip: '89.22.33.1', mitigated: true },
];

// ─── COMPONENTES AUXILIARES ───
const getSeverityBadge = (severity: string | undefined) => {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'bg-[#ff3b3b]/10 text-[#ff3b3b] border-[#ff3b3b]/30';
    case 'HIGH':     return 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30';
    case 'MEDIUM':   return 'bg-[#00d4ff]/10 text-[#00d4ff] border-[#00d4ff]/30';
    case 'LOW':      return 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30';
    default:         return 'bg-[#6b7280]/10 text-[#6b7280] border-[#6b7280]/30';
  }
};

const getSourceIcon = (source: string | undefined) => {
  switch (source) {
    case 'Suricata (NIDS)':   return <Activity className="w-4 h-4 text-[#00d4ff]" />;
    case 'Wazuh (HIDS)':      return <Lock className="w-4 h-4 text-[#22c55e]" />;
    case 'Cowrie (Honeypot)': return <Flame className="w-4 h-4 text-[#ff3b3b]" />;
    default:                  return <Server className="w-4 h-4 text-[#9ca3af]" />;
  }
};

export function AlertsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [isLive, setIsLive] = useState(true);
  const [filterSource, setFilterSource] = useState<string>('ALL');
  const [kpis, setKpis] = useState<SiemKpis | null>(null);
  const [kpisLoading, setKpisLoading] = useState(true);
  const [topAttackers, setTopAttackers] = useState<TopAttacker[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<M5Alert[]>([]);
  const [alertsLoading, setAlertsLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

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

    const fetchTopAttackers = async () => {
      try {
        const res = await fetch(`${ORCHESTRATOR_BASE}/orchestrator/siem/top-attackers`, {
          headers: authH(),
          signal: AbortSignal.timeout(8000),
        });
        if (res.ok) {
          const data = await res.json() as { attackers?: TopAttacker[] };
          setTopAttackers(data.attackers ?? []);
        }
      } catch { /* silencioso */ }
    };

    fetchKpis();
    fetchTopAttackers();
    const id = setInterval(() => { fetchKpis(); fetchTopAttackers(); }, 30000);
    return () => clearInterval(id);
  }, []);

  // Live alerts polling (15s) — stops when isLive is false
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

        const combined: M5Alert[] = [];

        if (suricataRes.status === 'fulfilled' && suricataRes.value.ok) {
          const data = await suricataRes.value.json() as Record<string, unknown>;
          const rawAlerts = ((data.alerts as unknown[]) ?? []).slice(0, 20);
          const mapped = rawAlerts.map((a: unknown, i: number) => {
            const al = a as Record<string, unknown>;
            const nested = al.alert as Record<string, unknown> | undefined;
            return {
              id: (al.id as string | undefined) ?? `suricata-${i}`,
              timestamp: (al.timestamp as string | undefined) ?? '',
              source: 'Suricata (NIDS)',
              severity: ((al.severity as string | undefined)?.toUpperCase()) ?? 'MEDIUM',
              message: (al.signature as string | undefined)
                ?? (al.message as string | undefined)
                ?? (nested?.signature as string | undefined)
                ?? 'Suricata alert',
              src_ip: al.src_ip as string | undefined,
              target_ip: (al.dest_ip as string | undefined) ?? (al.target_ip as string | undefined),
              attacker_ip: al.src_ip as string | undefined,
              mitigated: al.action === 'blocked' || al.mitigated === true,
            } satisfies M5Alert;
          });
          combined.push(...mapped);
        }

        if (cowrieRes.status === 'fulfilled' && cowrieRes.value.ok) {
          const data = await cowrieRes.value.json() as Record<string, unknown>;
          const rawEvents = ((data.events as unknown[]) ?? []).slice(0, 10);
          const mapped = rawEvents.map((e: unknown, i: number) => {
            const ev = e as Record<string, unknown>;
            return {
              id: `cowrie-${i}`,
              timestamp: (ev.timestamp as string | undefined) ?? '',
              source: 'Cowrie (Honeypot)',
              severity: 'HIGH',
              message: (ev.detail as string | undefined) ?? (ev.event_type as string | undefined) ?? 'Honeypot interaction',
              src_ip: ev.src_ip as string | undefined,
              attacker_ip: ev.src_ip as string | undefined,
              mitigated: false,
            } satisfies M5Alert;
          });
          combined.push(...mapped);
        }

        if (combined.length > 0) {
          combined.sort((a, b) =>
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
          );
          setLiveAlerts(combined.slice(0, 50));
        }
      } catch { /* silencioso */ }
      finally { setAlertsLoading(false); }
    };

    fetchAlerts();
    const id = setInterval(fetchAlerts, 15000);
    return () => clearInterval(id);
  }, [isLive]);

  const alerts: (M5Alert | SiemAlert)[] = liveAlerts.length > 0 ? liveAlerts : MOCK_ALERTS;
  const filteredAlerts = alerts.filter(alert => {
    const a = alert as M5Alert;
    const msg = (a.message ?? '').toLowerCase();
    const desc = (a.description ?? '').toLowerCase();
    const matchesSearch =
      msg.includes(searchTerm.toLowerCase()) ||
      desc.includes(searchTerm.toLowerCase()) ||
      (a.attacker_ip ?? '').includes(searchTerm) ||
      (a.src_ip ?? '').includes(searchTerm);
    const matchesSource = filterSource === 'ALL' || alert.source === filterSource;
    return matchesSearch && matchesSource;
  });

  const maxAttackerCount = topAttackers.length > 0 ? topAttackers[0].count : 1;

  return (
    <div className="flex h-screen bg-[#0f1117]">
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
                  <p className="text-[#9ca3af] text-sm">Correlación de eventos Wazuh, Suricata y Honeypots (ENS op.mon.1)</p>
                  {lastUpdated && (
                    <span className="text-xs text-[#6b7280] font-mono">Actualizado: {lastUpdated}</span>
                  )}
                </div>
              </div>
            </div>

            <button
              onClick={() => setIsLive(!isLive)}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex items-center gap-2 border cursor-pointer ${
                isLive
                  ? 'bg-[#1a1d27] border-[#1e2530] text-[#6b7280] hover:text-white'
                  : 'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff] hover:bg-[#00d4ff]/20'
              }`}
            >
              <Wifi className="w-4 h-4" />
              {isLive ? 'Pausar Telemetría' : 'Reanudar Stream'}
            </button>
          </div>

          {/* ─── KPIS TOP ─── */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 shrink-0">
            {/* Card 1 — Ataques Perimetrales */}
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-[#6b7280] uppercase tracking-wider font-semibold mb-1">Ataques Perimetrales Bloqueados</p>
                <h3 className="text-2xl font-bold text-white">
                  {kpisLoading ? '...' : (kpis?.suricata_blocked ?? 142).toLocaleString()}
                </h3>
                <p className="text-xs text-[#22c55e] mt-1">
                  {kpis ? `Fuente: Suricata IPS · ${lastUpdated}` : '+12% vs ayer (Suricata IPS)'}
                </p>
              </div>
              <div className="p-3 bg-[#00d4ff]/10 rounded-lg"><Activity className="w-5 h-5 text-[#00d4ff]" /></div>
            </div>

            {/* Card 2 — Autenticación HIDS */}
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-[#6b7280] uppercase tracking-wider font-semibold mb-1">Alertas de Autenticación HIDS</p>
                <h3 className="text-2xl font-bold text-white">
                  {kpisLoading ? '...' : (kpis?.wazuh_auth_failures ?? 28)}
                </h3>
                <p className="text-xs text-[#f59e0b] mt-1">
                  {kpis
                    ? (kpis.wazuh_auth_failures > 0 ? 'Requiere revisión (Wazuh)' : 'Sin alertas activas')
                    : 'Requiere revisión (Wazuh)'}
                </p>
              </div>
              <div className="p-3 bg-[#f59e0b]/10 rounded-lg"><Lock className="w-5 h-5 text-[#f59e0b]" /></div>
            </div>

            {/* Card 3 — Honeypot */}
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-[#6b7280] uppercase tracking-wider font-semibold mb-1">Interacciones en Honeypot</p>
                <h3
                  className="text-2xl font-bold"
                  style={{ color: kpis && kpis.cowrie_interactions > 0 ? '#ff3b3b' : 'white' }}
                >
                  {kpisLoading ? '...' : (kpis?.cowrie_interactions ?? 7)}
                </h3>
                <p className="text-xs text-[#ff3b3b] mt-1">
                  {kpis ? `${kpis.cowrie_interactions} eventos capturados (Cowrie)` : '2 payloads capturados'}
                </p>
              </div>
              <div className="p-3 bg-[#ff3b3b]/10 rounded-lg"><Flame className="w-5 h-5 text-[#ff3b3b]" /></div>
            </div>

            {/* Card 4 — Estado SIEM */}
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-[#6b7280] uppercase tracking-wider font-semibold mb-1">Estado del Nodo SIEM</p>
                <h3
                  className="text-2xl font-bold"
                  style={{
                    color: kpis?.sensor_health === 'ok' ? '#22c55e'
                      : kpis?.sensor_health === 'degraded' ? '#f59e0b'
                      : kpis?.sensor_health === 'offline' ? '#ff3b3b'
                      : 'white',
                  }}
                >
                  {kpisLoading ? '...' : kpis ? `${kpis.sensors_online}/${kpis.sensors_total}` : '100%'}
                </h3>
                <p className="text-xs text-[#22c55e] mt-1">
                  {kpis?.sensor_health === 'ok'
                    ? 'Todos los sensores respondiendo'
                    : kpis?.sensor_health === 'degraded'
                    ? 'Algunos sensores sin respuesta'
                    : kpis?.sensor_health === 'offline'
                    ? 'Sensores offline'
                    : 'Todos los agentes respondiendo'}
                </p>
              </div>
              <div className="p-3 bg-[#22c55e]/10 rounded-lg"><Server className="w-5 h-5 text-[#22c55e]" /></div>
            </div>
          </div>

          {/* Banner datos mock */}
          {liveAlerts.length === 0 && !alertsLoading && (
            <div className="px-4 py-2 bg-[#f59e0b]/10 border border-[#f59e0b]/20 rounded-lg text-xs text-[#f59e0b] flex items-center gap-2">
              <AlertTriangle className="w-3 h-3 shrink-0" />
              M5 no disponible — mostrando datos de demostración
            </div>
          )}

          <div className="flex flex-1 gap-6 min-h-0">

            {/* ─── PANEL IZQUIERDO: EVENT FEED ─── */}
            <div className="flex-[2] bg-[#1a1d27] border border-[#1e2530] rounded-xl flex flex-col overflow-hidden">
              {/* Toolbar */}
              <div className="p-4 border-b border-[#1e2530] flex flex-wrap items-center justify-between gap-4">
                <div className="relative w-full max-w-xs">
                  <Search className="absolute left-3 top-2.5 w-4 h-4 text-[#6b7280]" />
                  <input
                    type="text"
                    placeholder="Buscar IP o CVE..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-[#00d4ff] transition-colors"
                  />
                </div>

                <div className="flex items-center gap-2 bg-[#0f1117] p-1 rounded-lg border border-[#1e2530]">
                  <Filter className="w-4 h-4 text-[#6b7280] ml-2 mr-1" />
                  {['ALL', 'Suricata (NIDS)', 'Wazuh (HIDS)', 'Cowrie (Honeypot)'].map((src) => (
                    <button
                      key={src}
                      onClick={() => setFilterSource(src)}
                      className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                        filterSource === src
                          ? 'bg-[#1e2530] text-white'
                          : 'text-[#6b7280] hover:text-white hover:bg-[#1a1d27]'
                      }`}
                    >
                      {src === 'ALL' ? 'Todos' : src.split(' ')[0]}
                    </button>
                  ))}
                </div>
              </div>

              {/* Lista de Eventos */}
              <div className="flex-1 overflow-auto custom-scrollbar p-2">
                {filteredAlerts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-[#6b7280]">
                    <Search className="w-12 h-12 mb-3 opacity-20" />
                    <p className="text-sm">No se encontraron eventos con esos filtros.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {filteredAlerts.map((alert, idx) => {
                      const a = alert as M5Alert;
                      const alertId = a.id ?? `alert-${idx}`;
                      return (
                        <div key={alertId} className="flex items-start gap-4 p-4 rounded-lg bg-[#0f1117]/50 hover:bg-[#1e2530]/50 border border-transparent hover:border-[#1e2530] transition-all group">

                          <div className="flex flex-col items-center gap-2 mt-1">
                            {getSourceIcon(a.source)}
                            <span className="text-[10px] text-[#6b7280] font-mono">{a.timestamp}</span>
                          </div>

                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(a.severity)}`}>
                                {a.severity ?? 'UNKNOWN'}
                              </span>
                              <span className="text-xs font-mono text-[#9ca3af]">{alertId}</span>
                              {a.mitigated && (
                                <span className="px-2 py-0.5 rounded bg-[#22c55e]/10 text-[#22c55e] text-[10px] font-bold border border-[#22c55e]/20 ml-auto flex items-center gap-1">
                                  <ShieldAlert className="w-3 h-3" /> Auto-Mitigado
                                </span>
                              )}
                            </div>

                            <p className="text-sm text-white font-medium truncate">{a.message ?? a.description ?? ''}</p>

                            <div className="flex items-center gap-4 mt-2">
                              {a.target_ip && (
                                <div className="flex items-center gap-1.5 text-xs">
                                  <span className="text-[#6b7280]">Target:</span>
                                  <span className="font-mono text-[#00d4ff]">{a.target_ip}</span>
                                </div>
                              )}
                              {(a.attacker_ip ?? a.src_ip) && (
                                <div className="flex items-center gap-1.5 text-xs">
                                  <span className="text-[#6b7280]">Origen:</span>
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

            {/* ─── PANEL DERECHO: CONTEXTO Y AMENAZAS ─── */}
            <div className="flex-1 flex flex-col gap-6 min-h-0 overflow-y-auto custom-scrollbar">

              {/* Top Atacantes */}
              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                  <Skull className="w-4 h-4 text-[#ff3b3b]" /> Top IPs Agresoras (24h)
                </h3>
                {topAttackers.length === 0 ? (
                  <p className="text-xs text-[#6b7280]">Sin datos de atacantes. M5 no disponible o sin eventos.</p>
                ) : (
                  <div className="space-y-4">
                    {topAttackers.map((atk, idx) => {
                      const pct = Math.round((atk.count / maxAttackerCount) * 100);
                      return (
                        <div key={idx}>
                          <div className="flex justify-between text-xs mb-1.5">
                            <span className="font-mono text-[#9ca3af]">{atk.ip}</span>
                            <span className="text-[#ff3b3b] font-semibold">{atk.count} evts</span>
                          </div>
                          <div className="w-full bg-[#0f1117] rounded-full h-1.5">
                            <div
                              className="bg-gradient-to-r from-[#ff3b3b]/50 to-[#ff3b3b] h-1.5 rounded-full"
                              style={{ width: `${pct}%` }}
                            ></div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Status de Sensores */}
              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-[#00d4ff]" /> Estado de Sensores
                </h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-[#0f1117] rounded-lg border border-[#1e2530]">
                    <div className="flex items-center gap-3">
                      <Activity className="w-4 h-4 text-[#00d4ff]" />
                      <div>
                        <div className="text-sm text-white font-medium">Suricata IPS (NIDS)</div>
                        <div className="text-[10px] text-[#6b7280]">eth0 promiscuous mode</div>
                      </div>
                    </div>
                    <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#22c55e] opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-[#22c55e]"></span>
                    </span>
                  </div>

                  <div className="flex items-center justify-between p-3 bg-[#0f1117] rounded-lg border border-[#1e2530]">
                    <div className="flex items-center gap-3">
                      <Lock className="w-4 h-4 text-[#22c55e]" />
                      <div>
                        <div className="text-sm text-white font-medium">Wazuh Manager</div>
                        <div className="text-[10px] text-[#6b7280]">15 Active Agents</div>
                      </div>
                    </div>
                    <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#22c55e] opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-[#22c55e]"></span>
                    </span>
                  </div>

                  <div className="flex items-center justify-between p-3 bg-[#0f1117] rounded-lg border border-[#1e2530]">
                    <div className="flex items-center gap-3">
                      <Flame className="w-4 h-4 text-[#ff3b3b]" />
                      <div>
                        <div className="text-sm text-white font-medium">Cowrie SSH Honeypot</div>
                        <div className="text-[10px] text-[#6b7280]">Port 22 (Redirected)</div>
                      </div>
                    </div>
                    <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#22c55e] opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-[#22c55e]"></span>
                    </span>
                  </div>
                </div>
              </div>

              {/* Quick Action */}
              <div className="mt-auto p-4 bg-[#f59e0b]/10 border border-[#f59e0b]/30 rounded-xl">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-[#f59e0b] shrink-0" />
                  <div>
                    <h4 className="text-sm font-semibold text-[#f59e0b]">Integración IPS Activa</h4>
                    <p className="text-xs text-[#f59e0b]/80 mt-1">
                      Las IPs con más de 50 intentos fallidos están siendo bloqueadas automáticamente por Suricata mediante IP-Tables en el firewall perimetral (ENS op.pl.3).
                    </p>
                  </div>
                </div>
              </div>

            </div>
          </div>

        </main>
      </div>
    </div>
  );
}
