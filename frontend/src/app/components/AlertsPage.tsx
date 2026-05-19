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
const getSeverityBadge = (severity: AlertSeverity) => {
  switch (severity) {
    case 'CRITICAL': return 'bg-[#ff3b3b]/10 text-[#ff3b3b] border-[#ff3b3b]/30';
    case 'HIGH': return 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30';
    case 'MEDIUM': return 'bg-[#00d4ff]/10 text-[#00d4ff] border-[#00d4ff]/30';
    case 'LOW': return 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30';
  }
};

const getSourceIcon = (source: AlertSource) => {
  switch (source) {
    case 'Suricata (NIDS)': return <Activity className="w-4 h-4 text-[#00d4ff]" />;
    case 'Wazuh (HIDS)': return <Lock className="w-4 h-4 text-[#22c55e]" />;
    case 'Cowrie (Honeypot)': return <Flame className="w-4 h-4 text-[#ff3b3b]" />;
    case 'Orchestrator': return <Server className="w-4 h-4 text-[#9ca3af]" />;
  }
};

export function AlertsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [isLive, setIsLive] = useState(true);
  const [filterSource, setFilterSource] = useState<string>('ALL');

  // Filtrado de eventos
  const filteredAlerts = MOCK_ALERTS.filter(alert => {
    const matchesSearch = alert.message.toLowerCase().includes(searchTerm.toLowerCase()) || alert.attacker_ip?.includes(searchTerm);
    const matchesSource = filterSource === 'ALL' || alert.source === filterSource;
    return matchesSearch && matchesSource;
  });

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
                <p className="text-[#9ca3af] text-sm">Correlación de eventos Wazuh, Suricata y Honeypots (ENS op.mon.1)</p>
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
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-[#6b7280] uppercase tracking-wider font-semibold mb-1">Ataques Perimetrales Bloqueados</p>
                <h3 className="text-2xl font-bold text-white">142</h3>
                <p className="text-xs text-[#22c55e] mt-1">+12% vs ayer (Suricata IPS)</p>
              </div>
              <div className="p-3 bg-[#00d4ff]/10 rounded-lg"><Activity className="w-5 h-5 text-[#00d4ff]" /></div>
            </div>
            
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-[#6b7280] uppercase tracking-wider font-semibold mb-1">Alertas de Autenticación HIDS</p>
                <h3 className="text-2xl font-bold text-white">28</h3>
                <p className="text-xs text-[#f59e0b] mt-1">Requiere revisión (Wazuh)</p>
              </div>
              <div className="p-3 bg-[#f59e0b]/10 rounded-lg"><Lock className="w-5 h-5 text-[#f59e0b]" /></div>
            </div>

            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-[#6b7280] uppercase tracking-wider font-semibold mb-1">Interacciones en Honeypot</p>
                <h3 className="text-2xl font-bold text-[#ff3b3b]">7</h3>
                <p className="text-xs text-[#ff3b3b] mt-1">2 payloads capturados (Cowrie)</p>
              </div>
              <div className="p-3 bg-[#ff3b3b]/10 rounded-lg"><Flame className="w-5 h-5 text-[#ff3b3b]" /></div>
            </div>

            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-[#6b7280] uppercase tracking-wider font-semibold mb-1">Estado del Nodo SIEM</p>
                <h3 className="text-2xl font-bold text-white">100%</h3>
                <p className="text-xs text-[#22c55e] mt-1">Todos los agentes respondiendo</p>
              </div>
              <div className="p-3 bg-[#22c55e]/10 rounded-lg"><Server className="w-5 h-5 text-[#22c55e]" /></div>
            </div>
          </div>

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
                    {filteredAlerts.map((alert) => (
                      <div key={alert.id} className="flex items-start gap-4 p-4 rounded-lg bg-[#0f1117]/50 hover:bg-[#1e2530]/50 border border-transparent hover:border-[#1e2530] transition-all group">
                        
                        <div className="flex flex-col items-center gap-2 mt-1">
                          {getSourceIcon(alert.source)}
                          <span className="text-[10px] text-[#6b7280] font-mono">{alert.timestamp}</span>
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(alert.severity)}`}>
                              {alert.severity}
                            </span>
                            <span className="text-xs font-mono text-[#9ca3af]">{alert.id}</span>
                            {alert.mitigated && (
                              <span className="px-2 py-0.5 rounded bg-[#22c55e]/10 text-[#22c55e] text-[10px] font-bold border border-[#22c55e]/20 ml-auto flex items-center gap-1">
                                <ShieldAlert className="w-3 h-3" /> Auto-Mitigado
                              </span>
                            )}
                          </div>
                          
                          <p className="text-sm text-white font-medium truncate">{alert.message}</p>
                          
                          <div className="flex items-center gap-4 mt-2">
                            <div className="flex items-center gap-1.5 text-xs">
                              <span className="text-[#6b7280]">Target:</span>
                              <span className="font-mono text-[#00d4ff]">{alert.target_ip}</span>
                            </div>
                            {alert.attacker_ip && (
                              <div className="flex items-center gap-1.5 text-xs">
                                <span className="text-[#6b7280]">Origen:</span>
                                <span className="font-mono text-[#ff3b3b]">{alert.attacker_ip}</span>
                              </div>
                            )}
                          </div>
                        </div>

                      </div>
                    ))}
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
                <div className="space-y-4">
                  {[
                    { ip: '185.15.56.22', count: 1205, bar: 'w-[85%]' },
                    { ip: '89.22.33.1', count: 840, bar: 'w-[65%]' },
                    { ip: '112.54.22.1', count: 320, bar: 'w-[30%]' },
                  ].map((atk, idx) => (
                    <div key={idx}>
                      <div className="flex justify-between text-xs mb-1.5">
                        <span className="font-mono text-[#9ca3af]">{atk.ip}</span>
                        <span className="text-[#ff3b3b] font-semibold">{atk.count} evts</span>
                      </div>
                      <div className="w-full bg-[#0f1117] rounded-full h-1.5">
                        <div className={`bg-gradient-to-r from-[#ff3b3b]/50 to-[#ff3b3b] h-1.5 rounded-full ${atk.bar}`}></div>
                      </div>
                    </div>
                  ))}
                </div>
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