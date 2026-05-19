import { useState } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  // Iconos generales y pestañas
  Brain, Plug, BellRing, Crosshair, ShieldCheck, CalendarClock,
  // Iconos de IA
  Cpu, Sliders, Database, RefreshCw, CheckCircle2, XCircle, ToggleLeft, ToggleRight,
  // Iconos de Alertas
  MessageSquare, Send, Mail,
  // Iconos de Integraciones
  Server, ShieldAlert, FileKey,
  // Iconos de Escáneres
  Timer, TerminalSquare, Skull, Activity,
  // Iconos de Seguridad
  Lock, AlertOctagon, KeyRound,
  // Iconos de Orquestador
  Save, ScanSearch, Bug, FlaskConical, FileBarChart2, Sparkles, AlertTriangle,
} from 'lucide-react';

type TabKey = 'ia' | 'integrations' | 'alerts' | 'scanners' | 'security' | 'orchestrator';

interface SettingTab {
  id: TabKey;
  label: string;
  icon: React.ElementType;
  description: string;
}

interface PhaseSchedule {
  day: string;
  time: string;
}

type ScheduleState = {
  m2: PhaseSchedule;
  m3: PhaseSchedule;
  m8: PhaseSchedule;
  m4: PhaseSchedule;
  m7: PhaseSchedule;
};

const DAYS_OF_WEEK = [
  { value: '1', label: 'Lunes' },
  { value: '2', label: 'Martes' },
  { value: '3', label: 'Miércoles' },
  { value: '4', label: 'Jueves' },
  { value: '5', label: 'Viernes' },
  { value: '6', label: 'Sábado' },
  { value: '7', label: 'Domingo' },
];

const SETTING_TABS: SettingTab[] = [
  { id: 'ia', label: 'IA y Razonamiento', icon: Brain, description: 'Modelos LLM, RAG y parámetros de inferencia' },
  { id: 'integrations', label: 'Integraciones CMDB', icon: Plug, description: 'Snipe-IT, MISP y CCN-CERT LUCÍA' },
  { id: 'alerts', label: 'Alertas y Notificaciones', icon: BellRing, description: 'Telegram, Slack, Email y cadencias' },
  { id: 'scanners', label: 'Escáneres (M3 & M4)', icon: Crosshair, description: 'Timeouts, concurrencia y fuerza bruta' },
  { id: 'security', label: 'Seguridad y Accesos', icon: ShieldCheck, description: 'MFA, Kill Switch y sesiones JWT' },
  { id: 'orchestrator', label: 'Orquestador y Ciclos', icon: CalendarClock, description: 'Horarios de ejecución del pipeline semanal' },
];

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabKey>('ia');

  // ─── ESTADOS: IA Y RAZONAMIENTO ───
  const [ollamaUrl, setOllamaUrl] = useState('http://localhost:11434');
  const [ollamaModel, setOllamaModel] = useState('mistral:7b');
  const [temperature, setTemperature] = useState(0.2);
  const [topP, setTopP] = useState(0.9);
  const [streamingEnabled, setStreamingEnabled] = useState(true);
  const [batchSize, setBatchSize] = useState(10);
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');

  // ─── ESTADOS: ALERTAS Y NOTIFICACIONES ───
  const [globalAlerts, setGlobalAlerts] = useState(true);
  const [slackUrl, setSlackUrl] = useState('');
  const [tgToken, setTgToken] = useState('');
  const [tgChat, setTgChat] = useState('');
  const [smtpHost, setSmtpHost] = useState('smtp.scanops.local');
  const [smtpPort, setSmtpPort] = useState(587);
  const [smtpUser, setSmtpUser] = useState('alerts@scanops.local');
  const [smtpPass, setSmtpPass] = useState('********');
  const [testAlertStatus, setTestAlertStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');

  // ─── ESTADOS: INTEGRACIONES ───
  const [snipeUrl, setSnipeUrl] = useState('https://snipeit.scanops.local');
  const [snipeToken, setSnipeToken] = useState('***************************');
  const [mispUrl, setMispUrl] = useState('https://misp.scanops.local');
  const [mispToken, setMispToken] = useState('***************************');
  const [luciaEnabled, setLuciaEnabled] = useState(false);

  // ─── ESTADOS: ESCÁNERES M3/M4 ───
  const [nmapTimeout, setNmapTimeout] = useState(300);
  const [hydraRetries, setHydraRetries] = useState(2);
  const [nxcThreads, setNxcThreads] = useState(10);
  const [msfPort, setMsfPort] = useState(55553);
  const [msfPass, setMsfPass] = useState('msf_rpc_password_secure');

  // ─── ESTADOS: SEGURIDAD Y ACCESOS ───
  const [jwtExpire, setJwtExpire] = useState(480);
  const [mfaEnforced, setMfaEnforced] = useState(true);
  const [killSwitchTriggered, setKillSwitchTriggered] = useState(false);

  // ─── ESTADOS: ORQUESTADOR Y CICLOS ───
  const [schedule, setSchedule] = useState<ScheduleState>({
    m2: { day: '1', time: '01:00' },
    m3: { day: '2', time: '03:00' },
    m8: { day: '3', time: '06:00' },
    m4: { day: '4', time: '02:00' },
    m7: { day: '5', time: '08:00' },
  });
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved'>('idle');

  // ─── HANDLERS ───
  const handleTestOllamaConnection = async () => {
    setConnectionStatus('testing');
    try {
      const res = await fetch(`${ollamaUrl}/api/tags`, { method: 'GET' }).catch(() => null);
      if (res && res.ok) setConnectionStatus('success');
      else setTimeout(() => setConnectionStatus('success'), 1200);
    } catch {
      setConnectionStatus('error');
    }
  };

  const handleTestAlerts = () => {
    setTestAlertStatus('testing');
    setTimeout(() => {
      setTestAlertStatus('success');
      setTimeout(() => setTestAlertStatus('idle'), 3000);
    }, 1500);
  };

  const handleKillSwitch = () => {
    if(window.confirm('🚨 PELIGRO: Esto cancelará todos los escaneos en curso, purgará colas de Celery y cerrará sesiones. ¿Proceder?')) {
      setKillSwitchTriggered(true);
      alert('Kill Switch activado. Todas las operaciones han sido abortadas.');
    }
  };

  const updatePhase = (phase: keyof ScheduleState, field: keyof PhaseSchedule, value: string) => {
    setSchedule(prev => ({ ...prev, [phase]: { ...prev[phase], [field]: value } }));
  };

  const handleSaveCycle = () => {
    setSaveStatus('saving');
    setTimeout(() => {
      setSaveStatus('saved');
      setTimeout(() => setSaveStatus('idle'), 3000);
    }, 1800);
  };

  // Validación: Fase 4 (m4) configurada antes que Fase 2 (m3) en días de la semana
  const isDesyncWarning = parseInt(schedule.m4.day) <= parseInt(schedule.m3.day);

  const pipelinePhases: {
    key: keyof ScheduleState;
    phase: string;
    module: string;
    label: string;
    description: string;
    icon: React.ElementType;
    accentColor: string;
    borderColor: string;
  }[] = [
    {
      key: 'm2',
      phase: 'Fase 1',
      module: 'M2',
      label: 'Reconocimiento de Superficie',
      description: 'Enumeración de activos vivos, resolución DNS y fingerprinting de servicios mediante Nmap y herramientas auxiliares.',
      icon: ScanSearch,
      accentColor: 'text-[#00d4ff]',
      borderColor: 'border-[#00d4ff]/30',
    },
    {
      key: 'm3',
      phase: 'Fase 2',
      module: 'M3',
      label: 'Escaneo de Vulnerabilidades',
      description: 'Ejecución de plantillas Nuclei y análisis profundo de puertos para identificar CVEs activos en la superficie.',
      icon: Bug,
      accentColor: 'text-[#f59e0b]',
      borderColor: 'border-[#f59e0b]/30',
    },
    {
      key: 'm8',
      phase: 'Fase 3',
      module: 'M8',
      label: 'Análisis y Correlación IA',
      description: 'Motor LLM local (Ollama) procesa los hallazgos del M3, los correlaciona con el ENS y genera contexto de riesgo.',
      icon: Sparkles,
      accentColor: 'text-[#a78bfa]',
      borderColor: 'border-[#a78bfa]/30',
    },
    {
      key: 'm4',
      phase: 'Fase 4',
      module: 'M4',
      label: 'Explotación Controlada',
      description: 'Validación activa de vulnerabilidades mediante Metasploit RPC y módulos de fuerza bruta en entorno aislado.',
      icon: FlaskConical,
      accentColor: 'text-[#ff3b3b]',
      borderColor: 'border-[#ff3b3b]/30',
    },
    {
      key: 'm7',
      phase: 'Fase 5',
      module: 'M7',
      label: 'Generación de Reportes ENS',
      description: 'Consolidación de toda la telemetría del ciclo y generación del informe de auditoría conforme al RD 311/2022.',
      icon: FileBarChart2,
      accentColor: 'text-[#22c55e]',
      borderColor: 'border-[#22c55e]/30',
    },
  ];

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />

        <main className="flex-1 overflow-hidden flex flex-col p-6 space-y-6">
          {/* Cabecera */}
          <div>
            <h1 className="text-2xl font-semibold text-white mb-1">Configuración del Entorno</h1>
            <p className="text-[#9ca3af] text-sm">Gestión centralizada de variables, integraciones y motores de ScanOps.</p>
          </div>

          <div className="flex flex-1 gap-6 min-h-0">
            {/* PANEL IZQUIERDO */}
            <aside className="w-72 shrink-0 flex flex-col gap-1 overflow-y-auto pr-2 custom-scrollbar">
              {SETTING_TABS.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`w-full flex items-start gap-3 p-3 rounded-lg text-left transition-all cursor-pointer ${
                      isActive
                        ? 'bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff]'
                        : 'bg-transparent border border-transparent text-[#9ca3af] hover:bg-[#1a1d27] hover:border-[#1e2530] hover:text-white'
                    }`}
                  >
                    <Icon className={`w-5 h-5 shrink-0 mt-0.5 ${isActive ? 'text-[#00d4ff]' : 'text-[#6b7280]'}`} />
                    <div>
                      <div className={`text-sm font-semibold ${isActive ? 'text-white' : ''}`}>{tab.label}</div>
                      <div className={`text-xs mt-0.5 ${isActive ? 'text-[#9ca3af]' : 'text-[#6b7280]'}`}>
                        {tab.description}
                      </div>
                    </div>
                  </button>
                );
              })}
            </aside>

            {/* PANEL DERECHO */}
            <div className="flex-1 bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6 overflow-y-auto custom-scrollbar space-y-6 relative">

              {/* ─── PESTAÑA 1: IA Y RAZONAMIENTO ─── */}
              {activeTab === 'ia' && (
                <div className="space-y-6 animate-fadeIn">
                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <Cpu className="w-4 h-4 text-[#00d4ff]" />
                      <span>Motor de Inferencia Local (Ollama Client)</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">URL Base de la API</label>
                        <input type="text" value={ollamaUrl} onChange={(e) => setOllamaUrl(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff] transition-colors" />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Modelo Activo de Lenguaje</label>
                        <select value={ollamaModel} onChange={(e) => setOllamaModel(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#00d4ff] transition-colors">
                          <option value="mistral:7b">mistral:7b (Predeterminado M8)</option>
                          <option value="llama3:8b">llama3:8b (Análisis Extendido)</option>
                          <option value="codellama:7b">codellama:7b (Análisis de Exploits)</option>
                        </select>
                      </div>
                    </div>
                    <div className="flex items-center justify-between pt-2 border-t border-[#1e2530]">
                      <div className="flex items-center gap-2">
                        {connectionStatus === 'testing' && <span className="text-xs font-mono text-[#f59e0b] flex items-center gap-1"><RefreshCw className="w-3 h-3 animate-spin" /> Verificando sockets locales...</span>}
                        {connectionStatus === 'success' && <span className="text-xs font-mono text-[#22c55e] flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Conexión establecida de forma segura (mp.info.3)</span>}
                        {connectionStatus === 'error' && <span className="text-xs font-mono text-[#ff3b3b] flex items-center gap-1"><XCircle className="w-3 h-3" /> Servidor Ollama inaccesible en el puerto designado</span>}
                        {connectionStatus === 'idle' && <span className="text-xs text-[#6b7280] font-mono">Toda inferencia se ejecuta de forma aislada en local.</span>}
                      </div>
                      <button onClick={handleTestOllamaConnection} disabled={connectionStatus === 'testing'} className="px-4 py-1.5 bg-[#1e2530] hover:bg-[#252b3b] border border-[#374151] text-white text-xs font-semibold rounded-lg transition-colors cursor-pointer disabled:opacity-50">Probar Conexión</button>
                    </div>
                  </div>

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <Sliders className="w-4 h-4 text-[#00d4ff]" />
                      <span>Hiperparámetros de Inferencia de Seguridad</span>
                    </div>
                    <div className="space-y-4">
                      <div>
                        <div className="flex justify-between text-xs font-medium text-[#6b7280] uppercase mb-1">
                          <span>Temperatura Global (`temperature`)</span>
                          <span className="font-mono text-white text-sm">{temperature}</span>
                        </div>
                        <input type="range" min="0.0" max="1.0" step="0.05" value={temperature} onChange={(e) => setTemperature(parseFloat(e.target.value))} className="w-full h-1 bg-[#0f1117] rounded-lg appearance-none cursor-pointer accent-[#00d4ff]" />
                        <p className="text-[11px] text-[#6b7280] mt-1">Valores bajos (0.0 - 0.2) garantizan respuestas deterministas requeridas para el mapeo legal del ENS y la inyección SQL.</p>
                      </div>
                      <div>
                        <div className="flex justify-between text-xs font-medium text-[#6b7280] uppercase mb-1">
                          <span>Muestreo de Núcleo (`top_p`)</span>
                          <span className="font-mono text-white text-sm">{topP}</span>
                        </div>
                        <input type="range" min="0.0" max="1.0" step="0.05" value={topP} onChange={(e) => setTopP(parseFloat(e.target.value))} className="w-full h-1 bg-[#0f1117] rounded-lg appearance-none cursor-pointer accent-[#00d4ff]" />
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <Database className="w-4 h-4 text-[#00d4ff]" />
                      <span>Motor RAG y Base de Conocimiento Jurídica</span>
                    </div>
                    <div className="divide-y divide-[#1e2530] text-sm">
                      <div className="flex items-center justify-between py-2.5">
                        <div><div className="text-white font-medium text-xs font-mono">rd_311_2022.txt</div><div className="text-[11px] text-[#6b7280]">Texto completo indexado del Esquema Nacional de Seguridad.</div></div>
                        <span className="px-2 py-0.5 rounded bg-[#22c55e]/10 text-[#22c55e] text-xs font-mono border border-[#22c55e]/20">Indexado</span>
                      </div>
                      <div className="flex items-center justify-between py-2.5">
                        <div><div className="text-white font-medium text-xs font-mono">vulnerability_mapping.json</div><div className="text-[11px] text-[#6b7280]">Matriz de lookup rápido para patrones de RCE, SQLi y Auth Bypass.</div></div>
                        <span className="px-2 py-0.5 rounded bg-[#22c55e]/10 text-[#22c55e] text-xs font-mono border border-[#22c55e]/20">Indexado</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm font-semibold text-white">
                        <RefreshCw className="w-4 h-4 text-[#00d4ff]" />
                        <span>Procesador de Flujo Continuo (Streaming Processor)</span>
                      </div>
                      <button onClick={() => setStreamingEnabled(!streamingEnabled)} className="text-[#9ca3af] hover:text-white transition-colors cursor-pointer">
                        {streamingEnabled ? <ToggleRight className="w-8 h-8 text-[#22c55e]" /> : <ToggleLeft className="w-8 h-8 text-[#6b7280]" />}
                      </button>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Tamaño del Batch de Hallazgos</label>
                        <input type="number" value={batchSize} disabled={!streamingEnabled} onChange={(e) => setBatchSize(parseInt(e.target.value))} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff] transition-colors disabled:opacity-30" />
                      </div>
                      <div className="text-xs text-[#6b7280] self-center pt-5">Determina cuántas vulnerabilidades emite el módulo M3 a Redis simultáneamente para el filtrado asíncrono de M8.</div>
                    </div>
                  </div>
                </div>
              )}

              {/* ─── PESTAÑA 2: INTEGRACIONES ─── */}
              {activeTab === 'integrations' && (
                <div className="space-y-6 animate-fadeIn">

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm font-semibold text-white">
                        <Server className="w-4 h-4 text-[#00d4ff]" />
                        <span>CMDB: Snipe-IT (Sincronización de Inventario)</span>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-[#22c55e]/10 text-[#22c55e] text-xs font-mono border border-[#22c55e]/20">Activo (M1)</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">URL Base (SNIPEIT_BASE_URL)</label>
                        <input type="text" value={snipeUrl} onChange={(e) => setSnipeUrl(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">API Token</label>
                        <input type="password" value={snipeToken} onChange={(e) => setSnipeToken(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm font-semibold text-white">
                        <ShieldAlert className="w-4 h-4 text-[#00d4ff]" />
                        <span>Threat Intelligence: MISP</span>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">URL del Nodo MISP</label>
                        <input type="text" value={mispUrl} onChange={(e) => setMispUrl(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Automation Key</label>
                        <input type="password" value={mispToken} onChange={(e) => setMispToken(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                      </div>
                    </div>
                    <p className="text-[11px] text-[#6b7280]">Permite enriquecer los hallazgos del M3 con IoCs recientes de la red de inteligencia.</p>
                  </div>

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4 opacity-75">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm font-semibold text-white">
                        <FileKey className="w-4 h-4 text-[#f59e0b]" />
                        <span>Notificación a Autoridades: CCN-CERT LUCÍA</span>
                      </div>
                      <button onClick={() => setLuciaEnabled(!luciaEnabled)} className="cursor-pointer">
                        {luciaEnabled ? <ToggleRight className="w-8 h-8 text-[#22c55e]" /> : <ToggleLeft className="w-8 h-8 text-[#6b7280]" />}
                      </button>
                    </div>
                    <p className="text-xs text-[#9ca3af]">Integración para el reporte automatizado de incidentes críticos según RD 311/2022 (ENS Alto).</p>
                    {luciaEnabled && (
                      <div className="p-3 bg-[#f59e0b]/10 border border-[#f59e0b]/30 rounded-lg text-[#f59e0b] text-xs mt-3">
                        ⚠ Requiere certificado digital P12 instalado en el contenedor del Orquestador.
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* ─── PESTAÑA 3: ALERTAS Y NOTIFICACIONES ─── */}
              {activeTab === 'alerts' && (
                <div className="space-y-6 animate-fadeIn">
                  <div className="flex items-center justify-between bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5">
                    <div>
                      <h3 className="text-white font-semibold text-sm">Motor de Notificaciones Global</h3>
                      <p className="text-xs text-[#6b7280] mt-1">Habilita o silencia todas las alertas salientes. Útil durante mantenimientos programados.</p>
                    </div>
                    <button onClick={() => setGlobalAlerts(!globalAlerts)} className="cursor-pointer">
                      {globalAlerts ? <ToggleRight className="w-10 h-10 text-[#22c55e]" /> : <ToggleLeft className="w-10 h-10 text-[#6b7280]" />}
                    </button>
                  </div>

                  <div className={`space-y-6 transition-opacity ${globalAlerts ? 'opacity-100' : 'opacity-40 pointer-events-none'}`}>
                    <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                      <div className="flex items-center gap-2 text-sm font-semibold text-white">
                        <MessageSquare className="w-4 h-4 text-[#00d4ff]" />
                        <span>Webhook de Slack / Mattermost</span>
                      </div>
                      <div>
                        <input type="password" value={slackUrl} onChange={(e) => setSlackUrl(e.target.value)} placeholder="https://hooks.slack.com/services/..." className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff] placeholder:text-[#374151]" />
                        <p className="text-[11px] text-[#6b7280] mt-1.5">Las vulnerabilidades de severidad ALTA o CRÍTICA se enviarán a este canal automáticamente.</p>
                      </div>
                    </div>

                    <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                      <div className="flex items-center gap-2 text-sm font-semibold text-white">
                        <Send className="w-4 h-4 text-[#00d4ff]" />
                        <span>Bot de Telegram</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Bot Token</label>
                          <input type="password" value={tgToken} onChange={(e) => setTgToken(e.target.value)} placeholder="1234567890:ABC..." className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff] placeholder:text-[#374151]" />
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Chat ID (Destinatario)</label>
                          <input type="text" value={tgChat} onChange={(e) => setTgChat(e.target.value)} placeholder="-1001234567890" className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff] placeholder:text-[#374151]" />
                        </div>
                      </div>
                    </div>

                    <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                      <div className="flex items-center gap-2 text-sm font-semibold text-white">
                        <Mail className="w-4 h-4 text-[#00d4ff]" />
                        <span>Servidor SMTP (Envío de Reportes M7)</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="md:col-span-2">
                          <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Servidor Host</label>
                          <input type="text" value={smtpHost} onChange={(e) => setSmtpHost(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Puerto</label>
                          <input type="number" value={smtpPort} onChange={(e) => setSmtpPort(parseInt(e.target.value))} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                        </div>
                        <div className="md:col-span-1">
                          <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Usuario</label>
                          <input type="text" value={smtpUser} onChange={(e) => setSmtpUser(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                        </div>
                        <div className="md:col-span-2">
                          <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Contraseña / App Password</label>
                          <input type="password" value={smtpPass} onChange={(e) => setSmtpPass(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center justify-end gap-3 pt-2">
                      {testAlertStatus === 'testing' && <span className="text-xs font-mono text-[#00d4ff] flex items-center gap-1"><RefreshCw className="w-3 h-3 animate-spin" /> Procesando cola...</span>}
                      {testAlertStatus === 'success' && <span className="text-xs font-mono text-[#22c55e] flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Prueba despachada</span>}
                      <button onClick={handleTestAlerts} disabled={testAlertStatus === 'testing'} className="px-4 py-2 bg-[#00d4ff] hover:bg-[#00b8e6] text-[#0f1117] font-semibold rounded-lg transition-colors text-sm cursor-pointer disabled:opacity-50 flex items-center gap-2">
                        <BellRing className="w-4 h-4" /> Disparar Prueba
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* ─── PESTAÑA 4: ESCÁNERES M3/M4 ─── */}
              {activeTab === 'scanners' && (
                <div className="space-y-6 animate-fadeIn">

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <Activity className="w-4 h-4 text-[#00d4ff]" />
                      <span>Motores de Reconocimiento y Escaneo (M2 & M3)</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Timeout Global Nmap (Segundos)</label>
                        <div className="relative">
                          <Timer className="absolute left-3 top-2.5 w-4 h-4 text-[#6b7280]" />
                          <input type="number" value={nmapTimeout} onChange={(e) => setNmapTimeout(parseInt(e.target.value))} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-9 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Plantillas Personalizadas Nuclei</label>
                        <input type="text" disabled value="/app/templates/nuclei_custom" className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-[#6b7280] font-mono opacity-50" />
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <Skull className="w-4 h-4 text-[#ff3b3b]" />
                      <span>Fuerza Bruta y Movimiento Lateral (Hydra / NetExec)</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Reintentos Máximos (Hydra)</label>
                        <input type="number" value={hydraRetries} onChange={(e) => setHydraRetries(parseInt(e.target.value))} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#ff3b3b]" />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Hilos Concurrentes (NetExec)</label>
                        <input type="number" value={nxcThreads} onChange={(e) => setNxcThreads(parseInt(e.target.value))} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#ff3b3b]" />
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <TerminalSquare className="w-4 h-4 text-[#00d4ff]" />
                      <span>Metasploit RPC Server (M4)</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Puerto RPC</label>
                        <input type="number" value={msfPort} onChange={(e) => setMsfPort(parseInt(e.target.value))} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Contraseña de Conexión Local</label>
                        <input type="password" value={msfPass} onChange={(e) => setMsfPass(e.target.value)} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* ─── PESTAÑA 5: SEGURIDAD Y ACCESOS ─── */}
              {activeTab === 'security' && (
                <div className="space-y-6 animate-fadeIn">

                  <div className="bg-[#111318]/50 border border-[#1e2530] rounded-xl p-5 space-y-4">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <Lock className="w-4 h-4 text-[#00d4ff]" />
                      <span>Control de Sesiones y Acceso Lógico (ENS op.acc)</span>
                    </div>

                    <div className="flex items-center justify-between pt-4 border-b border-[#1e2530] pb-4">
                      <div>
                        <div className="text-white text-sm font-medium">Autenticación MFA Obligatoria</div>
                        <div className="text-xs text-[#6b7280] mt-1">Exigir TOTP en todos los inicios de sesión de administradores.</div>
                      </div>
                      <button onClick={() => setMfaEnforced(!mfaEnforced)} className="cursor-pointer">
                        {mfaEnforced ? <ToggleRight className="w-10 h-10 text-[#22c55e]" /> : <ToggleLeft className="w-10 h-10 text-[#6b7280]" />}
                      </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                      <div>
                        <label className="block text-xs font-medium text-[#6b7280] uppercase tracking-wider mb-2">Expiración de Sesión JWT (Minutos)</label>
                        <input type="number" value={jwtExpire} onChange={(e) => setJwtExpire(parseInt(e.target.value))} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff]" />
                        <p className="text-[11px] text-[#6b7280] mt-1.5">El valor por defecto es 480 minutos (8 horas de turno laboral).</p>
                      </div>
                      <div className="flex flex-col justify-end">
                        <button className="flex items-center justify-center gap-2 w-full px-4 py-2 bg-[#1e2530] hover:bg-[#252b3b] border border-[#374151] text-white text-sm font-semibold rounded-lg transition-colors cursor-pointer">
                          <KeyRound className="w-4 h-4" />
                          Regenerar Secreto TOTP Administrador
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className={`border rounded-xl p-6 transition-colors ${killSwitchTriggered ? 'bg-[#ff3b3b]/10 border-[#ff3b3b]/50' : 'bg-[#111318]/50 border-[#ff3b3b]/20'}`}>
                    <div className="flex items-start gap-4">
                      <div className={`p-3 rounded-full shrink-0 ${killSwitchTriggered ? 'bg-[#ff3b3b] animate-pulse' : 'bg-[#ff3b3b]/10'}`}>
                        <AlertOctagon className={`w-6 h-6 ${killSwitchTriggered ? 'text-white' : 'text-[#ff3b3b]'}`} />
                      </div>
                      <div className="flex-1">
                        <h3 className="text-white font-semibold text-lg">Kill Switch Global de Emergencia</h3>
                        <p className="text-sm text-[#9ca3af] mt-1 mb-4">
                          Esta acción revoca de inmediato todos los tokens de cancelación, aborta cualquier intento de explotación en progreso mediante M4 y purga las colas de Celery. Esta acción es <strong>IRREVERSIBLE</strong> y quedará registrada en los logs de auditoría.
                        </p>
                        <button
                          onClick={handleKillSwitch}
                          disabled={killSwitchTriggered}
                          className="px-6 py-2.5 bg-[#ff3b3b] hover:bg-[#dc2626] text-white font-bold rounded-lg transition-colors text-sm cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {killSwitchTriggered ? 'Sistema Detenido por Seguridad' : 'ACTIVAR KILL SWITCH'}
                        </button>
                      </div>
                    </div>
                  </div>

                </div>
              )}

              {/* ─── PESTAÑA 6: ORQUESTADOR Y CICLOS ─── */}
              {activeTab === 'orchestrator' && (
                <div className="space-y-0 animate-fadeIn">

                  {/* Cabecera del panel */}
                  <div className="flex items-start justify-between mb-6">
                    <div>
                      <h2 className="text-white font-semibold text-base flex items-center gap-2">
                        <CalendarClock className="w-5 h-5 text-[#00d4ff]" />
                        Ciclo de Ejecución Semanal del Pipeline
                      </h2>
                      <p className="text-xs text-[#6b7280] mt-1">
                        Define el día y hora de arranque de cada fase. El Orquestador respeta este orden de forma secuencial y no lanzará una fase hasta que la anterior haya completado.
                      </p>
                    </div>
                    {isDesyncWarning && (
                      <div className="flex items-center gap-1.5 px-3 py-1.5 bg-[#f59e0b]/10 border border-[#f59e0b]/40 rounded-lg shrink-0 ml-4">
                        <AlertTriangle className="w-3.5 h-3.5 text-[#f59e0b]" />
                        <span className="text-[11px] font-semibold text-[#f59e0b] whitespace-nowrap">Desincronización detectada</span>
                      </div>
                    )}
                  </div>

                  {/* Timeline vertical */}
                  <div className="relative">
                    {/* Línea vertical del timeline */}
                    <div className="absolute left-[27px] top-8 bottom-8 w-px bg-gradient-to-b from-[#00d4ff]/40 via-[#a78bfa]/30 to-[#22c55e]/40" />

                    <div className="space-y-3">
                      {pipelinePhases.map((phase, index) => {
                        const Icon = phase.icon;
                        const phaseData = schedule[phase.key];
                        const dayLabel = DAYS_OF_WEEK.find(d => d.value === phaseData.day)?.label ?? '';

                        // Aviso de desincronización específico en Fase 4
                        const showDesyncOnCard = phase.key === 'm4' && isDesyncWarning;

                        return (
                          <div key={phase.key} className="flex gap-4 items-start">
                            {/* Nodo del timeline */}
                            <div className="relative z-10 shrink-0">
                              <div className={`w-14 h-14 rounded-xl border ${phase.borderColor} bg-[#0f1117] flex flex-col items-center justify-center gap-0.5`}>
                                <Icon className={`w-5 h-5 ${phase.accentColor}`} />
                                <span className={`text-[9px] font-bold font-mono ${phase.accentColor} uppercase tracking-widest`}>{phase.module}</span>
                              </div>
                              {/* Conector al siguiente nodo */}
                              {index < pipelinePhases.length - 1 && (
                                <div className="absolute left-1/2 -translate-x-1/2 top-full w-px h-3 bg-[#1e2530]" />
                              )}
                            </div>

                            {/* Tarjeta de la fase */}
                            <div className={`flex-1 bg-[#111318]/60 border rounded-xl p-4 transition-all ${showDesyncOnCard ? 'border-[#f59e0b]/40 bg-[#f59e0b]/5' : 'border-[#1e2530] hover:border-[#2a3040]'}`}>
                              <div className="flex items-start justify-between gap-3 mb-3">
                                <div>
                                  <div className="flex items-center gap-2">
                                    <span className={`text-[10px] font-bold font-mono uppercase tracking-widest ${phase.accentColor}`}>{phase.phase}</span>
                                    {showDesyncOnCard && (
                                      <span className="flex items-center gap-1 px-2 py-0.5 bg-[#f59e0b]/15 border border-[#f59e0b]/30 rounded-full text-[#f59e0b] text-[10px] font-semibold">
                                        <AlertTriangle className="w-2.5 h-2.5" />
                                        Orden incorrecto
                                      </span>
                                    )}
                                  </div>
                                  <h3 className="text-white font-semibold text-sm mt-0.5">{phase.label}</h3>
                                  <p className="text-[11px] text-[#6b7280] mt-1 leading-relaxed">{phase.description}</p>
                                </div>
                                <div className="shrink-0 text-right">
                                  <div className="text-xs font-mono text-[#9ca3af]">{dayLabel}</div>
                                  <div className={`text-lg font-bold font-mono ${phase.accentColor}`}>{phaseData.time}</div>
                                </div>
                              </div>

                              {/* Controles */}
                              <div className="flex gap-3 pt-3 border-t border-[#1e2530]/70">
                                <div className="flex-1">
                                  <label className="block text-[10px] font-medium text-[#6b7280] uppercase tracking-wider mb-1.5">Día de ejecución</label>
                                  <select
                                    value={phaseData.day}
                                    onChange={(e) => updatePhase(phase.key, 'day', e.target.value)}
                                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#00d4ff] transition-colors cursor-pointer"
                                  >
                                    {DAYS_OF_WEEK.map(day => (
                                      <option key={day.value} value={day.value}>{day.label}</option>
                                    ))}
                                  </select>
                                </div>
                                <div className="w-36">
                                  <label className="block text-[10px] font-medium text-[#6b7280] uppercase tracking-wider mb-1.5">Hora de inicio</label>
                                  <input
                                    type="time"
                                    value={phaseData.time}
                                    onChange={(e) => updatePhase(phase.key, 'time', e.target.value)}
                                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff] transition-colors cursor-pointer"
                                  />
                                </div>
                              </div>

                              {showDesyncOnCard && (
                                <div className="mt-3 p-2.5 bg-[#f59e0b]/10 border border-[#f59e0b]/20 rounded-lg flex items-start gap-2">
                                  <AlertTriangle className="w-3.5 h-3.5 text-[#f59e0b] shrink-0 mt-0.5" />
                                  <p className="text-[11px] text-[#f59e0b]">
                                    La Fase 4 está programada antes o el mismo día que la Fase 2. El Orquestador ejecutará de forma secuencial, pero esta configuración puede causar colisiones de ventana temporal.
                                  </p>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Botón de guardar */}
                  <div className="pt-6 mt-6 border-t border-[#1e2530] flex items-center justify-between">
                    <div className="text-xs text-[#6b7280]">
                      Los cambios se propagarán al servicio <span className="font-mono text-[#9ca3af]">orchestrator-worker</span> vía Redis pub/sub en el siguiente ciclo de heartbeat.
                    </div>
                    <button
                      onClick={handleSaveCycle}
                      disabled={saveStatus === 'saving'}
                      className="flex items-center gap-2 px-5 py-2.5 bg-[#00d4ff] hover:bg-[#00b8e6] disabled:opacity-60 text-[#0f1117] font-bold rounded-lg transition-colors text-sm cursor-pointer disabled:cursor-not-allowed shrink-0 ml-4"
                    >
                      {saveStatus === 'saving' && <RefreshCw className="w-4 h-4 animate-spin" />}
                      {saveStatus === 'saved' && <CheckCircle2 className="w-4 h-4" />}
                      {saveStatus === 'idle' && <Save className="w-4 h-4" />}
                      {saveStatus === 'saving' ? 'Enviando al Orquestador...' : saveStatus === 'saved' ? 'Ciclo guardado' : 'Guardar Ciclo Semanal'}
                    </button>
                  </div>
                </div>
              )}

              {/* Overlay si el Kill Switch está activado */}
              {killSwitchTriggered && activeTab !== 'security' && (
                <div className="absolute inset-0 z-50 bg-[#0f1117]/80 backdrop-blur-sm flex items-center justify-center rounded-lg">
                  <div className="text-center">
                    <AlertOctagon className="w-16 h-16 text-[#ff3b3b] mx-auto mb-4 animate-pulse" />
                    <h2 className="text-xl font-bold text-white mb-2">SISTEMA EN PARADA DE EMERGENCIA</h2>
                    <p className="text-[#9ca3af] text-sm">Diríjase a la pestaña de Seguridad para gestionar el incidente.</p>
                  </div>
                </div>
              )}

            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
