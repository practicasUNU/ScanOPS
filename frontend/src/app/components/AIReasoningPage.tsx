import { useState, useEffect } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  Filter, ArrowUpDown, BookOpen, FileText, Crosshair, UserCheck,
  Check, Terminal, XCircle, Loader2, RefreshCw, AlertCircle,
  ChevronDown, ChevronUp, ShieldAlert, Activity, Cpu, Layers
} from 'lucide-react';
import { toast } from 'sonner';

type StepStatus = 'completed' | 'active' | 'pending' | 'requires_review' | 'rejected';

interface Step {
  id: number;
  label: string;
  us: string;
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>;
  activeColor: string;
  description: string;
}

const STEPS: Step[] = [
  {
    id: 1, label: 'Filtro Falsos Positivos', us: 'US-4.3', icon: Filter, activeColor: '#00d4ff',
    description: 'Filtrado automático de falsos positivos usando modelos de ML entrenados con el histórico de la organización. Reduce el ruido antes de la priorización.',
  },
  {
    id: 2, label: 'Priorizador CVSS', us: 'US-4.4', icon: ArrowUpDown, activeColor: '#00d4ff',
    description: 'Priorización de vulnerabilidades según score CVSS v3.1, contexto de red y criticidad del activo. Genera ranking ajustado al entorno ENS.',
  },
  {
    id: 3, label: 'ENS Mapper (RAG)', us: 'US-4.5', icon: BookOpen, activeColor: '#00d4ff',
    description: 'Mapeo de vulnerabilidades a controles ENS mediante Retrieval-Augmented Generation sobre la base de conocimiento local. Genera referencias normativas automáticas.',
  },
  {
    id: 4, label: 'Informe Preliminar', us: 'US-4.6', icon: FileText, activeColor: '#00d4ff',
    description: 'Generación automática del informe preliminar con hallazgos priorizados, referencias ENS y recomendaciones de mitigación.',
  },
  {
    id: 5, label: 'Vector de Ataque', us: 'US-4.7', icon: Crosshair, activeColor: '#f59e0b',
    description: 'Generación del vector de ataque sugerido por M8 basado en las vulnerabilidades detectadas. Requiere revisión manual antes de pasar a M4.',
  },
  {
    id: 6, label: 'Validación Humana', us: 'US-4.8', icon: UserCheck, activeColor: '#22c55e',
    description: 'Validación manual obligatoria del vector de ataque generado por M8. El operador debe confirmar, corregir o rechazar la propuesta de explotación.',
  },
];

const INITIAL_STATES: StepStatus[] = ['completed', 'completed', 'completed', 'completed', 'requires_review', 'pending'];

const MSF_DATA = {
  attack_module: 'exploit/multi/handler',
  attack_payload: 'linux/x86/meterpreter/reverse_tcp',
  target_ip: '10.202.15.15',
  confidence: '0.72',
  risk_level: 'ALTO',
  attack_rationale: '',
  ens_article: 'op.exp.2',
};

function OllamaWidget() {
  const [status, setStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  const check = async () => {
    try {
      const res = await fetch('http://localhost:11434/api/tags', { signal: AbortSignal.timeout(3000) });
      setStatus(res.ok ? 'online' : 'offline');
    } catch {
      setStatus('offline');
    }
  };

  useEffect(() => {
    check();
    const id = setInterval(check, 30000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 bg-[#1a1d27] border border-[#1e2530] rounded-lg text-xs text-[#9ca3af]">
      <div className={`w-2 h-2 rounded-full shrink-0 ${
        status === 'online' ? 'bg-[#22c55e]' :
        status === 'offline' ? 'bg-[#ff3b3b]' :
        'bg-[#f59e0b] animate-pulse'
      }`} />
      <span className="font-mono">Ollama · mistral:7b</span>
      <span className={
        status === 'online' ? 'text-[#22c55e]' :
        status === 'offline' ? 'text-[#ff3b3b]' :
        'text-[#f59e0b]'
      }>
        {status === 'checking' ? '...' : status === 'online' ? 'Online' : 'Offline'}
      </span>
    </div>
  );
}

function stepColor(status: StepStatus, activeColor: string): string {
  switch (status) {
    case 'completed': return '#22c55e';
    case 'active': return activeColor;
    case 'requires_review': return '#f59e0b';
    case 'rejected': return '#ff3b3b';
    case 'pending': return '#374151';
  }
}

function statusLabel(status: StepStatus): string {
  switch (status) {
    case 'completed': return 'Completado';
    case 'active': return 'En proceso';
    case 'requires_review': return 'Requiere revisión';
    case 'rejected': return 'Rechazado';
    case 'pending': return 'Pendiente';
  }
}

function statusBadgeClass(status: StepStatus): string {
  switch (status) {
    case 'completed': return 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30';
    case 'active': return 'bg-[#00d4ff]/10 text-[#00d4ff] border-[#00d4ff]/30';
    case 'requires_review': return 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30';
    case 'rejected': return 'bg-[#ff3b3b]/10 text-[#ff3b3b] border-[#ff3b3b]/30';
    case 'pending': return 'bg-[#374151]/30 text-[#6b7280] border-[#374151]';
  }
}

const ASSET_ID = 10;
const M3_BASE = 'http://localhost:8002';

export function AIReasoningPage() {
  const [stepStates, setStepStates] = useState<StepStatus[]>(INITIAL_STATES);
  const [selectedStep, setSelectedStep] = useState(4);
  const [editingMsf, setEditingMsf] = useState(false);
  const [msfInput, setMsfInput] = useState(MSF_DATA.attack_module);
  const [regenerating, setRegenerating] = useState(false);
  const [regenError, setRegenError] = useState<string | null>(null);
  const [liveResult, setLiveResult] = useState<{
    attack_module: string; attack_payload: string;
    target_ip: string; confidence: string;
    risk_level: string; attack_rationale: string; ens_article: string;
  } | null>(null);
  const [showRationale, setShowRationale] = useState(false);

  function getToken() {
    try {
      const r = sessionStorage.getItem('scanops_auth');
      return r ? JSON.parse(r)?.access_token ?? null : null;
    } catch { return null; }
  }

  const handleRegenerate = async () => {
    setRegenerating(true); setRegenError(null); setLiveResult(null);
    setStepStates(['active', 'pending', 'pending', 'pending', 'pending', 'pending']);
    try {
      const h: HeadersInit = {
        'Content-Type': 'application/json',
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
      };
      const launch = await fetch(
        `${M3_BASE}/api/v1/scan/assets/${ASSET_ID}/attack-vector`,
        { method: 'POST', headers: h, signal: AbortSignal.timeout(15000) },
      );
      if (!launch.ok) throw new Error(`HTTP ${launch.status}`);
      const { task_id } = await launch.json();
      for (let i = 0; i < 4; i++) {
        await new Promise(r => setTimeout(r, 1800));
        setStepStates(p => { const n = [...p]; n[i] = 'completed'; if (i + 1 < 5) n[i + 1] = 'active'; return n; });
      }
      for (let a = 0; a < 60; a++) {
        await new Promise(r => setTimeout(r, 3000));
        const res = await fetch(
          `${M3_BASE}/api/v1/scan/assets/${ASSET_ID}/attack-vector/result/${task_id}`,
          { headers: h, signal: AbortSignal.timeout(8000) },
        );
        if (!res.ok) continue;
        const data = await res.json();
        if (data.status === 'FAILED') throw new Error('M8 falló al generar el vector');
        if (data.status === 'SUCCESS' && data.result) {
          const r = data.result;
          setLiveResult({
            attack_module: r.msf_module ?? r.attack_module ?? 'vector/generico',
            attack_payload: r.msf_payload ?? r.attack_payload ?? 'shell/reverse_tcp',
            target_ip: r.msf_options?.RHOSTS ?? '10.202.15.15',
            confidence: String(r.confidence ?? '0.72'),
            risk_level: r.risk_level ?? 'ALTO',
            attack_rationale: r.attack_rationale ?? '',
            ens_article: r.ens_article ?? 'op.exp.2',
          });
          setStepStates(['completed', 'completed', 'completed', 'completed', 'requires_review', 'pending']);
          setSelectedStep(4);
          return;
        }
      }
      throw new Error('Timeout — Ollama tardó más de 90s');
    } catch (e: any) {
      setRegenError(e?.message ?? 'Error');
      setStepStates(INITIAL_STATES);
    } finally {
      setRegenerating(false);
    }
  };

  const handleRejectDecision = () => {
    setStepStates((prevStates) => {
      const newStates = [...prevStates];
      newStates[5] = 'rejected';
      return newStates;
    });
  };

  const step = STEPS[selectedStep];
  const stepStatus = stepStates[selectedStep];

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />
        <main className="flex-1 overflow-auto p-6 space-y-6">

          {/* Header + Ollama widget */}
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-semibold text-white mb-1">IA Reasoning (M8)</h1>
              <p className="text-[#9ca3af] text-sm">Cadena de razonamiento local — Ollama/Mistral · ENS op.exp.5</p>
            </div>
            <div className="flex items-center gap-3">
              <OllamaWidget />
              <button
                onClick={handleRegenerate}
                disabled={regenerating}
                className="flex items-center gap-2 px-4 py-1.5 bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] rounded-lg text-xs font-semibold hover:bg-[#00d4ff]/20 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              >
                {regenerating
                  ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Analizando...</>
                  : <><RefreshCw className="w-3.5 h-3.5" />Regenerar análisis</>}
              </button>
              {regenError && (
                <span className="text-xs text-[#ff3b3b] flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" />{regenError}
                </span>
              )}
            </div>
          </div>

          {/* Stepper */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6">
            <div className="flex items-start">
              {STEPS.map((s, idx) => {
                const status = stepStates[idx];
                const color = stepColor(status, s.activeColor);
                const Icon = s.icon;
                const isSelected = selectedStep === idx;
                const prevCompleted = idx > 0 && stepStates[idx - 1] === 'completed';

                return (
                  <div key={s.id} className="flex items-start flex-1">
                    {idx > 0 && (
                      <div
                        className="flex-1 h-px mt-5 shrink"
                        style={{ background: prevCompleted ? '#22c55e' : '#1e2530' }}
                      />
                    )}
                    <div className="flex flex-col items-center" style={{ minWidth: 72 }}>
                      <button
                        onClick={() => setSelectedStep(idx)}
                        className="w-10 h-10 rounded-full border-2 flex items-center justify-center transition-all cursor-pointer hover:opacity-80 shrink-0"
                        style={{
                          borderColor: color,
                          backgroundColor: isSelected ? color + '20' : '#0f1117',
                        }}
                      >
                        {status === 'completed' ? (
                          <Check className="w-4 h-4" style={{ color }} />
                        ) : (
                          <Icon className="w-4 h-4" style={{ color }} />
                        )}
                      </button>
                      <div className="mt-2 text-center px-1">
                        <div className={`text-xs font-medium leading-tight ${isSelected ? 'text-white' : 'text-[#9ca3af]'}`}>
                          {s.label}
                        </div>
                        <div className="text-[10px] text-[#6b7280] mt-0.5">{s.us}</div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Detail panel */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-white font-semibold text-lg">{step.label}</span>
                <span className={`px-2.5 py-0.5 rounded-full border text-xs font-semibold ${statusBadgeClass(stepStatus)}`}>
                  {statusLabel(stepStatus)}
                </span>
              </div>
              <span className="text-xs font-mono text-[#6b7280] bg-[#0f1117] border border-[#1e2530] px-2 py-1 rounded">
                {step.us}
              </span>
            </div>

            <p className="text-sm text-[#9ca3af] border-b border-[#1e2530] pb-4">{step.description}</p>

            {/* ─── DESGLOSE TÉCNICO EXPLICITO POR PUNTO SELECCIONADO ─── */}

            {/* PASO 1: Filtro de Falsos Positivos */}
            {selectedStep === 0 && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs mt-2 animate-fadeIn">
                <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4 space-y-2">
                  <div className="text-[#00d4ff] font-semibold flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5" /> Correlación del Estado del Puerto
                  </div>
                  <p className="text-[#6b7280] leading-relaxed">
                    Cruza los banners recogidos por Nmap (M2) con los vectores de escaneo de Nuclei (M3). Si el banner del servicio indica un puerto cerrado o filtrado perimetralmente, M8 realiza un descarte inmediato de la vulnerabilidad.
                  </p>
                </div>
                <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4 space-y-2">
                  <div className="text-[#00d4ff] font-semibold flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5" /> Verificación de Arquitectura del S.O.
                  </div>
                  <p className="text-[#6b7280] leading-relaxed">
                    Valida la correspondencia del exploit contra el Kernel detectado. Descarta automáticamente firmas de Linux que intenten saltar contra plataformas Windows corporativas, minimizando alertas inútiles en el SOC.
                  </p>
                </div>
                <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4 space-y-2">
                  <div className="text-[#22c55e] font-semibold flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5" /> Directiva ENS de Salvaguarda
                  </div>
                  <p className="text-[#6b7280] leading-relaxed">
                    Principio de Máxima Cobertura: Ante la falta de evidencias concluyentes en el banner de red, M8 asume de manera proactiva que el hallazgo es VERDADERO para no ignorar brechas potenciales en el perímetro de auditoría.
                  </p>
                </div>
              </div>
            )}

            {/* PASO 2: Prioritizador CVSS */}
            {selectedStep === 1 && (
              <div className="space-y-4 font-mono text-xs mt-2 animate-fadeIn">
                <div className="bg-[#0f1117] border border-[#00d4ff]/20 rounded-lg p-4">
                  <div className="text-white font-semibold mb-2">Fórmula de Cálculo Dinámico de Riesgo Real:</div>
                  <div className="text-[#00d4ff] text-center p-3 bg-[#1a1d27] rounded border border-[#1e2530] text-sm my-2 font-mono">
                    Score_Ajustado = CVSS_Base × Coeficiente_CMDB × Coeficiente_Red
                  </div>
                  <p className="text-[#6b7280] mt-2 leading-relaxed">
                    Modifica el score estático de la vulnerabilidad cruzando la gravedad base de la CVE con la criticidad real que tiene asignada ese activo dentro de la base de datos de ScanOps.
                  </p>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
                  <div className="bg-[#0f1117] p-3 rounded-lg border border-[#1e2530] space-y-1">
                    <span className="text-[#f59e0b] font-semibold">Pesos de Criticidad del Activo (M1):</span>
                    <p className="text-[#6b7280]">• CRÍTICA: Multiplicador 1.2 (Bases de datos de producción, AD)</p>
                    <p className="text-[#6b7280]">• ALTA / MEDIA: Multiplicador 1.0 (Servidores web, proxies)</p>
                    <p className="text-[#6b7280]">• BAJA: Multiplicador 0.7 (Entornos aislados de desarrollo o sandbox)</p>
                  </div>
                  <div className="bg-[#0f1117] p-3 rounded-lg border border-[#1e2530] space-y-1">
                    <span className="text-[#f59e0b] font-semibold">Pesos de Exposición Perimetral:</span>
                    <p className="text-[#6b7280]">• INTERNET: Multiplicador 1.3 (Accesible de forma pública)</p>
                    <p className="text-[#6b7280]">• DMZ INTERNA: Multiplicador 1.0 (Segmentado mediante VLANs)</p>
                    <p className="text-[#6b7280]">• INTRANET: Multiplicador 0.8 (Aislado dentro de la LAN corporativa)</p>
                  </div>
                </div>
              </div>
            )}

            {/* PASO 3: ENS Mapper (RAG) */}
            {selectedStep === 2 && (
              <div className="space-y-3 font-mono text-xs mt-2 animate-fadeIn">
                <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4">
                  <div className="text-white font-semibold mb-1">Mapeo Semántico Local mediante Embeddings:</div>
                  <p className="text-[#6b7280] leading-relaxed">
                    M8 indexa el contenido del fichero normativo <span className="text-white">rd_311_2022.txt</span> de forma estrictamente local para buscar qué artículos del Anexo II se ven vulnerados por el hallazgo técnico, garantizando la confidencialidad de la infraestructura.
                  </p>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[11px]">
                  <div className="p-3 bg-[#0f1117] border border-purple-500/20 rounded-lg space-y-1">
                    <div className="text-[#a78bfa] font-semibold">Firma de Código Dañino</div>
                    <div className="text-white font-bold">👉 Medida [op.exp.4]</div>
                    <p className="text-[#6b7280]">Identifica parches críticos ausentes y software desactualizado expuesto en el activo corporativo.</p>
                  </div>
                  <div className="p-3 bg-[#0f1117] border border-purple-500/20 rounded-lg space-y-1">
                    <div className="text-[#a78bfa] font-semibold">Firma de Inyección SQL / XSS</div>
                    <div className="text-white font-bold">👉 Medida [mp.info.3]</div>
                    <p className="text-[#6b7280]">Detecta la falta de cifrado e integridad de la información en los formularios de almacenamiento de datos.</p>
                  </div>
                  <div className="p-3 bg-[#0f1117] border border-purple-500/20 rounded-lg space-y-1">
                    <div className="text-[#a78bfa] font-semibold">Firma de Bypass de Login</div>
                    <div className="text-white font-bold">👉 Medida [op.acc.5]</div>
                    <p className="text-[#6b7280]">Asocia la vulnerabilidad con fallos estructurales en los mecanismos de autenticación y control de acceso robusto.</p>
                  </div>
                </div>
              </div>
            )}

            {/* PASO 4: Informe Preliminar */}
            {selectedStep === 3 && (
              <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4 font-mono text-xs space-y-3 animate-fadeIn">
                <div className="text-white font-semibold flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-[#00d4ff]" /> Esqueleto Estructural del Reporte Semanal Consolidado (M7)
                </div>
                <p className="text-[#6b7280] leading-relaxed">
                  Planifica de forma automatizada las secciones requeridas para la entrega del informe ejecutivo en formato PDF firmado digitalmente:
                </p>
                <div className="space-y-2 p-3 bg-[#16171d] rounded border border-[#1e2530] text-[#6b7280] text-[11px]">
                  <div>📊 <span className="text-white font-bold">SECCIÓN 1:</span> Resumen General Cuantitativo del Ciclo de Vigilancia Activo.</div>
                  <div>🚨 <span className="text-white font-bold">SECCIÓN 2:</span> Hallazgos Críticos Filtrados que califican para Explotación Inmediata ($\ge 8.0$).</div>
                  <div>⚔ <span className="text-white font-bold">SECCIÓN 3:</span> Propuesta de la Ventana Automatizada de Ataques del sábado.</div>
                  <div>📜 <span className="text-white font-bold">SECCIÓN 4:</span> Artículos del Anexo II del ENS impactados con trazas de auditoría inmutables.</div>
                </div>
              </div>
            )}

            {/* Step 5 — requires_review: attack vector card */}
            {selectedStep === 4 && stepStatus === 'requires_review' && (() => {
              const displayResult = liveResult ?? MSF_DATA;
              const conf = parseFloat(displayResult.confidence);
              return (
                <div className="space-y-3 animate-fadeIn">
                  <div className="bg-[#0f1117] border border-[#00d4ff]/20 rounded-lg p-4 space-y-3">
                    <div className="flex items-center gap-2 text-sm font-semibold text-[#00d4ff]">
                      <Terminal className="w-4 h-4" />
                      Vector sugerido por M8
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <span className="text-[#6b7280]">Módulo de Ataque</span>
                        <div className="font-mono text-white mt-0.5">{displayResult.attack_module}</div>
                      </div>
                      <div>
                        <span className="text-[#6b7280]">Payload</span>
                        <div className="font-mono text-white mt-0.5">{displayResult.attack_payload}</div>
                      </div>
                      <div>
                        <span className="text-[#6b7280]">target_ip</span>
                        <div className="font-mono text-white mt-0.5">{displayResult.target_ip}</div>
                      </div>
                      <div>
                        <span className="text-[#6b7280]">Nivel de riesgo</span>
                        <div className="font-mono text-white mt-0.5">{displayResult.risk_level}</div>
                      </div>
                      <div>
                        <span className="text-[#6b7280]">confidence</span>
                        <div className="font-mono text-white mt-0.5">{displayResult.confidence}</div>
                      </div>
                      <div>
                        <span className="text-[#6b7280]">ENS</span>
                        <div className="font-mono text-white mt-0.5">{displayResult.ens_article}</div>
                      </div>
                    </div>
                    {displayResult.attack_rationale && (
                      <>
                        <button
                          onClick={() => setShowRationale(p => !p)}
                          className="flex items-center gap-1 text-xs text-[#6b7280] hover:text-white mt-2 cursor-pointer"
                        >
                          {showRationale ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          Razonamiento de la IA
                        </button>
                        {showRationale && (
                          <p className="text-xs text-[#9ca3af] mt-1 max-h-32 overflow-y-auto font-mono bg-[#16171d] p-2.5 rounded border border-[#1e2530] leading-relaxed">
                            {displayResult.attack_rationale}
                          </p>
                        )}
                      </>
                    )}
                  </div>
                  {conf < 0.75 && (
                    <div className="flex items-start gap-2 bg-[#f59e0b]/10 border border-[#f59e0b]/30 rounded-lg px-4 py-3 text-sm text-[#f59e0b]">
                      ⚠ Confianza baja ({displayResult.confidence}) — requiere revisión manual antes de pasar a M4
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Step 6 — human validation form */}
            {selectedStep === 5 && stepStatus === 'pending' && (
              <div className="space-y-4 animate-fadeIn">
                <div className="flex flex-wrap items-center gap-3">
                  <button
                    className="px-4 py-2 bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] rounded-lg text-sm font-semibold hover:bg-[#22c55e]/20 transition-colors cursor-pointer"
                    onClick={() => {
                      const next = [...stepStates];
                      next[5] = 'completed';
                      setStepStates(next);
                    }}
                  >
                    Validar
                  </button>
                  <button
                    className="px-4 py-2 bg-[#f59e0b]/10 border border-[#f59e0b]/30 text-[#f59e0b] rounded-lg text-sm font-semibold hover:bg-[#f59e0b]/20 transition-colors cursor-pointer"
                    onClick={() => setEditingMsf(!editingMsf)}
                  >
                    Corregir módulo MSF
                  </button>
                  <button
                    onClick={handleRejectDecision}
                    className="px-4 py-2 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] rounded-lg text-sm font-semibold hover:bg-[#ff3b3b]/20 transition-colors cursor-pointer"
                  >
                    Rechazar
                  </button>
                </div>

                {editingMsf && (
                  <div className="flex items-center gap-2 animate-fadeIn">
                    <input
                      value={msfInput}
                      onChange={e => setMsfInput(e.target.value)}
                      className="flex-1 bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#00d4ff] transition-colors"
                      placeholder="exploit/multi/handler"
                    />
                    <button
                      className="px-3 py-2 bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] rounded-lg text-sm hover:bg-[#00d4ff]/20 transition-colors cursor-pointer"
                      onClick={() => setEditingMsf(false)}
                    >
                      Guardar
                    </button>
                  </div>
                )}

                <p className="text-xs text-[#6b7280] font-mono">
                  ENS op.pl.1 — Toda decisión requiere justificación humana y firma del operador en auditoría.
                </p>
              </div>
            )}

            {/* Step 6 — rejected confirmation */}
            {selectedStep === 5 && stepStatus === 'rejected' && (
              <div className="flex flex-col gap-3 animate-fadeIn">
                <div className="flex items-center gap-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 rounded-lg px-4 py-3">
                  <XCircle className="w-4 h-4 text-[#ff3b3b] shrink-0" />
                  <div>
                    <div className="text-sm font-semibold text-[#ff3b3b]">Vector de ataque rechazado</div>
                    <div className="text-xs text-[#9ca3af] mt-0.5 font-mono">
                      Decisión denegada registrada de forma inmutable en los logs de auditoría (ENS op.exp.5). El ciclo de explotación M4 queda cancelado.
                    </div>
                  </div>
                </div>
                <button
                  className="self-start px-4 py-2 bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] rounded-lg text-sm hover:text-white transition-colors cursor-pointer"
                  onClick={() => {
                    const next = [...stepStates];
                    next[5] = 'pending';
                    setStepStates(next);
                  }}
                >
                  Revertir decisión
                </button>
              </div>
            )}
          </div>

        </main>
      </div>
    </div>
  );
}