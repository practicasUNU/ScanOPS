import { useState, useEffect } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  Filter, ArrowUpDown, BookOpen, FileText, Crosshair, UserCheck,
  Check, Terminal, XCircle,
} from 'lucide-react';
import { toast } from 'sonner';

// [1] Añadimos 'rejected' a los estados válidos de TypeScript
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
  msf_module: 'exploit/multi/handler',
  payload: 'linux/x86/meterpreter/reverse_tcp',
  target_ip: '10.202.15.15',
  port: '443',
  confidence: '0.72',
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

// [2] Mapeamos el color carmesí/rojo para el estado 'rejected'
function stepColor(status: StepStatus, activeColor: string): string {
  switch (status) {
    case 'completed': return '#22c55e';
    case 'active': return activeColor;
    case 'requires_review': return '#f59e0b';
    case 'rejected': return '#ff3b3b';
    case 'pending': return '#374151';
  }
}

// [3] Mapeamos la etiqueta para el estado 'rejected'
function statusLabel(status: StepStatus): string {
  switch (status) {
    case 'completed': return 'Completado';
    case 'active': return 'En proceso';
    case 'requires_review': return 'Requiere revisión';
    case 'rejected': return 'Rechazado';
    case 'pending': return 'Pendiente';
  }
}

// [4] Mapeamos las clases de Tailwind para el Badge de estado 'rejected'
function statusBadgeClass(status: StepStatus): string {
  switch (status) {
    case 'completed': return 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30';
    case 'active': return 'bg-[#00d4ff]/10 text-[#00d4ff] border-[#00d4ff]/30';
    case 'requires_review': return 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30';
    case 'rejected': return 'bg-[#ff3b3b]/10 text-[#ff3b3b] border-[#ff3b3b]/30';
    case 'pending': return 'bg-[#374151]/30 text-[#6b7280] border-[#374151]';
  }
}

export function AIReasoningPage() {
  const [stepStates, setStepStates] = useState<StepStatus[]>(INITIAL_STATES);
  const [selectedStep, setSelectedStep] = useState(4);
  const [editingMsf, setEditingMsf] = useState(false);
  const [msfInput, setMsfInput] = useState(MSF_DATA.msf_module);

  // [5] UBICACIÓN EXACTA: La función se declara aquí dentro para que pueda leer y escribir usando setStepStates
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
            <OllamaWidget />
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
            <div className="flex items-center gap-3">
              <span className="text-white font-semibold">{step.label}</span>
              <span className={`px-2.5 py-0.5 rounded-full border text-xs font-semibold ${statusBadgeClass(stepStatus)}`}>
                {statusLabel(stepStatus)}
              </span>
            </div>

            <p className="text-sm text-[#9ca3af]">{step.description}</p>

            {/* Step 5 — requires_review: MSF card */}
            {selectedStep === 4 && stepStatus === 'requires_review' && (
              <div className="space-y-3">
                <div className="bg-[#0f1117] border border-[#00d4ff]/20 rounded-lg p-4 space-y-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-[#00d4ff]">
                    <Terminal className="w-4 h-4" />
                    Vector sugerido por M8
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <span className="text-[#6b7280]">msf_module </span>
                      <div className="font-mono text-white mt-0.5">{MSF_DATA.msf_module}</div>
                    </div>
                    <div>
                      <span className="text-[#6b7280]">payload </span>
                      <div className="font-mono text-white mt-0.5">{MSF_DATA.payload}</div>
                    </div>
                    <div>
                      <span className="text-[#6b7280]">target_ip </span>
                      <div className="font-mono text-white mt-0.5">{MSF_DATA.target_ip}</div>
                    </div>
                    <div>
                      <span className="text-[#6b7280]">port </span>
                      <div className="font-mono text-white mt-0.5">{MSF_DATA.port}</div>
                    </div>
                    <div>
                      <span className="text-[#6b7280]">confidence </span>
                      <div className="font-mono text-white mt-0.5">{MSF_DATA.confidence}</div>
                    </div>
                  </div>
                </div>
                <div className="flex items-start gap-2 bg-[#f59e0b]/10 border border-[#f59e0b]/30 rounded-lg px-4 py-3 text-sm text-[#f59e0b]">
                  ⚠ Confianza baja (0.72) — requiere revisión manual antes de pasar a M4
                </div>
              </div>
            )}

            {/* Step 6 — human validation form */}
            {selectedStep === 5 && stepStatus === 'pending' && (
              <div className="space-y-4">
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
                  <div className="flex items-center gap-2">
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

                <p className="text-xs text-[#6b7280]">
                  ENS op.pl.1 — Toda decisión requiere justificación humana
                </p>
              </div>
            )}

            {/* Step 6 — rejected confirmation */}
            {selectedStep === 5 && stepStatus === 'rejected' && (
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 rounded-lg px-4 py-3">
                  <XCircle className="w-4 h-4 text-[#ff3b3b] shrink-0" />
                  <div>
                    <div className="text-sm font-semibold text-[#ff3b3b]">Vector rechazado</div>
                    <div className="text-xs text-[#9ca3af] mt-0.5">
                      Decisión registrada de forma inmutable en los logs de auditoría (ENS op.exp.5).
                    </div>
                  </div>
                </div>
                <button
                  className="self-start px-4 py-2 bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] rounded-lg text-sm hover:text-white transition-colors"
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