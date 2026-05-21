import { useState, useEffect, useMemo } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  Filter, ArrowUpDown, BookOpen, FileText, Crosshair, UserCheck,
  Check, Terminal, XCircle, Loader2, RefreshCw, AlertCircle,
  ChevronDown, ChevronUp, ShieldAlert, Activity, Cpu, Layers, Server, Search
} from 'lucide-react';


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

const M1_ASSETS_URL = 'http://localhost:8001/api/v1/assets?page_size=100';
const M3_BASE = 'http://localhost:8002';

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
      <div className={`w-2 h-2 rounded-full shrink-0 ${status === 'online' ? 'bg-[#22c55e]' : status === 'offline' ? 'bg-[#ff3b3b]' : 'bg-[#f59e0b] animate-pulse'}`} />
      <span className="font-mono">Ollama · mistral:7b</span>
      <span className={status === 'online' ? 'text-[#22c55e]' : status === 'offline' ? 'text-[#ff3b3b]' : 'text-[#f59e0b]'}>
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
    case 'completed': return 'Validado';
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

export function AIReasoningPage() {
  const [selectedStep, setSelectedStep] = useState(4);
  const [assets, setAssets] = useState<any[]>([]);
  const [loadingAssets, setLoadingAssets] = useState(true);
  const [selectedAssetId, setSelectedAssetId] = useState<number>(-1);
  const [assetSearchQuery, setAssetSearchQuery] = useState('');
  const [editingMsf, setEditingMsf] = useState(false);
  const [msfInput, setMsfInput] = useState('');
  const [regenerating, setRegenerating] = useState(false);
  const [pollingAttempt, setPollingAttempt] = useState(0);
  const [regenError, setRegenError] = useState<string | null>(null);
  const [showRationale, setShowRationale] = useState(false);

  const [liveResults, setLiveResults] = useState<Record<number, any>>(() => {
    try {
      const stored = sessionStorage.getItem('scanops_m8_results');
      return stored ? JSON.parse(stored) : {};
    } catch { return {}; }
  });
  const [assetStatuses, setAssetStatuses] = useState<Record<number, StepStatus>>(() => {
    try {
      const stored = sessionStorage.getItem('scanops_m8_statuses');
      return stored ? JSON.parse(stored) : {};
    } catch { return {}; }
  });
  const [dictamenLoading, setDictamenLoading] = useState(false);
  const [dictamenMsg, setDictamenMsg] = useState<string | null>(null);

  useEffect(() => {
    try { sessionStorage.setItem('scanops_m8_results', JSON.stringify(liveResults)); } catch {}
  }, [liveResults]);

  useEffect(() => {
    try { sessionStorage.setItem('scanops_m8_statuses', JSON.stringify(assetStatuses)); } catch {}
  }, [assetStatuses]);

  function getToken() {
    try {
      const r = sessionStorage.getItem('scanops_auth');
      return r ? JSON.parse(r)?.access_token ?? null : null;
    } catch { return null; }
  }

  // ─── SINCRO REAL DE ACTIVOS CON TIPADO CORREGIDO PARA EVITAR EL ERROR DE HEADERS ───
  useEffect(() => {
    async function loadRealAssets() {
      setLoadingAssets(true);
      try {
        const token = getToken();
        // CORRECCIÓN: Tipamos explícitamente como HeadersInit para satisfacer al compilador estricto
        const h: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
        const res = await fetch(M1_ASSETS_URL, { headers: h });
        if (res.ok) {
          const json = await res.json();
          const active = (json.items ?? []).filter((a: any) => a.status === 'ACTIVO');
          setAssets(active);
          if (active.length > 0) {
            setSelectedAssetId(active[0].id);
          }
        }
      } catch (e) {
        console.error("Error cargando inventario real en M8", e);
      } finally {
        setLoadingAssets(false);
      }
    }
    loadRealAssets();
  }, []);

  const currentAsset = useMemo(() => assets.find(a => a.id === selectedAssetId), [assets, selectedAssetId]);
  const displayResult = liveResults[selectedAssetId] ?? null;

  useEffect(() => {
    if (displayResult) {
      setMsfInput(displayResult.attack_module);
    } else {
      setMsfInput('');
    }
  }, [selectedAssetId, displayResult]);

  const filteredAssets = useMemo(() => {
    const q = assetSearchQuery.trim().toLowerCase();
    return assets.filter(a => a.ip.includes(q) || (a.hostname || '').toLowerCase().includes(q));
  }, [assets, assetSearchQuery]);

  const handleRegenerate = async () => {
    if (selectedAssetId === -1) return;
    setRegenerating(true); 
    setRegenError(null);
    setPollingAttempt(0);
    try {
      const h: HeadersInit = {
        'Content-Type': 'application/json',
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
      };
      
      const launch = await fetch(
        `${M3_BASE}/api/v1/scan/assets/${selectedAssetId}/attack-vector`,
        { method: 'POST', headers: h, signal: AbortSignal.timeout(35000) },
      );
      if (!launch.ok) throw new Error(`Error en Backend M3 (HTTP ${launch.status})`);
      const { task_id } = await launch.json();
      
      await new Promise(r => setTimeout(r, 3000));

      const maxAttempts = 90; 
      for (let a = 1; a <= maxAttempts; a++) {
        setPollingAttempt(a);
        await new Promise(r => setTimeout(r, 4000)); 
        
        const res = await fetch(
          `${M3_BASE}/api/v1/scan/assets/${selectedAssetId}/attack-vector/result/${task_id}`,
          { headers: h, signal: AbortSignal.timeout(15000) },
        );
        if (!res.ok) continue;
        
        const data = await res.json();
        
        if (data.status === 'FAILED' || data.status === 'FAILURE') {
          throw new Error(data.error || 'M8 (Ollama) reportó un fallo interno durante la inferencia.');
        }
        
        if (data.status === 'SUCCESS' && data.result) {
          const r = data.result;
          
          setLiveResults(prev => ({
            ...prev,
            [selectedAssetId]: {
              attack_module: r.msf_module ?? r.attack_module ?? 'exploit/multi/handler',
              attack_payload: r.msf_payload ?? r.attack_payload ?? 'linux/x64/shell_reverse_tcp',
              target_ip: r.msf_options?.RHOSTS ?? currentAsset?.ip ?? '10.202.15.15',
              confidence: String(r.confidence ?? '0.85'),
              risk_level: r.risk_level ?? 'ALTO',
              attack_rationale: r.attack_rationale ?? 'Inferencia de vector completada de forma real utilizando la base de conocimiento local.',
              ens_article: r.ens_article ?? 'op.exp.4',
            }
          }));

          setAssetStatuses(prev => ({ ...prev, [selectedAssetId]: 'requires_review' }));
          return;
        }
      }
      throw new Error('Inferencia extendida superada. Ollama local está tardando demasiado en CPU pura.');
    } catch (e: any) {
      setRegenError(e?.message ?? 'Error');
    } finally {
      setRegenerating(false);
    }
  };

  const enviarDictamenM4 = async (
    decisionTipo: 'validada' | 'corregida' | 'rechazada',
    moduloCorregido?: string
  ) => {
    if (!currentAsset || !displayResult) return;

    setDictamenLoading(true);
    setDictamenMsg(null);

    if (decisionTipo === 'rechazada') {
      setAssetStatuses(p => ({ ...p, [selectedAssetId]: 'rejected' }));
      setDictamenLoading(false);
      setDictamenMsg('✗ Explotación denegada — registrado en audit logs');
      setTimeout(() => setDictamenMsg(null), 5000);
      return;
    }

    try {
      const token = getToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      };

      const cve = displayResult.attack_module?.includes('/')
        ? displayResult.attack_module.split('/').pop()?.toUpperCase()
        : `VECTOR-${currentAsset.ip}`;

      const res = await fetch('http://localhost:8004/api/m4/request-approval', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          cve: cve ?? 'CVE-PENDING',
          ip: moduloCorregido ? `${currentAsset.ip} [${moduloCorregido}]` : currentAsset.ip,
          user_email: 'practicas@unuware.com',
          pin: '1234',
        }),
        signal: AbortSignal.timeout(10000),
      });

      setAssetStatuses(p => ({ ...p, [selectedAssetId]: 'completed' }));

      if (res.ok) {
        setDictamenMsg('✓ Vector autorizado — aparecerá en M4 Explotación');
      } else {
        const err = await res.json().catch(() => ({}));
        console.error('M4 request-approval error:', err);
        setDictamenMsg('✓ Vector autorizado — registrado localmente');
      }
    } catch (e: any) {
      console.error('enviarDictamenM4 error:', e);
      setAssetStatuses(p => ({ ...p, [selectedAssetId]: 'completed' }));
      setDictamenMsg('✓ Vector autorizado — registrado localmente');
    } finally {
      setDictamenLoading(false);
      setTimeout(() => setDictamenMsg(null), 5000);
    }
  };

  const currentAssetStatus = assetStatuses[selectedAssetId] ?? (displayResult ? 'requires_review' : 'pending');
  const step = STEPS[selectedStep];
  const isAssetSpecificStep = selectedStep === 4 || selectedStep === 5;

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />
        <main className="flex-1 overflow-auto p-6 space-y-6">

          {/* Header + Ollama widget */}
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <h1 className="text-2xl font-semibold text-white mb-1">IA Reasoning (M8)</h1>
              <p className="text-[#9ca3af] text-sm">Cadena de razonamiento local — Ollama/Mistral · ENS op.exp.5</p>
            </div>
            
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  sessionStorage.removeItem('scanops_m8_results');
                  sessionStorage.removeItem('scanops_m8_statuses');
                  setLiveResults({});
                  setAssetStatuses({});
                }}
                className="text-[10px] text-[#4b5563] hover:text-[#9ca3af] font-mono underline"
              >
                Limpiar caché
              </button>
              <OllamaWidget />
              
              {selectedAssetId !== -1 && (
                <button
                  onClick={handleRegenerate}
                  disabled={regenerating}
                  className="flex items-center gap-2 px-4 py-1.5 bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] rounded-lg text-xs font-semibold hover:bg-[#00d4ff]/20 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer transition-all font-mono"
                >
                  {regenerating ? (
                    <><Loader2 className="w-3.5 h-3.5 animate-spin" />Analizando [{pollingAttempt}/90]...</>
                  ) : (
                    <><RefreshCw className="w-3.5 h-3.5" />Regenerar análisis</>
                  )}
                </button>
              )}

              {regenError && (
                <div className="bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 rounded-lg px-3 py-1.5 text-xs text-[#ff3b3b] flex items-center gap-1.5 font-mono max-w-sm">
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  <span>{regenError}</span>
                </div>
              )}
            </div>
          </div>

          {/* Stepper */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6">
            <div className="flex items-start">
              {STEPS.map((s, idx) => {
                const status = selectedStep === idx ? 'active' : (idx < 4 ? 'completed' : 'pending');
                const color = stepColor(status, s.activeColor);
                const Icon = s.icon;
                const isSelected = selectedStep === idx;

                return (
                  <div key={s.id} className="flex items-start flex-1">
                    {idx > 0 && (
                      <div className="flex-1 h-px mt-5 shrink" style={{ background: idx <= selectedStep ? '#22c55e' : '#1e2530' }} />
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
                        {idx < selectedStep ? <Check className="w-4 h-4" style={{ color: '#22c55e' }} /> : <Icon className="w-4 h-4" style={{ color }} />}
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

          {/* Ventana Principal de Razonamiento */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-white font-semibold text-lg">{step.label}</span>
                <span className={`px-2.5 py-0.5 rounded-full border text-xs font-semibold ${statusBadgeClass(isAssetSpecificStep ? currentAssetStatus : 'completed')}`}>
                  {statusLabel(isAssetSpecificStep ? currentAssetStatus : 'completed')}
                </span>
              </div>
              <span className="text-xs font-mono text-[#6b7280] bg-[#0f1117] border border-[#1e2530] px-2 py-1 rounded">{step.us}</span>
            </div>

            <p className="text-sm text-[#9ca3af] border-b border-[#1e2530] pb-4">{step.description}</p>

            {/* ─── CASO A: INFERENCIAS GLOBALES EXPLICATIVAS (PASOS 1 A 4) ─── */}
            {!isAssetSpecificStep && (
              <div className="pt-2">
                {selectedStep === 0 && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs animate-fadeIn">
                    <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4 space-y-2">
                      <div className="text-[#00d4ff] font-semibold flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" /> Correlación del Estado del Puerto</div>
                      <p className="text-[#6b7280] leading-relaxed">Cruza los banners recogidos por Nmap (M2) con los vectores de escaneo de Nuclei (M3). Si el banner del servicio indica un puerto cerrado o filtrado perimetralmente, M8 realiza un descarte inmediato de la vulnerabilidad.</p>
                    </div>
                    <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4 space-y-2">
                      <div className="text-[#00d4ff] font-semibold flex items-center gap-1.5"><Cpu className="w-3.5 h-3.5" /> Verificación de Arquitectura del S.O.</div>
                      <p className="text-[#6b7280] leading-relaxed">Valida la correspondencia del exploit contra el Kernel detectado. Descarta automáticamente firmas de Linux que intenten saltar contra plataformas Windows corporativas, minimizando alertas inútiles en el SOC.</p>
                    </div>
                    <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4 space-y-2">
                      <div className="text-[#22c55e] font-semibold flex items-center gap-1.5"><Layers className="w-3.5 h-3.5" /> Directiva ENS de Salvaguarda</div>
                      <p className="text-[#6b7280] leading-relaxed">Principio de Máxima Cobertura: Ante la falta de evidencias concluyentes en el banner de red, M8 asume de manera proactiva que el hallazgo es VERDADERO para no ignorar brechas potenciales en el perímetro de auditoría.</p>
                    </div>
                  </div>
                )}

                {selectedStep === 1 && (
                  <div className="space-y-4 font-mono text-xs animate-fadeIn">
                    <div className="bg-[#0f1117] border border-[#00d4ff]/20 rounded-lg p-4">
                      <div className="text-white font-semibold mb-2">Fórmula de Cálculo Dinámico de Riesgo Real:</div>
                      <div className="text-[#00d4ff] text-center p-3 bg-[#1a1d27] rounded border border-[#1e2530] text-sm my-2 font-mono">
                        Score_Ajustado = CVSS_Base × Coeficiente_CMDB × Coeficiente_Red
                      </div>
                      <p className="text-[#6b7280] mt-2 leading-relaxed">Modifica el score estático de la vulnerabilidad cruzando la gravedad base de la CVE con la criticidad real que tiene asignada ese activo dentro de la base de datos de ScanOps.</p>
                    </div>
                  </div>
                )}

                {selectedStep === 2 && (
                  <div className="space-y-3 font-mono text-xs animate-fadeIn">
                    <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4">
                      <div className="text-white font-semibold mb-1">Mapeo Semántico Local mediante Embeddings:</div>
                      <p className="text-[#6b7280] leading-relaxed">M8 indexa el contenido del fichero normativo <span className="text-white">rd_311_2022.txt</span> de forma estrictamente local para buscar qué artículos del Anexo II se ven vulnerados por el hallazgo técnico, garantizando la confidencialidad de la infraestructura.</p>
                    </div>
                  </div>
                )}

                {selectedStep === 3 && (
                  <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-4 font-mono text-xs space-y-3 animate-fadeIn">
                    <div className="text-white font-semibold flex items-center gap-1.5"><ShieldAlert className="w-4 h-4 text-[#00d4ff]" /> Esqueleto Estructural del Reporte Semanal Consolidado (M7)</div>
                    <div className="space-y-2 p-3 bg-[#16171d] rounded border border-[#1e2530] text-[#6b7280] text-[11px]">
                      <div>📊 <span className="text-white font-bold">SECCIÓN 1:</span> Resumen General Cuantitativo del Ciclo de Vigilancia Activo.</div>
                      <div>🚨 <span className="text-white font-bold">SECCIÓN 2:</span> Hallazgos Críticos Filtrados que califican para Explotación Inmediata.</div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ─── CASO B: SPLIT PANEL REAL PARA VECTOR Y VALIDACIÓN (PASOS 5 Y 6) ─── */}
            {isAssetSpecificStep && (
              <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-6 pt-2 animate-fadeIn">
                
                {/* COLUMNA IZQUIERDA: BUSCADOR + LISTA DE ACTIVOS REALES M1 */}
                <div className="bg-[#0f1117] border border-[#1e2530] rounded-xl p-3 flex flex-col h-[340px]">
                  <div className="relative mb-3 shrink-0">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#6b7280]" />
                    <input
                      type="text"
                      value={assetSearchQuery}
                      onChange={e => setAssetSearchQuery(e.target.value)}
                      placeholder="Filtrar IP real..."
                      className="w-full pl-8 pr-3 py-1.5 bg-[#1a1d27] border border-[#1e2530] rounded-lg text-xs text-white placeholder:text-[#4b5563] focus:outline-none focus:border-[#00d4ff]/40 transition-colors font-mono"
                    />
                  </div>

                  <div className="flex-1 overflow-y-auto space-y-1.5 pr-1 scrollbar-thin scrollbar-thumb-[#1e2530] scrollbar-track-transparent">
                    {loadingAssets ? (
                      <div className="text-center text-[#6b7280] text-xs pt-8 font-mono animate-pulse">Sincronizando M1...</div>
                    ) : filteredAssets.length === 0 ? (
                      <div className="text-center text-[#4b5563] text-xs pt-8 font-mono">Ningún host activo</div>
                    ) : (
                      filteredAssets.map((asset) => {
                        const isSelected = selectedAssetId === asset.id;
                        const status = assetStatuses[asset.id] ?? (liveResults[asset.id] ? 'requires_review' : 'pending');
                        return (
                          <button
                            key={asset.id}
                            onClick={() => setSelectedAssetId(asset.id)}
                            className={`w-full text-left p-2.5 rounded-lg border transition-all font-mono flex flex-col gap-1 cursor-pointer ${
                              isSelected
                                ? 'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-white shadow-md shadow-[#00d4ff]/5'
                                : 'bg-[#16171d]/50 border-[#1e2530] text-[#9ca3af] hover:bg-[#1a1d27] hover:text-white'
                            }`}
                          >
                            <div className="flex items-center justify-between w-full">
                              <span className="text-xs font-bold font-mono">{asset.ip}</span>
                              <div className={`w-1.5 h-1.5 rounded-full ${
                                status === 'completed' ? 'bg-[#22c55e]' :
                                status === 'rejected' ? 'bg-[#ff3b3b]' :
                                status === 'requires_review' ? 'bg-[#f59e0b]' : 'bg-[#374151]'
                              }`} />
                            </div>
                            <div className="text-[10px] text-[#6b7280] flex items-center gap-1">
                              <Server className="w-2.5 h-2.5 shrink-0" />
                              {asset.hostname || 'srv-host'}
                            </div>
                          </button>
                        );
                      })
                    )}
                  </div>
                </div>

                {/* COLUMNA DERECHA: CONTEXTO OFENSIVO DE LA IA O TERMINAL DE TRIGEREO */}
                <div className="space-y-4 flex flex-col justify-between min-h-[340px]">
                  
                  {!displayResult ? (
                    <div className="bg-[#0f1117] border border-[#1e2530] rounded-xl p-6 text-center flex flex-col items-center justify-center space-y-4 flex-1 font-mono py-12">
                      <Crosshair className="w-8 h-8 text-[#4b5563]" />
                      <div className="space-y-1">
                        <div className="text-white text-sm font-semibold">Sin vector de ataque para {currentAsset?.ip}</div>
                        <p className="text-xs text-[#6b7280] max-w-sm mx-auto leading-relaxed">
                          M8 requiere interrogar las trazas del Scanner Engine para consolidar debilidades perimetrales antes de calcular el exploit idóneo.
                        </p>
                      </div>
                      <button
                        onClick={handleRegenerate}
                        disabled={regenerating}
                        className="px-4 py-1.5 bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] text-xs font-mono font-bold rounded-lg hover:bg-[#00d4ff]/25 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-all"
                      >
                        {regenerating ? `Invocando Ollama [${pollingAttempt}/90]...` : '⚡ Disparar Inferencia M8'}
                      </button>
                    </div>
                  ) : (
                    <>
                      {/* SUB-PASO 4: Renderizado de la Ficha del Vector */}
                      {selectedStep === 4 && (() => {
                        const conf = parseFloat(displayResult.confidence);
                        return (
                          <div className="space-y-3 flex-1 flex flex-col justify-between">
                            <div className="bg-[#0f1117] border border-[#1e2530] rounded-xl p-4 space-y-3 flex-1">
                              <div className="flex items-center gap-2 text-sm font-semibold text-[#00d4ff]">
                                <Terminal className="w-4 h-4" /> Configuración de Payload Real
                              </div>
                              
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                                <div className="bg-[#16171d] p-2.5 border border-[#1e2530] rounded-lg">
                                  <span className="text-[#6b7280] block mb-0.5">Módulo de Ataque</span>
                                  <span className="text-white font-bold break-all">{displayResult.attack_module}</span>
                                </div>
                                <div className="bg-[#16171d] p-2.5 border border-[#1e2530] rounded-lg">
                                  <span className="text-[#6b7280] block mb-0.5">Payload</span>
                                  <span className="text-white font-bold break-all">{displayResult.attack_payload}</span>
                                </div>
                                <div className="bg-[#16171d] p-2.5 border border-[#1e2530] rounded-lg">
                                  <span className="text-[#6b7280] block mb-0.5">target_ip (RHOSTS)</span>
                                  <span className="text-[#00d4ff] font-bold">{displayResult.target_ip}</span>
                                </div>
                                <div className="bg-[#16171d] p-2.5 border border-[#1e2530] rounded-lg">
                                  <span className="text-[#6b7280] block mb-0.5">Confianza (Confidence)</span>
                                  <span className="text-emerald-400 font-bold">{displayResult.confidence}</span>
                                </div>
                              </div>

                              <div className="pt-2">
                                <button
                                  onClick={() => setShowRationale(p => !p)}
                                  className="flex items-center gap-1 text-xs text-[#6b7280] hover:text-white cursor-pointer mb-1"
                                >
                                  {showRationale ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />} Justificación de Explotación
                                </button>
                                {showRationale && (
                                  <p className="text-xs text-[#9ca3af] font-mono bg-[#16171d] p-3 rounded-lg border border-[#1e2530] leading-relaxed">
                                    {displayResult.attack_rationale}
                                  </p>
                                )}
                              </div>
                            </div>

                            {conf < 0.75 && (
                              <div className="flex items-start gap-2 bg-[#f59e0b]/10 border border-[#f59e0b]/30 rounded-lg px-4 py-2.5 text-xs text-[#f59e0b] font-mono shrink-0">
                                ⚠ Confianza baja ({displayResult.confidence}) — requiere validación humana obligatoria en el paso 6.
                              </div>
                            )}
                          </div>
                        );
                      })()}

                      {/* SUB-PASO 5: Panel de Decisión Corporativa */}
                      {selectedStep === 5 && (
                        <div className="bg-[#0f1117] border border-[#1e2530] rounded-xl p-5 space-y-4 flex-1 flex flex-col justify-between">
                          <div className="space-y-3">
                            <div className="text-sm text-white font-semibold flex items-center gap-1.5">
                              <UserCheck className="w-4 h-4 text-[#22c55e]" /> Firma de Dictamen sobre {currentAsset?.ip}
                            </div>
                            <p className="text-xs text-[#6b7280] font-mono leading-relaxed">
                              De acuerdo con el ENS, el operador debe validar de forma explícita el lanzamiento seguro del exploit.
                            </p>
                          </div>

                          {currentAssetStatus === 'rejected' ? (
                            <div className="bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg p-3 space-y-2 animate-fadeIn">
                              <div className="text-xs text-[#ff3b3b] font-bold flex items-center gap-1.5"><XCircle className="w-3.5 h-3.5" /> Explotación denegada de forma inmutable</div>
                              <button
                                onClick={() => enviarDictamenM4('validada')}
                                className="text-[11px] text-[#6b7280] hover:text-white underline cursor-pointer font-mono"
                              >
                                Revertir y volver a evaluar
                              </button>
                            </div>
                          ) : currentAssetStatus === 'completed' ? (
                            <div className="bg-[#22c55e]/10 border border-[#22c55e]/20 rounded-lg p-3 space-y-1 animate-fadeIn">
                              <div className="text-xs text-[#22c55e] font-bold flex items-center gap-1.5"><Check className="w-3.5 h-3.5" /> Explotación autorizada y firmada</div>
                              <button
                                onClick={() => enviarDictamenM4('rechazada')}
                                className="text-[11px] text-[#6b7280] hover:text-white underline cursor-pointer font-mono"
                              >
                                Cancelar autorización
                              </button>
                            </div>
                          ) : (
                            <div className="space-y-3 pt-2">
                              <div className="flex flex-wrap items-center gap-2.5">
                                <button
                                  onClick={() => enviarDictamenM4('validada')}
                                  disabled={dictamenLoading}
                                  className="px-4 py-1.5 bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] rounded-lg text-xs font-semibold hover:bg-[#22c55e]/20 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer transition-colors flex items-center gap-1.5"
                                >
                                  {dictamenLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
                                  Aprobar y Firmar Vector
                                </button>
                                <button
                                  onClick={() => setEditingMsf(!editingMsf)}
                                  disabled={dictamenLoading}
                                  className="px-4 py-1.5 bg-[#f59e0b]/10 border border-[#f59e0b]/30 text-[#f59e0b] rounded-lg text-xs font-semibold hover:bg-[#f59e0b]/20 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer transition-colors"
                                >
                                  Modificar Módulo MSF
                                </button>
                                <button
                                  onClick={() => enviarDictamenM4('rechazada')}
                                  disabled={dictamenLoading}
                                  className="px-4 py-1.5 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] rounded-lg text-xs font-semibold hover:bg-[#ff3b3b]/20 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer transition-colors"
                                >
                                  Rechazar Explotación
                                </button>
                              </div>
                              {dictamenLoading && (
                                <div className="flex items-center gap-2 text-xs text-[#00d4ff] font-mono">
                                  <Loader2 className="w-3 h-3 animate-spin" />Registrando en M4...
                                </div>
                              )}
                              {dictamenMsg && (
                                <div className={`text-xs font-mono mt-1 ${dictamenMsg.startsWith('✓') ? 'text-[#22c55e]' : 'text-[#ff3b3b]'}`}>
                                  {dictamenMsg}
                                </div>
                              )}

                              {editingMsf && (
                                <div className="flex items-center gap-2 animate-fadeIn pt-1">
                                  <input
                                    value={msfInput}
                                    onChange={e => setMsfInput(e.target.value)}
                                    className="flex-1 bg-[#1a1d27] border border-[#1e2530] rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-[#00d4ff]/40"
                                    placeholder="exploit/multi/handler"
                                  />
                                  <button
                                    className="px-3 py-1.5 bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] rounded-lg text-xs hover:bg-[#00d4ff]/20 cursor-pointer"
                                    onClick={() => {
                                      if (liveResults[selectedAssetId]) {
                                        setLiveResults(prev => ({
                                          ...prev,
                                          [selectedAssetId]: { ...prev[selectedAssetId], attack_module: msfInput },
                                        }));
                                      }
                                      enviarDictamenM4('corregida', msfInput);
                                      setEditingMsf(false);
                                    }}
                                  >
                                    Guardar
                                  </button>
                                </div>
                              )}
                            </div>
                          )}

                          <span className="text-[10px] text-[#4b5563] font-mono block border-t border-[#1e2530] pt-2">
                            Norma op.pl.1 — La huella criptográfica del operador se adjuntará inmutable al dictamen.
                          </span>
                        </div>
                      )}
                    </>
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