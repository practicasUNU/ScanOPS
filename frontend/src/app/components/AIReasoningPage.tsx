import React, { useState, useEffect, useMemo } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  Filter, ArrowUpDown, BookOpen, FileText, Crosshair, UserCheck,
  Check, Terminal, XCircle, Loader2, RefreshCw, AlertCircle,
  ShieldAlert, Activity, Cpu, Layers, Server, Search,
  ShieldCheck
} from 'lucide-react';


const fmtDate = (iso?: string | null): string => {
  if (!iso) return '—';
  try {
    const normalized = iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z';
    return new Date(normalized).toLocaleDateString('es-ES', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
      timeZone: 'Europe/Madrid',
    });
  } catch { return '—'; }
};

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

const M1_ASSETS_URL = '/api/m1/api/v1/assets?page_size=100';
const M3_BASE = '/api/m3';

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
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authStep, setAuthStep] = useState<'pin'|'qr'|'done'>('pin');
  const [authPin, setAuthPin] = useState('');
  const [authPinError, setAuthPinError] = useState('');
  const [authApprovalId, setAuthApprovalId] = useState<number|null>(null);
  const [authQrBase64, setAuthQrBase64] = useState('');
  const [authTotpCode, setAuthTotpCode] = useState('');
  const [authTotpError, setAuthTotpError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [authTotpSecret, setAuthTotpSecret] = useState('');
  const [authLiveCode, setAuthLiveCode] = useState('');
  const [authCodeTimer, setAuthCodeTimer] = useState(30);

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
              attack_module:    r.suggested_tool       ?? r.msf_module    ?? r.attack_module    ?? 'N/A',
              attack_payload:   r.tool_params          ?? r.msf_payload   ?? r.attack_payload   ?? {},
              attack_technique: r.attack_technique     ?? 'N/A',
              mitre_tactic:     r.mitre_tactic         ?? 'N/A',
              attack_vector:    r.attack_vector        ?? 'N/A',
              alternative:      r.alternative_technique ?? null,
              technical_steps:  r.technical_steps      ?? [],
              attack_rationale: r.attack_rationale     ?? r.rationale     ?? '',
              target_ip:        r.tool_params?.target  ?? r.msf_options?.RHOSTS ?? currentAsset?.ip ?? '',
              confidence:       String(r.confidence    ?? '0.85'),
              risk_level:       r.risk_level           ?? 'ALTO',
              ens_article:      r.ens_article          ?? 'op.exp.2',
              status:           r.status               ?? 'pending_human_approval',
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

  const handleAprobarClick = () => {
    setAuthPin('');
    setAuthPinError('');
    setAuthTotpCode('');
    setAuthTotpError('');
    setAuthStep('pin');
    setAuthModalOpen(true);
  };

  const handleRequestApproval = async () => {
    if (!authPin || authPin.length < 4) {
      setAuthPinError('El PIN debe tener al menos 4 caracteres');
      return;
    }
    setAuthLoading(true);
    setAuthPinError('');
    try {
      const token = getToken();
      const cveId = displayResult?.attack_module?.split('/').pop()?.toUpperCase()
        ?? `VECTOR-${currentAsset?.ip}`;
      const res = await fetch('/api/m4/api/m4/request-approval', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          cve: cveId,
          ip: currentAsset?.ip ?? '0.0.0.0',
          user_email: 'admin@scanops.local',
          pin: authPin,
        }),
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setAuthPinError((err as any)?.detail ?? `Error ${res.status}`);
        return;
      }
      const data = await res.json();
      setAuthApprovalId(data.approval_id);
      setAuthQrBase64(data.qr_code_base64);
      setAuthTotpSecret(data.totp_secret ?? '');
      setAuthStep('qr');
    } catch (e: any) {
      setAuthPinError(e?.message ?? 'Error de conexión con M4');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleSubmitTotp = async () => {
    if (!authTotpCode || authTotpCode.length !== 6) {
      setAuthTotpError('Introduce el código de 6 dígitos');
      return;
    }
    if (!authApprovalId) return;
    setAuthLoading(true);
    setAuthTotpError('');
    try {
      const token = getToken();
      const res = await fetch('/api/m4/api/m4/approve', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          approval_id: authApprovalId,
          totp_code: authTotpCode,
          pin: authPin,
        }),
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setAuthTotpError((err as any)?.detail ?? 'Código incorrecto o expirado');
        return;
      }
      setAuthStep('done');
      setAssetStatuses(p => ({ ...p, [selectedAssetId]: 'completed' }));
      setTimeout(() => {
        setAuthModalOpen(false);
        setAuthTotpSecret('');
        setAuthLiveCode('');
        setAuthCodeTimer(30);
      }, 2000);
    } catch (e: any) {
      setAuthTotpError(e?.message ?? 'Error de conexión con M4');
    } finally {
      setAuthLoading(false);
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
                            {liveResults[asset.id]?.generated_at && (
                              <span className="text-[9px] text-[#4b5563] font-mono block mt-0.5">
                                {fmtDate(liveResults[asset.id].generated_at)}
                              </span>
                            )}
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
                      {selectedStep === 4 && displayResult && (() => {
                        const riskColor: Record<string, string> = {
                          CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#22c55e'
                        };
                        const confPct = isNaN(parseFloat(displayResult.confidence))
                          ? displayResult.confidence
                          : `${Math.round(parseFloat(displayResult.confidence) * 100)}%`;
                        const risk = String(displayResult.risk_level ?? 'HIGH').toUpperCase();
                        const steps: string[] = Array.isArray(displayResult.technical_steps)
                          ? displayResult.technical_steps
                          : [];
                        const params = typeof displayResult.attack_payload === 'object' && displayResult.attack_payload !== null
                          ? displayResult.attack_payload as Record<string, string>
                          : {};

                        return (
                          <div className="space-y-4 flex-1 flex flex-col">

                            {/* ── CABECERA: técnica + táctica MITRE ── */}
                            <div className="bg-[#0f1117] border border-[#1e2530] rounded-xl p-4 space-y-2">
                              <div className="flex items-center justify-between flex-wrap gap-2">
                                <span className="text-xs font-mono text-[#6b7280] uppercase tracking-widest">Técnica de Ataque</span>
                                <div className="flex items-center gap-2">
                                  <span
                                    className="px-2 py-0.5 rounded text-xs font-bold font-mono"
                                    style={{ backgroundColor: `${riskColor[risk] ?? '#f97316'}22`, color: riskColor[risk] ?? '#f97316', border: `1px solid ${riskColor[risk] ?? '#f97316'}44` }}
                                  >
                                    {risk}
                                  </span>
                                  <span className="px-2 py-0.5 rounded text-xs font-bold font-mono bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/30">
                                    {confPct} confianza
                                  </span>
                                </div>
                              </div>
                              <p className="text-white font-semibold text-sm font-mono">{displayResult.attack_technique ?? '—'}</p>
                              <p className="text-[#9ca3af] text-xs">{displayResult.attack_vector ?? '—'}</p>
                              <div className="flex items-center gap-1.5 pt-1">
                                <span className="text-[#6b7280] text-xs">Táctica MITRE:</span>
                                <span className="text-[#a78bfa] text-xs font-mono font-semibold">{displayResult.mitre_tactic ?? '—'}</span>
                                <span className="ml-auto text-[#6b7280] text-xs">ENS:</span>
                                <span className="text-[#00d4ff] text-xs font-mono">{displayResult.ens_article ?? 'op.exp.2'}</span>
                              </div>
                            </div>

                            {/* ── HERRAMIENTA + PARÁMETROS ── */}
                            <div className="bg-[#0f1117] border border-[#1e2530] rounded-xl p-4 space-y-3">
                              <div className="flex items-center gap-2 text-sm font-semibold text-[#00d4ff]">
                                <Terminal className="w-4 h-4" />
                                Herramienta de Validación
                              </div>
                              <div className="bg-[#16171d] border border-[#1e2530] rounded-lg p-3 font-mono text-xs text-white break-all">
                                {displayResult.attack_module ?? '—'}
                              </div>
                              {Object.keys(params).length > 0 && (
                                <div className="grid grid-cols-2 gap-2">
                                  {Object.entries(params).map(([k, v]) => v && (
                                    <div key={k} className="bg-[#16171d] border border-[#1e2530] rounded-lg p-2.5">
                                      <span className="text-[#6b7280] text-xs block mb-0.5 uppercase tracking-wide">{k}</span>
                                      <span className="text-white font-mono text-xs font-bold break-all">{String(v)}</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                              {displayResult.alternative && (
                                <div className="flex items-start gap-2 pt-1">
                                  <span className="text-[#6b7280] text-xs shrink-0 mt-0.5">Alternativa:</span>
                                  <span className="text-[#f59e0b] text-xs font-mono">{displayResult.alternative}</span>
                                </div>
                              )}
                            </div>

                            {/* ── PASOS TÉCNICOS ── */}
                            {steps.length > 0 && (
                              <div className="bg-[#0f1117] border border-[#1e2530] rounded-xl p-4 space-y-2">
                                <div className="text-xs font-semibold text-[#6b7280] uppercase tracking-widest mb-1">
                                  Secuencia Operativa
                                </div>
                                {steps.map((step, i) => (
                                  <div key={i} className="flex items-start gap-3">
                                    <span className="w-5 h-5 rounded-full bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                                      {i + 1}
                                    </span>
                                    <p className="text-[#d1d5db] text-xs leading-relaxed">{step}</p>
                                  </div>
                                ))}
                              </div>
                            )}

                            {/* ── RATIONALE ── */}
                            {displayResult.attack_rationale && (() => {
                              const raw: string = displayResult.attack_rationale;

                              const SECTION_LABELS: { regex: RegExp; label: string; color: string }[] = [
                                { regex: /An[aá]lisis\s+de\s+Superficie\s*:/i,  label: 'Análisis de Superficie', color: '#00d4ff' },
                                { regex: /Vector\s+Cr[ií]tico\s*:/i,             label: 'Vector Crítico',         color: '#a78bfa' },
                                { regex: /Evaluaci[oó]n\s+de\s+Riesgo\s*:/i,     label: 'Evaluación de Riesgo',   color: '#f59e0b' },
                                { regex: /Analysis\s+of\s+Surface\s*:/i,          label: 'Análisis de Superficie', color: '#00d4ff' },
                                { regex: /Critical\s+Vector\s*:/i,                label: 'Vector Crítico',         color: '#a78bfa' },
                                { regex: /Risk\s+Evaluation\s*:/i,                label: 'Evaluación de Riesgo',   color: '#f59e0b' },
                              ];

                              const splitRegex = new RegExp(
                                `(${SECTION_LABELS.map(s => s.regex.source).join('|')})`,
                                'gi'
                              );

                              const parts = raw.split(splitRegex).map(s => s.trim()).filter(Boolean);

                              type Section = { label: string; color: string; body: string };
                              let sections: Section[] = [];

                              if (parts.length > 1) {
                                for (let i = 0; i < parts.length; i++) {
                                  const matched = SECTION_LABELS.find(s => s.regex.test(parts[i]));
                                  if (matched && parts[i + 1]) {
                                    const body = parts[i + 1]
                                      .replace(/\b(Risk Level|ENS Article|Confidence|Estimated Service Impact)[^\n.]*/gi, '')
                                      .trim();
                                    if (body.length > 10) {
                                      sections.push({ label: matched.label, color: matched.color, body });
                                      i++;
                                    }
                                  }
                                }
                              }

                              if (sections.length === 0) {
                                const fallbackLabels = ['Análisis de Superficie', 'Vector Crítico', 'Evaluación de Riesgo'];
                                const fallbackColors = ['#00d4ff', '#a78bfa', '#f59e0b'];
                                const sentences = raw.match(/[^.!?]+[.!?]+/g) ?? [raw];
                                const chunkSize = Math.ceil(sentences.length / 3);
                                for (let i = 0; i < 3; i++) {
                                  const body = sentences.slice(i * chunkSize, (i + 1) * chunkSize).join(' ').trim();
                                  if (body.length > 10) {
                                    sections.push({ label: fallbackLabels[i], color: fallbackColors[i], body });
                                  }
                                }
                              }

                              return (
                                <div className="bg-[#0f1117] border border-[#1e2530] rounded-xl p-4 space-y-4 flex-1">
                                  <div className="text-xs font-semibold text-[#6b7280] uppercase tracking-widest">
                                    Análisis Técnico Red Team
                                  </div>
                                  {sections.map((sec, i) => (
                                    <div key={i} className="flex gap-3">
                                      <div
                                        className="w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold shrink-0 mt-0.5"
                                        style={{
                                          backgroundColor: `${sec.color}18`,
                                          color: sec.color,
                                          border: `1px solid ${sec.color}33`,
                                        }}
                                      >
                                        {i + 1}
                                      </div>
                                      <div className="flex-1 space-y-1 border-b border-[#1e2530] pb-3 last:border-0 last:pb-0">
                                        <span className="text-xs font-semibold block" style={{ color: sec.color }}>
                                          {sec.label}
                                        </span>
                                        <p className="text-[#9ca3af] text-xs leading-relaxed">{sec.body}</p>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              );
                            })()}

                            {/* ── ESTADO ENS ── */}
                            <div className="flex items-center gap-2 px-3 py-2 bg-[#f59e0b]/5 border border-[#f59e0b]/20 rounded-lg">
                              <span className="w-1.5 h-1.5 rounded-full bg-[#f59e0b] animate-pulse shrink-0" />
                              <span className="text-[#f59e0b] text-xs font-mono font-semibold">
                                {displayResult.status ?? 'pending_human_approval'}
                              </span>
                              <span className="text-[#6b7280] text-xs ml-auto">op.pl.1 — Requiere TOTP+PIN</span>
                            </div>

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
                                onClick={() => setAssetStatuses(p => ({ ...p, [selectedAssetId]: 'requires_review' }))}
                                className="text-[11px] text-[#6b7280] hover:text-white underline cursor-pointer font-mono"
                              >
                                Revertir y volver a evaluar
                              </button>
                            </div>
                          ) : currentAssetStatus === 'completed' ? (
                            <div className="bg-[#22c55e]/10 border border-[#22c55e]/20 rounded-lg p-3 space-y-1 animate-fadeIn">
                              <div className="text-xs text-[#22c55e] font-bold flex items-center gap-1.5"><Check className="w-3.5 h-3.5" /> Explotación autorizada y firmada</div>
                              <button
                                onClick={() => setAssetStatuses(p => ({ ...p, [selectedAssetId]: 'requires_review' }))}
                                className="text-[11px] text-[#6b7280] hover:text-white underline cursor-pointer font-mono"
                              >
                                Cancelar autorización
                              </button>
                            </div>
                          ) : (
                            <div className="space-y-3 pt-2">
                              <div className="flex flex-wrap items-center gap-2.5">
                                <button
                                  onClick={handleAprobarClick}
                                  className="px-4 py-1.5 bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] rounded-lg text-xs font-semibold hover:bg-[#22c55e]/20 cursor-pointer transition-colors flex items-center gap-1.5"
                                >
                                  Aprobar y Firmar Vector
                                </button>
                                <button
                                  onClick={() => setEditingMsf(!editingMsf)}
                                  className="px-4 py-1.5 bg-[#f59e0b]/10 border border-[#f59e0b]/30 text-[#f59e0b] rounded-lg text-xs font-semibold hover:bg-[#f59e0b]/20 cursor-pointer transition-colors"
                                >
                                  Modificar Módulo MSF
                                </button>
                                <button
                                  onClick={() => setAssetStatuses(p => ({ ...p, [selectedAssetId]: 'rejected' }))}
                                  className="px-4 py-1.5 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] rounded-lg text-xs font-semibold hover:bg-[#ff3b3b]/20 cursor-pointer transition-colors"
                                >
                                  Rechazar Explotación
                                </button>
                              </div>

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

      {/* ── Modal de autorización M8→M4 ── */}
      {authModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-2xl p-6 w-full max-w-md shadow-2xl">

            {/* Header */}
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-[#00d4ff]"/>
                <h3 className="text-sm font-bold text-white">Autorizar Vector de Ataque</h3>
              </div>
              <button onClick={() => { setAuthModalOpen(false); setAuthTotpSecret(''); setAuthLiveCode(''); setAuthCodeTimer(30); setAuthStep('pin'); }}
                className="text-[#6b7280] hover:text-white text-lg leading-none">×</button>
            </div>

            {/* Indicador de pasos */}
            <div className="flex items-center gap-2 mb-5">
              {['PIN', 'QR'].map((label, i) => {
                const stepIdx = authStep === 'pin' ? 0 : 1;
                return (
                  <React.Fragment key={label}>
                    <div className={`flex items-center gap-1.5 text-xs font-mono ${stepIdx >= i ? 'text-[#00d4ff]' : 'text-[#374151]'}`}>
                      <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold border ${stepIdx > i ? 'bg-[#22c55e] border-[#22c55e] text-white' : stepIdx === i ? 'border-[#00d4ff] text-[#00d4ff]' : 'border-[#374151] text-[#374151]'}`}>
                        {stepIdx > i ? '✓' : i + 1}
                      </div>
                      {label}
                    </div>
                    {i < 1 && <div className={`flex-1 h-px ${stepIdx > i ? 'bg-[#22c55e]' : 'bg-[#1e2530]'}`}/>}
                  </React.Fragment>
                );
              })}
            </div>

            {/* PASO 1: PIN */}
            {authStep === 'pin' && (
              <div className="space-y-4">
                <p className="text-xs text-[#9ca3af]">
                  Introduce un PIN de seguridad. Lo necesitarás junto al código TOTP para autorizar.
                </p>
                <div>
                  <label className="text-xs text-[#6b7280] mb-1.5 block">PIN de autorización *</label>
                  <input
                    type="password"
                    value={authPin}
                    onChange={e => setAuthPin(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleRequestApproval()}
                    placeholder="Mínimo 4 caracteres"
                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2
                               text-sm text-white focus:outline-none focus:border-[#00d4ff]"
                  />
                  {authPinError && (
                    <p className="text-xs text-[#ff3b3b] mt-1 flex items-center gap-1">
                      <AlertCircle className="w-3 h-3"/>{authPinError}
                    </p>
                  )}
                </div>
                <div className="bg-[#0f1117] rounded-lg p-3 text-xs text-[#6b7280]">
                  <p className="font-semibold text-[#9ca3af] mb-1">Activo objetivo</p>
                  <p className="font-mono">{currentAsset?.ip} — {currentAsset?.hostname ?? 'Sin hostname'}</p>
                </div>
                <button onClick={handleRequestApproval} disabled={authLoading || !authPin}
                  className="w-full py-2 bg-[#00d4ff] hover:bg-[#00b8e6] text-[#0f1117] font-bold
                             rounded-lg text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed
                             flex items-center justify-center gap-2">
                  {authLoading
                    ? <><Loader2 className="w-4 h-4 animate-spin"/>Solicitando...</>
                    : <>Continuar →</>}
                </button>
              </div>
            )}

            {/* PASO 2: QR */}
            {authStep === 'qr' && (
              <div className="space-y-4">
                <p className="text-xs text-[#9ca3af]">
                  Guarda este código QR en tu app autenticadora (<strong className="text-white">Google Authenticator</strong>, <strong className="text-white">Authy</strong>).
                  El Security Officer lo necesitará para aprobar en M4 Explotación.
                  La solicitud expira en <strong className="text-[#f59e0b]">30 minutos</strong>.
                </p>
                <div className="flex justify-center">
                  <img
                    src={`data:image/png;base64,${authQrBase64}`}
                    alt="QR TOTP"
                    className="w-64 h-64 rounded-lg border border-[#1e2530]"
                  />
                </div>
                <p className="text-xs text-[#6b7280] text-center">
                  Aprobación ID: <span className="font-mono text-[#00d4ff]">#{authApprovalId}</span>
                </p>
                <button onClick={() => setAuthStep('done')}
                  className="w-full py-2 bg-[#00d4ff] hover:bg-[#00b8e6] text-[#0f1117] font-bold
                             rounded-lg text-sm transition-colors">
                  Solicitud enviada a M4 ✓
                </button>
              </div>
            )}


            {/* DONE */}
            {authStep === 'done' && (
              <div className="text-center space-y-3 py-4">
                <div className="w-12 h-12 rounded-full bg-[#22c55e]/20 border border-[#22c55e]/30
                                flex items-center justify-center mx-auto">
                  <Check className="w-6 h-6 text-[#22c55e]"/>
                </div>
                <p className="text-sm font-bold text-[#22c55e]">Vector autorizado y firmado</p>
                <p className="text-xs text-[#6b7280]">
                  La solicitud está PENDING en M4 Explotación. El Security Officer debe aprobarla con su código TOTP.
                </p>
              </div>
            )}

          </div>
        </div>
      )}

    </div>
  );
}