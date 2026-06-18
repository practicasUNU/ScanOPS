// frontend/src/pages/BastionadoPage.tsx
import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router';
import { Shield, CheckCircle2, XCircle, AlertTriangle, ChevronDown, ChevronUp, FileText, Loader2, ArrowLeft } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../app/components/ui/card';
import { Badge } from '../app/components/ui/badge';
import { Button } from '../app/components/ui/button';
import { Alert, AlertDescription } from '../app/components/ui/alert';
import { Checkbox } from '../app/components/ui/checkbox';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../app/components/ui/tooltip';

// ── Tipos ──────────────────────────────────────────────────────────────────
interface Asset {
  id: number;
  ip: string;
  nombre: string | null;
  hostname: string | null;
  ssh_user: string | null;
}

interface HardeningControl {
  id: number;
  nombre: string;
  resultado: 'SI' | 'NO' | 'REVISAR';
  medida_ens: string;
  detalle: string;
}

interface HardeningResult {
  asset_id: number;
  asset_name: string;
  target: string;
  timestamp: string;
  controles: HardeningControl[];
  resumen: {
    total: number;
    si: number;
    no: number;
    revisar: number;
    cumple_ens: boolean;
  };
}

interface TaskStatus {
  status: 'PENDING' | 'STARTED' | 'SUCCESS' | 'FAILURE';
  results?: HardeningResult[];
  error?: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────
function getToken(): string | null {
  // Intentar todas las claves conocidas donde el frontend guarda el JWT
  try {
    const raw = localStorage.getItem('token');
    if (raw) return raw;

    const authUser = localStorage.getItem('authUser');
    if (authUser) {
      const parsed = JSON.parse(authUser);
      if (parsed?.access_token) return parsed.access_token;
      if (parsed?.token) return parsed.token;
    }

    const session = sessionStorage.getItem('scanops_auth');
    if (session) {
      const parsed = JSON.parse(session);
      if (parsed?.access_token) return parsed.access_token;
    }

    // Iterar sessionStorage por si la clave varía
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (!key) continue;
      try {
        const val = JSON.parse(sessionStorage.getItem(key) || '');
        if (val?.access_token) return val.access_token;
      } catch { /* no era JSON */ }
    }
  } catch { /* ignore */ }
  return null;
}

function authHeaders(): HeadersInit {
  const token = getToken();
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };
}

function assetDisplayName(asset: Asset): string {
  return asset.nombre || asset.hostname || asset.ip;
}

// ── Componentes de presentación ────────────────────────────────────────────
function ResultBadge({ resultado }: { resultado: 'SI' | 'NO' | 'REVISAR' }) {
  if (resultado === 'SI') return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-green-500/15 text-green-400 border border-green-500/30">
      <CheckCircle2 className="w-3 h-3" /> SI
    </span>
  );
  if (resultado === 'NO') return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30">
      <XCircle className="w-3 h-3" /> NO
    </span>
  );
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">
      <AlertTriangle className="w-3 h-3" /> REVISAR
    </span>
  );
}

function ComplianceBadge({ result }: { result: HardeningResult }) {
  const { no, revisar } = result.resumen;
  if (no > 0) return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-red-500/15 text-red-400 border border-red-500/30">NO CUMPLE</span>
  );
  if (revisar > 0) return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">REVISAR</span>
  );
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-green-500/15 text-green-400 border border-green-500/30">CUMPLE</span>
  );
}

function AssetResultCard({ result }: { result: HardeningResult }) {
  const [expanded, setExpanded] = useState(true);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const { si, no, revisar } = result.resumen;
  const compliance = Math.round((si / 13) * 100);
  const ts = new Date(result.timestamp).toLocaleString('es-ES');

  const handlePdf = async () => {
    setPdfError(null);
    setPdfLoading(true);
    try {
      const res = await fetch(
        `/api/m7/report/hardening/${result.asset_id}`,
        { headers: authHeaders() },
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.download = `hardening_${result.asset_id}_${result.asset_name.replace(/\s+/g, '_')}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      // Liberar después de que el navegador haya iniciado la descarga
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (e: unknown) {
      setPdfError(e instanceof Error ? e.message : 'Error generando PDF');
    } finally {
      setPdfLoading(false);
    }
  };

  return (
    <Card className="bg-[#111318] border-[#1C2030]">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-white font-semibold">{result.asset_name}</span>
              <span className="text-slate-400 text-sm">{result.target}</span>
            </div>
            <div className="text-xs text-slate-500 mt-1">{ts}</div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-green-500/15 text-green-400 border border-green-500/30">{si} SI</span>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30">{no} NO</span>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">{revisar} REVISAR</span>
            <span className="text-slate-300 text-sm font-mono">{compliance}%</span>
            <ComplianceBadge result={result} />
            <button
              onClick={() => setExpanded(e => !e)}
              className="text-slate-400 hover:text-white transition-colors ml-1"
            >
              {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </CardHeader>

      {expanded && (
        <CardContent className="pt-0">
          <div className="overflow-x-auto rounded border border-[#1C2030]">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1C2030] text-slate-500 text-xs uppercase">
                  <th className="text-left px-3 py-2 w-8">#</th>
                  <th className="text-left px-3 py-2">Control</th>
                  <th className="text-left px-3 py-2">Resultado</th>
                  <th className="text-left px-3 py-2">Medida ENS</th>
                  <th className="text-left px-3 py-2">Detalle</th>
                </tr>
              </thead>
              <tbody>
                {result.controles.map((ctrl, idx) => (
                  <tr key={ctrl.id} className={`border-b border-[#1C2030]/50 ${idx % 2 === 0 ? 'bg-[#0A0C10]/30' : ''}`}>
                    <td className="px-3 py-2 text-slate-500 font-mono">{ctrl.id}</td>
                    <td className="px-3 py-2 text-slate-200">{ctrl.nombre}</td>
                    <td className="px-3 py-2"><ResultBadge resultado={ctrl.resultado} /></td>
                    <td className="px-3 py-2 font-mono text-[#8B5CF6] text-xs">{ctrl.medida_ens}</td>
                    <td className="px-3 py-2 text-slate-400 text-xs max-w-xs truncate" title={ctrl.detalle}>{ctrl.detalle || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {pdfError && (
            <p className="mt-2 text-xs text-red-400">{pdfError}</p>
          )}
          <div className="mt-4 flex justify-end">
            <Button
              variant="outline"
              size="sm"
              disabled={pdfLoading}
              className="gap-2 border-[#1C2030] text-slate-300 hover:text-white hover:border-[#8B5CF6]/50 disabled:opacity-50"
              onClick={handlePdf}
            >
              {pdfLoading
                ? <Loader2 className="w-4 h-4 animate-spin" />
                : <FileText className="w-4 h-4" />}
              {pdfLoading ? 'Generando...' : 'Generar Informe PDF'}
            </Button>
          </div>
        </CardContent>
      )}
    </Card>
  );
}

// ── Página principal ───────────────────────────────────────────────────────
export function BastionadoPage() {
  const navigate = useNavigate();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetsError, setAssetsError] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [results, setResults] = useState<HardeningResult[]>([]);
  const [lastCycle, setLastCycle] = useState<string | null>(null);
  const [pollingError, setPollingError] = useState<string | null>(null);
  const failCountRef = useRef(0);
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Cargar activos desde M1
  useEffect(() => {
    fetch('/api/m1/api/v1/assets?page=1&page_size=100', {
      headers: authHeaders(),
    })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => {
        // M1 devuelve {total, page, page_size, items:[...]}
        const list: Asset[] = Array.isArray(data) ? data : (data.items ?? []);
        setAssets(list);
      })
      .catch(() => setAssetsError('No se pudo cargar la lista de activos desde M1'));
  }, []);

  // Polling
  const stopPolling = useCallback(() => {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    pollTimerRef.current = null;
  }, []);

  const poll = useCallback((id: string) => {
    fetch(`/api/m3/api/v1/hardening/status/${id}`, { headers: authHeaders() })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<TaskStatus>;
      })
      .then(data => {
        failCountRef.current = 0;
        if (data.status === 'SUCCESS') {
          setRunning(false);
          setTaskId(null);
          stopPolling();
          if (data.results?.length) {
            setResults(data.results);
            setLastCycle(new Date().toISOString());
          }
        } else if (data.status === 'FAILURE') {
          setRunning(false);
          setTaskId(null);
          stopPolling();
          setPollingError(data.error ?? 'La verificación falló en el servidor');
        } else {
          pollTimerRef.current = setTimeout(() => poll(id), 3000);
        }
      })
      .catch(() => {
        failCountRef.current += 1;
        if (failCountRef.current >= 3) {
          setRunning(false);
          setTaskId(null);
          stopPolling();
          setPollingError('Se perdió la conexión con el servidor tras 3 intentos');
        } else {
          pollTimerRef.current = setTimeout(() => poll(id), 3000);
        }
      });
  }, [stopPolling]);

  useEffect(() => {
    if (taskId) {
      failCountRef.current = 0;
      poll(taskId);
    }
    return stopPolling;
  }, [taskId, poll, stopPolling]);

  const handleRun = async () => {
    setRunError(null);
    setPollingError(null);
    setRunning(true);
    try {
      const res = await fetch('/api/m3/api/v1/hardening/run', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ asset_ids: Array.from(selectedIds) }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail));
      }
      const data = await res.json();
      setTaskId(data.task_id);
    } catch (e: unknown) {
      setRunning(false);
      setRunError(e instanceof Error ? e.message : 'Error al lanzar la verificación');
    }
  };

  const toggleAsset = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const eligibleIds = assets.filter(a => a.ssh_user).map(a => a.id);
  const allSelected = eligibleIds.length > 0 && eligibleIds.every(id => selectedIds.has(id));
  const someSelected = !allSelected && eligibleIds.some(id => selectedIds.has(id));

  const toggleAll = () => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (allSelected) {
        eligibleIds.forEach(id => next.delete(id));
      } else {
        eligibleIds.forEach(id => next.add(id));
      }
      return next;
    });
  };

  return (
    <TooltipProvider>
      <div className="flex-1 overflow-y-auto bg-[#0A0C10] min-h-screen">
        <div className="max-w-6xl mx-auto p-6 space-y-6">

          {/* Cabecera */}
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div className="flex items-center gap-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate('/dashboard')}
                className="gap-1.5 text-slate-400 hover:text-white hover:bg-[#1C2030] px-2"
              >
                <ArrowLeft className="w-4 h-4" />
                Volver
              </Button>
              <div className="w-px h-6 bg-[#1C2030]" />
              <div className="w-10 h-10 rounded-lg bg-[#8B5CF6]/10 border border-[#8B5CF6]/20 flex items-center justify-center">
                <Shield className="w-5 h-5 text-[#8B5CF6]" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">Bastionado ENS</h1>
                <p className="text-sm text-slate-400">Verificación trimestral de controles — RD 311/2022</p>
              </div>
            </div>
            {lastCycle ? (
              <Badge variant="outline" className="border-[#8B5CF6]/30 text-[#8B5CF6] text-xs">
                Último ciclo: {new Date(lastCycle).toLocaleDateString('es-ES')}
              </Badge>
            ) : (
              <Badge variant="outline" className="border-slate-600 text-slate-400 text-xs">
                Sin verificaciones previas
              </Badge>
            )}
          </div>

          {/* Panel de ejecución */}
          <Card className="bg-[#111318] border-[#1C2030]">
            <CardHeader>
              <CardTitle className="text-white text-base">Nueva Verificación</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {assetsError && (
                <Alert variant="destructive">
                  <AlertDescription>{assetsError}</AlertDescription>
                </Alert>
              )}
              {runError && (
                <Alert variant="destructive">
                  <AlertDescription>{runError}</AlertDescription>
                </Alert>
              )}
              {pollingError && (
                <Alert variant="destructive">
                  <AlertDescription>{pollingError}</AlertDescription>
                </Alert>
              )}

              {!assetsError && assets.length === 0 && (
                <div className="text-center py-8 text-slate-500">
                  <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No hay activos disponibles</p>
                </div>
              )}

              {assets.length > 0 && (
                <>
                  {/* Seleccionar todos */}
                  <div className="flex items-center gap-3 px-3 py-2 border-b border-[#1C2030]">
                    <Checkbox
                      checked={allSelected}
                      disabled={eligibleIds.length === 0}
                      onCheckedChange={toggleAll}
                      className="border-slate-600 data-[state=checked]:bg-[#8B5CF6] data-[state=checked]:border-[#8B5CF6]"
                    />
                    <span
                      className={`text-xs font-medium select-none ${eligibleIds.length === 0 ? 'text-slate-600' : 'text-slate-400 cursor-pointer hover:text-white'}`}
                      onClick={() => eligibleIds.length > 0 && toggleAll()}
                    >
                      Seleccionar todos
                    </span>
                    {selectedIds.size > 0 && (
                      <span className="ml-auto text-xs text-[#8B5CF6]">
                        {selectedIds.size} / {eligibleIds.length} seleccionados
                      </span>
                    )}
                  </div>

                  <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                    {assets.map(asset => {
                      const disabled = !asset.ssh_user;
                      const checked = selectedIds.has(asset.id);
                      const displayName = assetDisplayName(asset);
                      return (
                        <div
                          key={asset.id}
                          className={`flex items-center gap-3 p-3 rounded-lg border transition-colors ${
                            disabled
                              ? 'border-[#1C2030] opacity-50 cursor-not-allowed'
                              : checked
                              ? 'border-[#8B5CF6]/30 bg-[#8B5CF6]/5'
                              : 'border-[#1C2030] hover:border-[#1C2030]/80 hover:bg-[#0A0C10]/40 cursor-pointer'
                          }`}
                          onClick={() => !disabled && toggleAsset(asset.id)}
                        >
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span>
                                <Checkbox
                                  checked={checked}
                                  disabled={disabled}
                                  onCheckedChange={() => !disabled && toggleAsset(asset.id)}
                                  onClick={e => e.stopPropagation()}
                                  className="border-slate-600 data-[state=checked]:bg-[#8B5CF6] data-[state=checked]:border-[#8B5CF6]"
                                />
                              </span>
                            </TooltipTrigger>
                            {disabled && (
                              <TooltipContent>
                                <p>Sin credenciales SSH configuradas</p>
                              </TooltipContent>
                            )}
                          </Tooltip>
                          <div className="flex-1 min-w-0">
                            <span className="text-sm text-white font-medium">{displayName}</span>
                            <span className="text-xs text-slate-400 ml-2">{asset.ip}</span>
                          </div>
                          <Badge
                            variant="outline"
                            className={`text-xs shrink-0 ${
                              disabled
                                ? 'border-slate-600 text-slate-500'
                                : 'border-green-500/30 text-green-400'
                            }`}
                          >
                            {disabled ? 'Sin SSH' : 'Listo'}
                          </Badge>
                        </div>
                      );
                    })}
                  </div>
                </>
              )}

              <div className="flex justify-end pt-2">
                <Button
                  disabled={selectedIds.size === 0 || running}
                  onClick={handleRun}
                  className="gap-2 bg-[#8B5CF6] hover:bg-[#00b8d9] text-[#0A0C10] font-semibold disabled:opacity-50"
                >
                  {running ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Verificando...
                    </>
                  ) : (
                    <>
                      <Shield className="w-4 h-4" />
                      ▶ Ejecutar Verificación
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Resultados */}
          {results.length > 0 && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold text-white">Resultados de la Verificación</h2>
              {results.map(r => (
                <AssetResultCard key={r.asset_id} result={r} />
              ))}
            </div>
          )}

        </div>
      </div>
    </TooltipProvider>
  );
}

export default BastionadoPage;