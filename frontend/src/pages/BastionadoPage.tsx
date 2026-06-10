import { useState, useEffect, useRef, useCallback } from 'react';
import { Shield, CheckCircle2, XCircle, AlertTriangle, ChevronDown, ChevronUp, FileText, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../app/components/ui/card';
import { Badge } from '../app/components/ui/badge';
import { Button } from '../app/components/ui/button';
import { Alert, AlertDescription } from '../app/components/ui/alert';
import { Checkbox } from '../app/components/ui/checkbox';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../app/components/ui/tooltip';

interface Asset {
  id: number;
  name: string;
  ip_address: string;
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

const CONTROLS_MAP: { nombre: string; medida_ens: string }[] = [
  { nombre: 'Antivirus',                 medida_ens: 'op.exp.2'   },
  { nombre: 'Cortafuegos (Firewall)',    medida_ens: 'mp.com.1'   },
  { nombre: 'Almacenamiento externo',    medida_ens: 'mp.si.5'    },
  { nombre: 'Aplicaciones permitidas',   medida_ens: 'op.exp.3'   },
  { nombre: 'Configuración de logs',     medida_ens: 'op.exp.5'   },
  { nombre: 'Puertos de red',            medida_ens: 'op.acc.6'   },
  { nombre: 'Servidor horario (NTP)',    medida_ens: 'op.exp.3'   },
  { nombre: 'Versión del software',      medida_ens: 'op.exp.2'   },
  { nombre: 'Niveles de parches',        medida_ens: 'op.exp.2'   },
  { nombre: 'Unidades encriptadas',      medida_ens: 'mp.info.3'  },
  { nombre: 'Certificado SSL',           medida_ens: 'mp.com.2'   },
  { nombre: 'Doble factor (2FA)',        medida_ens: 'op.acc.6'   },
  { nombre: 'Copias de seguridad',       medida_ens: 'op.cont.2'  },
];

function getToken(): string | null {
  const raw = localStorage.getItem('token');
  if (raw) return raw;
  // fallback for sessionStorage pattern used elsewhere
  try {
    const session = sessionStorage.getItem('scanops_auth');
    if (session) return JSON.parse(session)?.access_token ?? null;
  } catch { /* ignore */ }
  return null;
}

function authHeaders(): HeadersInit {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' };
}

function ResultBadge({ resultado }: { resultado: 'SI' | 'NO' | 'REVISAR' }) {
  if (resultado === 'SI') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-green-500/15 text-green-400 border border-green-500/30">
        <CheckCircle2 className="w-3 h-3" /> SI
      </span>
    );
  }
  if (resultado === 'NO') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30">
        <XCircle className="w-3 h-3" /> NO
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">
      <AlertTriangle className="w-3 h-3" /> REVISAR
    </span>
  );
}

function ComplianceBadge({ result }: { result: HardeningResult }) {
  const { no, revisar } = result.resumen;
  if (no > 0) {
    return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-red-500/15 text-red-400 border border-red-500/30">NO CUMPLE</span>;
  }
  if (revisar > 0) {
    return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">REVISAR</span>;
  }
  return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold bg-green-500/15 text-green-400 border border-green-500/30">CUMPLE</span>;
}

function AssetResultCard({ result }: { result: HardeningResult }) {
  const [expanded, setExpanded] = useState(true);
  const { si, no, revisar } = result.resumen;
  const compliance = Math.round((si / 13) * 100);
  const ts = new Date(result.timestamp).toLocaleString('es-ES');

  const controls = result.controles.length > 0
    ? result.controles
    : CONTROLS_MAP.map((c, i) => ({ id: i + 1, nombre: c.nombre, resultado: 'REVISAR' as const, medida_ens: c.medida_ens, detalle: '' }));

  return (
    <Card className="bg-[#1a1d27] border-[#1e2530]">
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
          <div className="overflow-x-auto rounded border border-[#1e2530]">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2530] text-slate-500 text-xs uppercase">
                  <th className="text-left px-3 py-2 w-8">#</th>
                  <th className="text-left px-3 py-2">Control</th>
                  <th className="text-left px-3 py-2">Resultado</th>
                  <th className="text-left px-3 py-2">Medida ENS</th>
                  <th className="text-left px-3 py-2">Detalle</th>
                </tr>
              </thead>
              <tbody>
                {controls.map((ctrl, idx) => (
                  <tr key={ctrl.id} className={`border-b border-[#1e2530]/50 ${idx % 2 === 0 ? 'bg-[#0f1117]/30' : ''}`}>
                    <td className="px-3 py-2 text-slate-500 font-mono">{idx + 1}</td>
                    <td className="px-3 py-2 text-slate-200">{ctrl.nombre || CONTROLS_MAP[idx]?.nombre}</td>
                    <td className="px-3 py-2"><ResultBadge resultado={ctrl.resultado} /></td>
                    <td className="px-3 py-2 font-mono text-[#00d4ff] text-xs">{ctrl.medida_ens || CONTROLS_MAP[idx]?.medida_ens}</td>
                    <td className="px-3 py-2 text-slate-400 text-xs max-w-xs truncate" title={ctrl.detalle}>{ctrl.detalle || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 flex justify-end">
            <Button
              variant="outline"
              size="sm"
              className="gap-2 border-[#1e2530] text-slate-300 hover:text-white hover:border-[#00d4ff]/50"
              onClick={() => window.open(`http://localhost:8007/report/hardening/${result.asset_id}`, '_blank')}
            >
              <FileText className="w-4 h-4" />
              Generar Informe PDF
            </Button>
          </div>
        </CardContent>
      )}
    </Card>
  );
}

export function BastionadoPage() {
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

  useEffect(() => {
    fetch('http://localhost:8001/api/v1/assets', { headers: authHeaders() })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: Asset[]) => setAssets(data))
      .catch(() => setAssetsError('No se pudo cargar la lista de activos'));
  }, []);

  const stopPolling = useCallback(() => {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    pollTimerRef.current = null;
  }, []);

  const poll = useCallback((id: string) => {
    fetch(`http://localhost:8002/api/v1/hardening/status/${id}`, { headers: authHeaders() })
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
          if (data.results) {
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
          setPollingError('Se perdió la conexión con el servidor de bastionado después de 3 intentos');
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
      const res = await fetch('http://localhost:8002/api/v1/hardening/run', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ asset_ids: Array.from(selectedIds) }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail ?? JSON.stringify(err));
      }
      const data = await res.json();
      setTaskId(data.task_id ?? data.id ?? String(data));
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

  return (
    <TooltipProvider>
      <div className="flex-1 overflow-y-auto bg-[#0f1117] min-h-screen">
        <div className="max-w-6xl mx-auto p-6 space-y-6">

          {/* SECCIÓN 1 — Cabecera */}
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#00d4ff]/10 border border-[#00d4ff]/20 flex items-center justify-center">
                <Shield className="w-5 h-5 text-[#00d4ff]" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">Bastionado ENS</h1>
                <p className="text-sm text-slate-400">Verificación trimestral de controles de bastionado — RD 311/2022</p>
              </div>
            </div>
            {lastCycle ? (
              <Badge variant="outline" className="border-[#00d4ff]/30 text-[#00d4ff] text-xs">
                Último ciclo: {new Date(lastCycle).toLocaleDateString('es-ES')}
              </Badge>
            ) : (
              <Badge variant="outline" className="border-slate-600 text-slate-400 text-xs">
                Sin verificaciones previas
              </Badge>
            )}
          </div>

          {/* SECCIÓN 2 — Panel de ejecución */}
          <Card className="bg-[#1a1d27] border-[#1e2530]">
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
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {assets.map(asset => {
                    const disabled = !asset.ssh_user;
                    const checked = selectedIds.has(asset.id);
                    return (
                      <div key={asset.id} className={`flex items-center gap-3 p-3 rounded-lg border transition-colors ${
                        disabled
                          ? 'border-[#1e2530] opacity-50 cursor-not-allowed'
                          : checked
                          ? 'border-[#00d4ff]/30 bg-[#00d4ff]/5'
                          : 'border-[#1e2530] hover:border-[#1e2530]/80 hover:bg-[#0f1117]/40 cursor-pointer'
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
                                className="border-slate-600 data-[state=checked]:bg-[#00d4ff] data-[state=checked]:border-[#00d4ff]"
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
                          <span className="text-sm text-white font-medium">{asset.name}</span>
                          <span className="text-xs text-slate-400 ml-2">{asset.ip_address}</span>
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
              )}

              <div className="flex justify-end pt-2">
                <Button
                  disabled={selectedIds.size === 0 || running}
                  onClick={handleRun}
                  className="gap-2 bg-[#00d4ff] hover:bg-[#00b8d9] text-[#0f1117] font-semibold disabled:opacity-50"
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

          {/* SECCIÓN 3 — Resultados */}
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
