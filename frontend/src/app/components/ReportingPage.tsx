import { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  BarChart3, FileCode, Shield, Archive, RefreshCw, Download,
  Loader2, AlertCircle,
} from 'lucide-react';

const M7_BASE = 'http://localhost:8007';

function getAuthHeader(): HeadersInit {
  try {
    const raw = sessionStorage.getItem('scanops_auth');
    const token = raw ? JSON.parse(raw)?.access_token : null;
    return token ? { Authorization: `Bearer ${token}` } : {};
  } catch {
    return {};
  }
}

async function blobDownload(url: string, filename: string): Promise<void> {
  const res = await fetch(url, { headers: getAuthHeader() });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const blob = await res.blob();
  const href = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = href;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(href);
}

interface ReportCard {
  id: string;
  icon: React.ElementType;
  color: string;
  title: string;
  description: string;
  endpoint: string;
  filename: string;
}

const REPORT_CARDS: ReportCard[] = [
  {
    id: 'executive',
    icon: BarChart3,
    color: '#00d4ff',
    title: 'Informe Ejecutivo',
    description: 'Métricas globales, score ENS, ROI y top vulnerabilidades.',
    endpoint: `${M7_BASE}/report/executive`,
    filename: 'ScanOps_Informe_Ejecutivo.pdf',
  },
  {
    id: 'technical',
    icon: FileCode,
    color: '#f59e0b',
    title: 'Informe Técnico',
    description: 'Cadena completa de evidencias M1+M2+M3+M4 con plan de remediación.',
    endpoint: `${M7_BASE}/report/technical`,
    filename: 'ScanOps_Informe_Tecnico.pdf',
  },
  {
    id: 'soa',
    icon: Shield,
    color: '#22c55e',
    title: 'Declaración de Aplicabilidad (SoA)',
    description: '73 medidas ENS Alto — estado de cumplimiento por control (RD 311/2022).',
    endpoint: `${M7_BASE}/report/soa`,
    filename: 'ScanOps_SoA_ENS_Alto.pdf',
  },
  {
    id: 'full-audit',
    icon: Archive,
    color: '#8b5cf6',
    title: 'Auditoría Completa (ZIP)',
    description: 'Paquete completo: 4 PDFs firmados + evidencias. Generación paralela asíncrona.',
    endpoint: `${M7_BASE}/report/full-audit`,
    filename: 'ScanOps_Auditoria_Completa.zip',
  },
];

const historyDateFmt = (name: string): string => {
  const m = name.match(/(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/);
  if (!m) return '—';
  return `${m[3]}/${m[2]}/${m[1]} ${m[4]}:${m[5]}`;
};

export function ReportingPage() {
  const [loadingMap, setLoadingMap] = useState<Record<string, boolean>>({});
  const [errorMap, setErrorMap] = useState<Record<string, string | null>>({});

  const [assets, setAssets] = useState<{id: number; ip: string; hostname: string | null}[]>([]);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [selectedAssetId, setSelectedAssetId] = useState<number | ''>('');
  const [assetReportLoading, setAssetReportLoading] = useState(false);
  const [assetReportError, setAssetReportError] = useState<string | null>(null);

  const [history, setHistory] = useState<string[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [dlLoading, setDlLoading] = useState<Record<string, boolean>>({});

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const res = await fetch(`${M7_BASE}/report/history`, { headers: getAuthHeader() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHistory(data.archivos ?? []);
    } catch (e) {
      setHistoryError(e instanceof Error ? e.message : 'Error al cargar historial');
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  useEffect(() => {
    setAssetsLoading(true);
    fetch('http://localhost:8001/api/v1/assets', { headers: getAuthHeader() })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        const list = Array.isArray(data) ? data : (data.assets ?? data.items ?? []);
        setAssets(list);
      })
      .catch(() => setAssets([]));
  }, []);

  const handleDownload = async (card: ReportCard) => {
    setLoadingMap(p => ({ ...p, [card.id]: true }));
    setErrorMap(p => ({ ...p, [card.id]: null }));
    try {
      await blobDownload(card.endpoint, card.filename);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Error desconocido';
      setErrorMap(p => ({ ...p, [card.id]: msg }));
      setTimeout(() => setErrorMap(p => ({ ...p, [card.id]: null })), 4000);
    } finally {
      setLoadingMap(p => ({ ...p, [card.id]: false }));
    }
  };

  const handleAssetReport = async () => {
    if (!selectedAssetId) return;
    setAssetReportLoading(true);
    setAssetReportError(null);
    try {
      const asset = assets.find(a => a.id === selectedAssetId);
      const filename = `ScanOps_Activo_${selectedAssetId}_${asset?.ip ?? 'report'}.pdf`;
      await blobDownload(`${M7_BASE}/report/asset/${selectedAssetId}`, filename);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Error generando informe';
      setAssetReportError(msg);
      setTimeout(() => setAssetReportError(null), 5000);
    } finally {
      setAssetReportLoading(false);
    }
  };

  const handleHistoryDownload = async (filename: string) => {
    setDlLoading(p => ({ ...p, [filename]: true }));
    try {
      await blobDownload(`${M7_BASE}/report/history/${encodeURIComponent(filename)}`, filename);
    } catch {
      // silent — no banner for history items
    } finally {
      setDlLoading(p => ({ ...p, [filename]: false }));
    }
  };

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="Auditor" />
        <main className="flex-1 overflow-auto p-6 space-y-8">

          {/* Header */}
          <div>
            <h1 className="text-2xl font-semibold text-white mb-1">Reporting Engine (M7)</h1>
            <p className="text-[#9ca3af] text-sm">
              Informes PDF firmados digitalmente · ENS mp.info.4 · AES-256
            </p>
          </div>

          {/* Generación de informes */}
          <section className="space-y-4">
            <h2 className="text-sm font-semibold text-[#9ca3af] uppercase tracking-wider">
              Generación de informes
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {REPORT_CARDS.map((card) => {
                const Icon = card.icon;
                const isLoading = loadingMap[card.id];
                const err = errorMap[card.id];
                return (
                  <div
                    key={card.id}
                    className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5 flex flex-col gap-4"
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
                        style={{ backgroundColor: `${card.color}1a` }}
                      >
                        <Icon className="w-5 h-5" style={{ color: card.color }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-semibold text-white">{card.title}</div>
                        <div className="text-xs text-[#9ca3af] mt-0.5">{card.description}</div>
                      </div>
                    </div>

                    <div className="mt-auto space-y-1.5">
                      <button
                        onClick={() => handleDownload(card)}
                        disabled={!!isLoading}
                        className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                        style={{
                          backgroundColor: `${card.color}1a`,
                          border: `1px solid ${card.color}4d`,
                          color: card.color,
                        }}
                        onMouseEnter={e => { if (!isLoading) (e.currentTarget as HTMLButtonElement).style.backgroundColor = `${card.color}33`; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.backgroundColor = `${card.color}1a`; }}
                      >
                        {isLoading
                          ? <><Loader2 className="w-4 h-4 animate-spin" /> Generando...</>
                          : <><Download className="w-4 h-4" /> Generar y Descargar</>}
                      </button>
                      {err && (
                        <div className="flex items-center gap-1.5 text-xs text-[#ff3b3b]">
                          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                          {err}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Informe por Activo */}
          <section className="space-y-4">
            <h2 className="text-sm font-semibold text-[#9ca3af] uppercase tracking-wider">
              Informe por Activo
            </h2>
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5 space-y-4">

              <div className="flex gap-3 items-center">
                <div className="flex-1">
                  <label className="text-xs text-[#9ca3af] mb-1.5 block">Seleccionar Activo (M1)</label>
                  <select
                    value={selectedAssetId}
                    onChange={e => setSelectedAssetId(Number(e.target.value) || '')}
                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2.5 text-white text-sm focus:outline-none focus:border-[#00d4ff] transition-colors"
                  >
                    <option value="">— Selecciona un activo —</option>
                    {assets.map(a => (
                      <option key={a.id} value={a.id}>
                        #{a.id} — {a.ip}{a.hostname ? ` (${a.hostname})` : ''}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  onClick={handleAssetReport}
                  disabled={!selectedAssetId || assetReportLoading}
                  className="mt-5 flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-colors disabled:opacity-60 disabled:cursor-not-allowed bg-[#f59e0b]/10 border border-[#f59e0b]/40 text-[#f59e0b] hover:bg-[#f59e0b]/20"
                >
                  {assetReportLoading
                    ? <><Loader2 className="w-4 h-4 animate-spin" /> Generando...</>
                    : <><Download className="w-4 h-4" /> Generar Informe PDF</>}
                </button>
              </div>

              <p className="text-xs text-[#6b7280]">
                Genera un informe PDF completo del activo seleccionado con datos de
                M1 (ficha), M2 (reconocimiento), M3 (vulnerabilidades),
                M8 (análisis IA), M4 (explotación) y M5 (eventos SIEM).
                Firmado AES-256 · ENS op.exp.2 + mp.info.4
              </p>

              {assetReportError && (
                <div className="flex items-center gap-1.5 text-xs text-[#ff3b3b]">
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  {assetReportError}
                </div>
              )}
            </div>
          </section>

          {/* Historial */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-[#9ca3af] uppercase tracking-wider">
                Historial de ciclos
              </h2>
              <button
                onClick={fetchHistory}
                disabled={historyLoading}
                className="flex items-center gap-2 px-3 py-1.5 bg-[#1a1d27] border border-[#1e2530] rounded-lg text-xs text-[#9ca3af] hover:text-white transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${historyLoading ? 'animate-spin' : ''}`} />
                Actualizar
              </button>
            </div>

            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg overflow-hidden">
              {historyLoading ? (
                <div className="flex items-center justify-center gap-2 py-10 text-[#6b7280]">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Cargando historial...</span>
                </div>
              ) : historyError || history.length === 0 ? (
                <div className="py-10 text-center text-sm text-[#6b7280] font-mono">
                  No hay informes históricos disponibles.
                </div>
              ) : (
                <table className="w-full text-sm text-left">
                  <thead className="text-xs text-[#6b7280] uppercase bg-[#111318] border-b border-[#1e2530]">
                    <tr>
                      <th className="px-6 py-3 font-semibold">Archivo</th>
                      <th className="px-6 py-3 font-semibold">Fecha</th>
                      <th className="px-6 py-3 font-semibold">Acciones</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2530]">
                    {history.map((filename) => (
                      <tr key={filename} className="hover:bg-[#1e2530]/40 transition-colors">
                        <td className="px-6 py-3 font-mono text-xs text-[#9ca3af]">{filename}</td>
                        <td className="px-6 py-3 text-xs text-[#6b7280]">
                          {historyDateFmt(filename)}
                        </td>
                        <td className="px-6 py-3">
                          <button
                            onClick={() => handleHistoryDownload(filename)}
                            disabled={!!dlLoading[filename]}
                            className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] rounded-lg hover:bg-[#00d4ff]/20 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                          >
                            {dlLoading[filename]
                              ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              : <Download className="w-3.5 h-3.5" />}
                            Descargar
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </section>

        </main>
      </div>
    </div>
  );
}
