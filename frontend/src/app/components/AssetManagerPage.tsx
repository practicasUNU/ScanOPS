import { useState, useCallback } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  Server, ShieldAlert, KeyRound, Plus, RefreshCw, AlertCircle,
  Play, Loader2, Eye, Info, Terminal, Monitor, HelpCircle, ChevronDown, ChevronRight,
  Copy, Check, Lock,
} from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Badge } from './ui/badge';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from './ui/sheet';
import * as Dialog from '@radix-ui/react-dialog';
import { useAssets, type Asset, type VulnResult } from '../../hooks/useAssets';
import { useShadowIT, type M2Snapshot } from '../../hooks/useShadowIT';
import { getStoredToken } from '../../hooks/useAuth';

type RowStatus = 'idle' | 'scanning' | 'done' | 'error';
interface RowState { status: RowStatus; msg?: string }

const M2_BASE = 'http://localhost:8003/api/v1';

const fmt = new Intl.DateTimeFormat('es-ES', {
  day: '2-digit', month: 'short', year: 'numeric',
  hour: '2-digit', minute: '2-digit',
});

function serviceBadgeClass(service: string) {
  const s = service.toLowerCase();
  if (['telnet', 'ftp', 'msrpc', 'netbios-ssn', 'netbios', 'microsoft-ds', 'ms-wbt-server'].some(k => s.includes(k))) {
    return 'border-[#ff3b3b]/40 text-[#ff3b3b] bg-[#ff3b3b]/5';
  }
  if (['ssh', 'http', 'https', 'mysql'].some(k => s.includes(k))) {
    return 'border-[#00d4ff]/40 text-[#00d4ff] bg-[#00d4ff]/5';
  }
  return 'border-[#374151] text-[#6b7280] bg-[#374151]/10';
}

function OsIcon({ os }: { os?: string | null }) {
  if (!os) return <HelpCircle className="w-3.5 h-3.5 text-[#6b7280] shrink-0" />;
  if (os.toLowerCase().includes('linux')) return <Terminal className="w-3.5 h-3.5 text-[#00d4ff] shrink-0" />;
  if (os.toLowerCase().includes('windows')) return <Monitor className="w-3.5 h-3.5 text-[#00d4ff] shrink-0" />;
  return <HelpCircle className="w-3.5 h-3.5 text-[#6b7280] shrink-0" />;
}

interface ShadowITTabProps {
  onRegisterAsset: (ip: string) => void;
}

function ShadowITTab({ onRegisterAsset }: ShadowITTabProps) {
  const { snapshots, loading, error, refetch } = useShadowIT();
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [rescanState, setRescanState] = useState<Record<string, RowState>>({});

  const handleRescan = async (snap: M2Snapshot) => {
    setRescanState(prev => ({ ...prev, [snap.snapshot_id]: { status: 'scanning' } }));
    try {
      const token = getStoredToken();
      const headers: HeadersInit = token
        ? { 'Authorization': `Bearer ${token}` }
        : {};
      const res = await fetch(`${M2_BASE}/scan?target=${encodeURIComponent(snap.target)}`, {
        method: 'POST',
        headers,
      });
      if (!res.ok) throw new Error(`Error ${res.status}`);
      setRescanState(prev => ({ ...prev, [snap.snapshot_id]: { status: 'done', msg: 'Escaneo iniciado' } }));
      refetch();
    } catch {
      setRescanState(prev => ({ ...prev, [snap.snapshot_id]: { status: 'error', msg: 'Error al re-escanear' } }));
    }
    setTimeout(() => {
      setRescanState(prev => ({ ...prev, [snap.snapshot_id]: { status: 'idle' } }));
    }, 3000);
  };

  const toggleRow = (id: string) => {
    setExpandedRow(prev => (prev === id ? null : id));
  };

  return (
    <div className="space-y-3">
      {/* Banner informativo */}
      <div className="flex items-start gap-3 bg-[#00d4ff]/5 border border-[#00d4ff]/20 rounded-lg px-4 py-3 text-sm text-[#9ca3af]">
        <Info className="w-4 h-4 text-[#00d4ff] shrink-0 mt-0.5" />
        <span>
          Hosts descubiertos por M2 (Nmap) no registrados en el inventario oficial.
          Clasificar como activo conocido o marcar como no autorizado.
        </span>
      </div>

      {/* Banner error M2 */}
      {error && (
        <div className="flex items-center gap-2 bg-[#f59e0b]/10 border border-[#f59e0b]/30 rounded-lg px-4 py-3 text-sm text-[#f59e0b]">
          <AlertCircle className="w-4 h-4 shrink-0" />
          M2 no disponible — mostrando datos de demostración
        </div>
      )}

      <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg overflow-hidden">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-[#6b7280] uppercase bg-[#111318] border-b border-[#1e2530]">
            <tr>
              <th className="px-4 py-3 font-semibold w-6"></th>
              <th className="px-4 py-3 font-semibold">IP / Target</th>
              <th className="px-4 py-3 font-semibold">OS</th>
              <th className="px-4 py-3 font-semibold">Puertos</th>
              <th className="px-4 py-3 font-semibold">Servicios</th>
              <th className="px-4 py-3 font-semibold">Último escaneo</th>
              <th className="px-4 py-3 font-semibold">Estado</th>
              <th className="px-4 py-3 font-semibold">Acciones</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1e2530]">
            {loading ? (
              <tr>
                <td colSpan={8} className="px-6 py-8 text-center text-[#6b7280] font-mono">
                  <Loader2 className="w-4 h-4 animate-spin inline mr-2" />
                  Cargando datos M2...
                </td>
              </tr>
            ) : snapshots.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-6 py-8 text-center text-[#6b7280] font-mono">
                  No hay dispositivos descubiertos.
                </td>
              </tr>
            ) : (
              snapshots.map((snap) => {
                const isExpanded = expandedRow === snap.snapshot_id;
                const rs = rescanState[snap.snapshot_id] ?? { status: 'idle' };
                const visiblePorts = snap.ports?.slice(0, 3) ?? [];
                const extraPorts = (snap.ports?.length ?? 0) - 3;

                return (
                  <>
                    <tr
                      key={snap.snapshot_id}
                      className="hover:bg-[#1e2530]/40 transition-colors cursor-pointer"
                      onClick={(e) => {
                        const target = e.target as HTMLElement;
                        if (target.closest('button')) return;
                        toggleRow(snap.snapshot_id);
                      }}
                    >
                      {/* Expand chevron */}
                      <td className="px-4 py-4 text-[#6b7280]">
                        {isExpanded
                          ? <ChevronDown className="w-3.5 h-3.5" />
                          : <ChevronRight className="w-3.5 h-3.5" />}
                      </td>

                      {/* IP / Target */}
                      <td className="px-4 py-4">
                        <div className="text-white font-mono">{snap.target}</div>
                        <div className="text-xs text-[#6b7280] mt-0.5">{snap.snapshot_id}</div>
                      </td>

                      {/* OS */}
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-1.5">
                          <OsIcon os={snap.os_family} />
                          <span className={snap.os_family ? 'text-[#9ca3af] text-xs' : 'text-[#6b7280] text-xs'}>
                            {snap.os_family ?? 'Desconocido'}
                          </span>
                        </div>
                      </td>

                      {/* Puertos abiertos */}
                      <td className="px-4 py-4">
                        {snap.ports_open ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded bg-[#1e2530] text-white text-xs font-mono">
                            {snap.ports_open}
                          </span>
                        ) : (
                          <span className="text-[#6b7280] text-xs">—</span>
                        )}
                      </td>

                      {/* Servicios */}
                      <td className="px-4 py-4">
                        <div className="flex flex-wrap gap-1">
                          {visiblePorts.map((p) => (
                            <span
                              key={p.port}
                              className={`inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-mono ${serviceBadgeClass(p.service)}`}
                            >
                              {p.service || String(p.port)}
                            </span>
                          ))}
                          {extraPorts > 0 && (
                            <span className="text-[10px] text-[#6b7280] self-center">+{extraPorts} más</span>
                          )}
                        </div>
                      </td>

                      {/* Último escaneo */}
                      <td className="px-4 py-4 text-xs text-[#9ca3af] whitespace-nowrap">
                        {fmt.format(new Date(snap.created_at))}
                      </td>

                      {/* Estado */}
                      <td className="px-4 py-4">
                        {snap.status === 'completed' && (
                          <div className="flex items-center gap-1.5">
                            <div className="w-1.5 h-1.5 rounded-full bg-[#22c55e]" />
                            <span className="text-xs text-[#9ca3af]">Completado</span>
                          </div>
                        )}
                        {snap.status === 'running' && (
                          <div className="flex items-center gap-1.5">
                            <div className="w-1.5 h-1.5 rounded-full bg-[#f59e0b] animate-pulse" />
                            <span className="text-xs text-[#9ca3af]">Escaneando...</span>
                          </div>
                        )}
                        {snap.status === 'failed' && (
                          <div className="flex items-center gap-1.5">
                            <div className="w-1.5 h-1.5 rounded-full bg-[#ff3b3b]" />
                            <span className="text-xs text-[#9ca3af]">Error</span>
                          </div>
                        )}
                        {!['completed', 'running', 'failed'].includes(snap.status) && (
                          <span className="text-xs text-[#6b7280]">{snap.status}</span>
                        )}
                      </td>

                      {/* Acciones */}
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => onRegisterAsset(snap.target)}
                            className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] rounded-lg hover:bg-[#22c55e]/20 transition-colors"
                          >
                            <Plus className="w-3.5 h-3.5" />
                            Registrar en M1
                          </button>
                          <button
                            onClick={() => handleRescan(snap)}
                            disabled={rs.status === 'scanning'}
                            className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] rounded-lg hover:text-white transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                          >
                            {rs.status === 'scanning'
                              ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              : <RefreshCw className="w-3.5 h-3.5" />}
                            Re-escanear
                          </button>
                        </div>
                        {rs.status === 'done' && rs.msg && (
                          <div className="mt-1 text-xs text-[#22c55e] font-mono">{rs.msg}</div>
                        )}
                        {rs.status === 'error' && rs.msg && (
                          <div className="mt-1 text-xs text-[#ff3b3b] font-mono">{rs.msg}</div>
                        )}
                      </td>
                    </tr>

                    {/* Fila expandible */}
                    {isExpanded && (
                      <tr key={`${snap.snapshot_id}-expanded`} className="bg-[#0f1117]">
                        <td colSpan={8} className="px-8 py-4">
                          {!snap.ports || snap.ports.length === 0 ? (
                            <p className="text-xs text-[#6b7280] font-mono">Sin datos de puertos disponibles.</p>
                          ) : (
                            <table className="w-full text-xs text-left">
                              <thead>
                                <tr className="text-[#6b7280] uppercase">
                                  <th className="pr-6 py-1 font-semibold">Puerto</th>
                                  <th className="pr-6 py-1 font-semibold">Protocolo</th>
                                  <th className="pr-6 py-1 font-semibold">Servicio</th>
                                  <th className="pr-6 py-1 font-semibold">Versión</th>
                                  <th className="pr-6 py-1 font-semibold">Estado</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-[#1e2530]/50">
                                {snap.ports.map((p) => (
                                  <tr key={p.port}>
                                    <td className="pr-6 py-1.5 font-mono text-white">{p.port}</td>
                                    <td className="pr-6 py-1.5 text-[#6b7280]">tcp</td>
                                    <td className="pr-6 py-1.5">
                                      <span className={`px-1.5 py-0.5 rounded border font-mono ${serviceBadgeClass(p.service)}`}>
                                        {p.service || '—'}
                                      </span>
                                    </td>
                                    <td className="pr-6 py-1.5 text-[#9ca3af] font-mono">{p.version || '—'}</td>
                                    <td className="pr-6 py-1.5">
                                      <div className="flex items-center gap-1.5">
                                        <div className={`w-1.5 h-1.5 rounded-full ${p.state === 'open' ? 'bg-[#22c55e]' : 'bg-[#6b7280]'}`} />
                                        <span className="text-[#9ca3af]">{p.state}</span>
                                      </div>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                        </td>
                      </tr>
                    )}
                  </>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

interface VaultEntry {
  asset: string;
  type: string;
  ref: string;
  rotated: string;
}

const VAULT_ENTRIES: VaultEntry[] = [
  { asset: '10.202.15.15',  type: 'SSH Private Key',   ref: 'secret/scanops/assets/10/ssh_key',     rotated: '2026-05-13T10:00:00Z' },
  { asset: '10.202.15.100', type: 'SSH Password',       ref: 'secret/scanops/assets/1/ssh_pass',     rotated: '2026-05-13T10:00:00Z' },
  { asset: '10.202.15.15',  type: 'API Token M3',       ref: 'secret/scanops/scanner/api_token',     rotated: '2026-05-01T08:00:00Z' },
  { asset: 'Global',        type: 'MSF RPC Password',   ref: 'secret/scanops/msf/rpc_password',      rotated: '2026-04-20T12:00:00Z' },
];

function VaultTab() {
  const [copiedRef, setCopiedRef] = useState<string | null>(null);
  const [maskedRow, setMaskedRow] = useState<string | null>(null);

  const handleCopy = (ref: string) => {
    navigator.clipboard.writeText(ref);
    setCopiedRef(ref);
    setTimeout(() => setCopiedRef(null), 2000);
  };

  return (
    <div className="space-y-3">
      {/* Banner */}
      <div className="flex items-start gap-3 bg-[#f59e0b]/5 border border-[#f59e0b]/20 rounded-lg px-4 py-3 text-sm text-[#9ca3af]">
        <Lock className="w-4 h-4 text-[#f59e0b] shrink-0 mt-0.5" />
        <span>
          Las credenciales están cifradas en HashiCorp Vault (AES-256).
          Este panel muestra referencias masked — nunca el secreto en claro.
          Acceso real requiere autenticación directa al Vault API (ENS mp.info.3).
        </span>
      </div>

      <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg overflow-hidden">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-[#6b7280] uppercase bg-[#111318] border-b border-[#1e2530]">
            <tr>
              <th className="px-6 py-3 font-semibold">Activo</th>
              <th className="px-6 py-3 font-semibold">Tipo de credencial</th>
              <th className="px-6 py-3 font-semibold">Referencia Vault</th>
              <th className="px-6 py-3 font-semibold">Última rotación</th>
              <th className="px-6 py-3 font-semibold">Acciones</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1e2530]">
            {VAULT_ENTRIES.map((entry) => (
              <>
                <tr key={entry.ref} className="hover:bg-[#1e2530]/40 transition-colors">
                  <td className="px-6 py-4 font-mono text-white">{entry.asset}</td>
                  <td className="px-6 py-4 text-[#9ca3af]">{entry.type}</td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-[#6b7280]">{entry.ref}</span>
                      <button
                        onClick={() => handleCopy(entry.ref)}
                        className="text-[#6b7280] hover:text-[#00d4ff] transition-colors shrink-0"
                        title="Copiar referencia"
                      >
                        {copiedRef === entry.ref
                          ? <Check className="w-3 h-3 text-[#22c55e]" />
                          : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-xs text-[#9ca3af]">
                    {fmt.format(new Date(entry.rotated))}
                  </td>
                  <td className="px-6 py-4">
                    {maskedRow === entry.ref ? (
                      <button
                        onClick={() => setMaskedRow(null)}
                        className="px-2.5 py-1 text-xs bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] rounded-lg hover:text-white transition-colors"
                      >
                        Cerrar
                      </button>
                    ) : (
                      <button
                        onClick={() => setMaskedRow(entry.ref)}
                        className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#f59e0b]/10 border border-[#f59e0b]/30 text-[#f59e0b] rounded-lg hover:bg-[#f59e0b]/20 transition-colors"
                      >
                        <Lock className="w-3.5 h-3.5" />
                        Ver masked
                      </button>
                    )}
                  </td>
                </tr>
                {maskedRow === entry.ref && (
                  <tr key={`${entry.ref}-masked`} className="bg-[#0f1117]">
                    <td colSpan={5} className="px-6 py-3">
                      <div className="flex items-center gap-3">
                        <input
                          type="password"
                          readOnly
                          value="••••••••••••••••"
                          className="font-mono text-sm bg-[#1a1d27] border border-[#1e2530] rounded px-3 py-1.5 text-[#9ca3af] w-48 focus:outline-none"
                        />
                        <span className="text-xs text-[#6b7280]">Valor enmascarado — solo referencia visible</span>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
        <div className="px-6 py-2.5 border-t border-[#1e2530] text-xs text-[#6b7280]">
          Vault path: http://localhost:8200 · Política: scanops-readonly · ENS mp.info.3
        </div>
      </div>
    </div>
  );
}

const severityClass = (sev: string) => {
  switch (sev.toUpperCase()) {
    case 'CRITICAL': return 'text-[#ff3b3b] border-[#ff3b3b]/30 bg-[#ff3b3b]/10';
    case 'HIGH': return 'text-[#f59e0b] border-[#f59e0b]/30 bg-[#f59e0b]/10';
    case 'MEDIUM': return 'text-[#00d4ff] border-[#00d4ff]/30 bg-[#00d4ff]/10';
    default: return 'text-[#6b7280] border-[#374151] bg-[#374151]/20';
  }
};

export function AssetManagerPage() {
  const { assets, loading, error, refetch, createAsset, scanAsset, getVulnResults } = useAssets();
  const [activeTab, setActiveTab] = useState('cmdb');

  // Row scan state
  const [rowState, setRowState] = useState<Record<number, RowState>>({});
  const [selectedTool, setSelectedTool] = useState('nikto');

  // Sheet (asset detail)
  const [sheetOpen, setSheetOpen] = useState(false);
  const [sheetAsset, setSheetAsset] = useState<Asset | null>(null);
  const [sheetVulns, setSheetVulns] = useState<VulnResult[]>([]);
  const [sheetVulnsLoading, setSheetVulnsLoading] = useState(false);
  const [fullScanState, setFullScanState] = useState<RowState>({ status: 'idle' });

  // Create dialog
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newAssetForm, setNewAssetForm] = useState({
    ip: '', hostname: '', tipo: 'SERVER', criticidad: 'MEDIA', responsable: '',
  });
  const [newAssetErrors, setNewAssetErrors] = useState<{ ip?: string; responsable?: string }>({});
  const [newAssetSubmitting, setNewAssetSubmitting] = useState(false);
  const [createApiError, setCreateApiError] = useState<string | null>(null);

  const handleScan = useCallback(async (asset: Asset) => {
    setRowState(prev => ({ ...prev, [asset.id]: { status: 'scanning' } }));
    try {
      const task = await scanAsset(asset.id, [selectedTool]);
      setRowState(prev => ({ ...prev, [asset.id]: { status: 'done', msg: `Escaneo iniciado · ${task.task_id}` } }));
    } catch {
      setRowState(prev => ({ ...prev, [asset.id]: { status: 'error', msg: 'Error al escanear' } }));
    }
    setTimeout(() => {
      setRowState(prev => ({ ...prev, [asset.id]: { status: 'idle' } }));
    }, 3000);
  }, [scanAsset, selectedTool]);

  const handleOpenSheet = useCallback(async (asset: Asset) => {
    setSheetAsset(asset);
    setSheetVulns([]);
    setFullScanState({ status: 'idle' });
    setSheetOpen(true);
    setSheetVulnsLoading(true);
    try {
      const vulns = await getVulnResults(asset.id);
      setSheetVulns(vulns);
    } catch {
      setSheetVulns([]);
    } finally {
      setSheetVulnsLoading(false);
    }
  }, [getVulnResults]);

  const handleFullScan = useCallback(async () => {
    if (!sheetAsset) return;
    setFullScanState({ status: 'scanning' });
    try {
      const task = await scanAsset(sheetAsset.id, ['nuclei', 'nikto']);
      setFullScanState({ status: 'done', msg: `Iniciado · ${task.task_id}` });
    } catch {
      setFullScanState({ status: 'error', msg: 'Error al lanzar escaneo' });
    }
  }, [scanAsset, sheetAsset]);

  const handleCreateAsset = useCallback(async () => {
    const errors: typeof newAssetErrors = {};
    if (!newAssetForm.ip.trim()) errors.ip = 'IP es obligatoria';
    if (!newAssetForm.responsable.trim()) errors.responsable = 'Responsable es obligatorio';
    if (Object.keys(errors).length) { setNewAssetErrors(errors); return; }
    setNewAssetSubmitting(true);
    try {
      await createAsset({
        ip: newAssetForm.ip.trim(),
        hostname: newAssetForm.hostname.trim() || undefined,
        tipo: newAssetForm.tipo,
        criticidad: newAssetForm.criticidad,
        responsable: newAssetForm.responsable.trim(),
      });
      setCreateDialogOpen(false);
      setNewAssetForm({ ip: '', hostname: '', tipo: 'SERVER', criticidad: 'MEDIA', responsable: '' });
      setNewAssetErrors({});
      refetch();
    } catch (e: any) {
      const msg = e?.detail ?? e?.message ?? (typeof e === 'string' ? e : 'Error al crear el activo');
      setCreateApiError(msg);
    } finally {
      setNewAssetSubmitting(false);
    }
  }, [createAsset, newAssetForm, refetch]);

  const resetCreateForm = () => {
    setNewAssetForm({ ip: '', hostname: '', tipo: 'SERVER', criticidad: 'MEDIA', responsable: '' });
    setNewAssetErrors({});
    setCreateApiError(null);
  };

  const handleOpenCreateDialog = useCallback((ip?: string) => {
    resetCreateForm();
    setCreateApiError(null);
    if (ip) setNewAssetForm(prev => ({ ...prev, ip }));
    setCreateDialogOpen(true);
  }, []);

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />

        <main className="flex-1 overflow-auto p-6 space-y-6">
          {/* Cabecera */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold text-white mb-1">Asset Manager (M1)</h1>
              <p className="text-[#9ca3af] text-sm">Inventario centralizado y gestión de credenciales (ENS op.exp.1)</p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={refetch}
                disabled={loading}
                className="flex items-center gap-2 px-3 py-2 bg-[#1a1d27] border border-[#1e2530] rounded-lg text-sm text-[#9ca3af] hover:text-white transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                Actualizar
              </button>
              <button
                onClick={() => handleOpenCreateDialog()}
                className="flex items-center gap-2 px-4 py-2 bg-[#00d4ff] hover:bg-[#00b8e6] text-[#0f1117] font-semibold rounded-lg transition-colors text-sm"
              >
                <Plus className="w-4 h-4" />
                Nuevo Activo
              </button>
            </div>
          </div>

          {error && (
            <div className="flex items-center gap-2 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 rounded-lg px-4 py-3 text-sm text-[#ff3b3b]">
              <AlertCircle className="w-4 h-4 shrink-0" />
              M1 API Error: {error}
            </div>
          )}

          {/* Navegación por Pestañas */}
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="bg-[#1a1d27] border border-[#1e2530] h-10 justify-start rounded-lg p-1">
              <TabsTrigger value="cmdb" className="flex items-center gap-2 text-xs data-[state=active]:bg-[#00d4ff]/10 data-[state=active]:text-[#00d4ff]">
                <Server className="w-3.5 h-3.5" /> Inventario Oficial
              </TabsTrigger>
              <TabsTrigger value="shadow" className="flex items-center gap-2 text-xs data-[state=active]:bg-[#f59e0b]/10 data-[state=active]:text-[#f59e0b]">
                <ShieldAlert className="w-3.5 h-3.5" /> Shadow IT (M2 Discovery)
              </TabsTrigger>
              <TabsTrigger value="vault" className="flex items-center gap-2 text-xs data-[state=active]:bg-[#22c55e]/10 data-[state=active]:text-[#22c55e]">
                <KeyRound className="w-3.5 h-3.5" /> Credenciales (Vault)
              </TabsTrigger>
            </TabsList>

            {/* TAB 1: Inventario Oficial */}
            <TabsContent value="cmdb" className="mt-4 space-y-3">
              {/* Tool selector */}
              <div className="flex items-center gap-3">
                <span className="text-xs text-[#6b7280]">Herramienta de escaneo:</span>
                <select
                  value={selectedTool}
                  onChange={e => setSelectedTool(e.target.value)}
                  className="bg-[#1a1d27] border border-[#1e2530] text-sm text-[#9ca3af] rounded-lg px-3 py-1.5 focus:outline-none focus:border-[#00d4ff] transition-colors"
                >
                  <option value="nikto">nikto</option>
                  <option value="nuclei">nuclei</option>
                  <option value="nmap">nmap</option>
                </select>
              </div>

              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg overflow-hidden">
                <table className="w-full text-sm text-left">
                  <thead className="text-xs text-[#6b7280] uppercase bg-[#111318] border-b border-[#1e2530]">
                    <tr>
                      <th className="px-6 py-3 font-semibold">ID</th>
                      <th className="px-6 py-3 font-semibold">Activo</th>
                      <th className="px-6 py-3 font-semibold">Criticidad</th>
                      <th className="px-6 py-3 font-semibold">Tipo</th>
                      <th className="px-6 py-3 font-semibold">Responsable</th>
                      <th className="px-6 py-3 font-semibold">Estado</th>
                      <th className="px-6 py-3 font-semibold">Acciones</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2530]">
                    {loading ? (
                      <tr><td colSpan={7} className="px-6 py-8 text-center text-[#6b7280] font-mono">Cargando inventario...</td></tr>
                    ) : assets.length === 0 ? (
                      <tr><td colSpan={7} className="px-6 py-8 text-center text-[#6b7280] font-mono">No hay activos registrados.</td></tr>
                    ) : (
                      assets.map((asset) => {
                        const rs = rowState[asset.id] ?? { status: 'idle' };
                        return (
                          <tr key={asset.id} className="hover:bg-[#1e2530]/50 transition-colors">
                            <td className="px-6 py-4 font-mono text-[#6b7280]">{asset.id}</td>
                            <td className="px-6 py-4">
                              <div className="text-white font-mono">{asset.ip}</div>
                              <div className="text-xs text-[#9ca3af] mt-0.5">{asset.hostname || 'Sin hostname'}</div>
                            </td>
                            <td className="px-6 py-4">
                              <Badge variant="outline" className={`border ${
                                asset.criticidad === 'CRITICA' ? 'text-[#ff3b3b] border-[#ff3b3b]/30 bg-[#ff3b3b]/10' :
                                asset.criticidad === 'ALTA' ? 'text-[#f59e0b] border-[#f59e0b]/30 bg-[#f59e0b]/10' :
                                'text-[#00d4ff] border-[#00d4ff]/30 bg-[#00d4ff]/10'
                              }`}>
                                {asset.criticidad}
                              </Badge>
                            </td>
                            <td className="px-6 py-4 text-[#9ca3af]">{asset.tipo}</td>
                            <td className="px-6 py-4 text-white">{asset.responsable}</td>
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-1.5">
                                <div className={`w-1.5 h-1.5 rounded-full ${asset.status === 'ACTIVO' ? 'bg-[#22c55e]' : 'bg-[#6b7280]'}`} />
                                <span className="text-xs text-[#9ca3af]">{asset.status}</span>
                              </div>
                            </td>
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-2">
                                {/* Scan button */}
                                <button
                                  onClick={() => handleScan(asset)}
                                  disabled={rs.status === 'scanning'}
                                  className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] rounded-lg hover:bg-[#00d4ff]/20 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                                >
                                  {rs.status === 'scanning' ? (
                                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                  ) : (
                                    <Play className="w-3.5 h-3.5" />
                                  )}
                                  Escanear
                                </button>
                                {/* View button */}
                                <button
                                  onClick={() => handleOpenSheet(asset)}
                                  className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#1e2530]/50 border border-[#1e2530] text-[#9ca3af] rounded-lg hover:bg-[#1e2530] hover:text-white transition-colors"
                                >
                                  <Eye className="w-3.5 h-3.5" />
                                  Ver
                                </button>
                              </div>
                              {/* Inline row feedback */}
                              {rs.status === 'done' && rs.msg && (
                                <div className="mt-1 text-xs text-[#22c55e] font-mono truncate max-w-[200px]">{rs.msg}</div>
                              )}
                              {rs.status === 'error' && rs.msg && (
                                <div className="mt-1 text-xs text-[#ff3b3b] font-mono">{rs.msg}</div>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </TabsContent>

            {/* TAB 2 y 3 */}
            <TabsContent value="shadow" className="mt-4">
              <ShadowITTab onRegisterAsset={(ip) => handleOpenCreateDialog(ip)} />
            </TabsContent>
            <TabsContent value="vault" className="mt-4">
              <VaultTab />
            </TabsContent>
          </Tabs>
        </main>
      </div>

      {/* ── Sheet: Asset Detail ── */}
      <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
        <SheetContent className="bg-[#1a1d27] border-l border-[#1e2530] text-white w-[420px] sm:max-w-[420px] overflow-y-auto">
          <SheetHeader className="pb-4 border-b border-[#1e2530]">
            <SheetTitle className="text-white font-mono text-lg">
              {sheetAsset?.ip ?? '—'}
            </SheetTitle>
            <p className="text-xs text-[#9ca3af]">{sheetAsset?.hostname || 'Sin hostname'}</p>
          </SheetHeader>

          {sheetAsset && (
            <div className="p-4 space-y-5">
              {/* Fields grid */}
              <div className="grid grid-cols-2 gap-3 text-sm">
                {[
                  ['ID', String(sheetAsset.id)],
                  ['IP', sheetAsset.ip],
                  ['Hostname', sheetAsset.hostname || '—'],
                  ['Tipo', sheetAsset.tipo],
                  ['Criticidad', sheetAsset.criticidad],
                  ['Responsable', sheetAsset.responsable || '—'],
                  ['Estado', sheetAsset.status],
                ].map(([label, value]) => (
                  <div key={label}>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">{label}</div>
                    <div className="text-white font-mono text-xs">{value}</div>
                  </div>
                ))}
              </div>

              {/* Vulns section */}
              <div className="border-t border-[#1e2530] pt-4 space-y-2">
                <div className="text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Últimas vulnerabilidades</div>
                {sheetVulnsLoading ? (
                  <div className="flex items-center gap-2 text-xs text-[#6b7280] py-2">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" /> Cargando resultados...
                  </div>
                ) : sheetVulns.length === 0 ? (
                  <p className="text-xs text-[#6b7280] py-2">Sin resultados de escaneo aún.</p>
                ) : (
                  <div className="space-y-1.5">
                    {sheetVulns.slice(0, 5).map((v) => (
                      <div key={v.id} className="flex items-center justify-between gap-2 py-1.5 px-2 rounded bg-[#0f1117]">
                        <span className="text-xs text-white truncate flex-1">{v.title}</span>
                        <span className={`shrink-0 text-[10px] px-2 py-0.5 rounded border font-semibold ${severityClass(v.severity)}`}>
                          {v.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Full scan button */}
              <div className="border-t border-[#1e2530] pt-4">
                <button
                  onClick={handleFullScan}
                  disabled={fullScanState.status === 'scanning'}
                  className="flex items-center gap-2 px-4 py-2 bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] hover:text-white rounded-lg text-sm transition-colors disabled:opacity-60 disabled:cursor-not-allowed w-full justify-center"
                >
                  {fullScanState.status === 'scanning' ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Play className="w-4 h-4" />
                  )}
                  Lanzar escaneo completo
                </button>
                {fullScanState.status === 'done' && (
                  <p className="text-xs text-[#22c55e] mt-1 text-center font-mono">{fullScanState.msg}</p>
                )}
                {fullScanState.status === 'error' && (
                  <p className="text-xs text-[#ff3b3b] mt-1 text-center font-mono">{fullScanState.msg}</p>
                )}
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* ── Dialog: Nuevo Activo ── */}
      <Dialog.Root
        open={createDialogOpen}
        onOpenChange={(open) => { setCreateDialogOpen(open); if (!open) resetCreateForm(); }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50" />
          <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6 shadow-2xl z-50">
            <Dialog.Title className="text-lg font-semibold text-white mb-1 flex items-center gap-2">
              <Plus className="w-4 h-4 text-[#00d4ff]" />
              Nuevo Activo
            </Dialog.Title>
            <Dialog.Description className="text-sm text-[#9ca3af] mb-5">
              Registrar un nuevo activo en el inventario (ENS op.exp.1)
            </Dialog.Description>

            <div className="space-y-4">
              {/* IP */}
              <div>
                <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">
                  IP <span className="text-[#ff3b3b]">*</span>
                </label>
                <input
                  type="text"
                  value={newAssetForm.ip}
                  onChange={e => { setNewAssetForm(p => ({ ...p, ip: e.target.value })); setNewAssetErrors(p => ({ ...p, ip: undefined })); }}
                  className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] transition-colors font-mono"
                  placeholder="192.168.1.1"
                />
                {newAssetErrors.ip && (
                  <p className="text-xs text-[#ff3b3b] mt-1">{newAssetErrors.ip}</p>
                )}
              </div>

              {/* Hostname */}
              <div>
                <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">Hostname</label>
                <input
                  type="text"
                  value={newAssetForm.hostname}
                  onChange={e => setNewAssetForm(p => ({ ...p, hostname: e.target.value }))}
                  className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] transition-colors font-mono"
                  placeholder="servidor-01.local"
                />
              </div>

              {/* Tipo + Criticidad */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">Tipo</label>
                  <select
                    value={newAssetForm.tipo}
                    onChange={e => setNewAssetForm(p => ({ ...p, tipo: e.target.value }))}
                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#00d4ff] transition-colors"
                  >
                    <option value="SERVER">SERVER</option>
                    <option value="WORKSTATION">WORKSTATION</option>
                    <option value="NETWORK_DEVICE">NETWORK_DEVICE</option>
                    <option value="WEB_APP">WEB_APP</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">Criticidad</label>
                  <select
                    value={newAssetForm.criticidad}
                    onChange={e => setNewAssetForm(p => ({ ...p, criticidad: e.target.value }))}
                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#00d4ff] transition-colors"
                  >
                    <option value="BAJA">BAJA</option>
                    <option value="MEDIA">MEDIA</option>
                    <option value="ALTA">ALTA</option>
                    <option value="CRITICA">CRITICA</option>
                  </select>
                </div>
              </div>

              {/* Responsable */}
              <div>
                <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">
                  Responsable <span className="text-[#ff3b3b]">*</span>
                </label>
                <input
                  type="text"
                  value={newAssetForm.responsable}
                  onChange={e => { setNewAssetForm(p => ({ ...p, responsable: e.target.value })); setNewAssetErrors(p => ({ ...p, responsable: undefined })); }}
                  className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] transition-colors"
                  placeholder="admin@empresa.es"
                />
                {newAssetErrors.responsable && (
                  <p className="text-xs text-[#ff3b3b] mt-1">{newAssetErrors.responsable}</p>
                )}
              </div>

              {createApiError && (
                <div className="flex items-center gap-2 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 rounded-lg px-3 py-2 text-sm text-[#ff3b3b]">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  {createApiError}
                </div>
              )}

              <div className="flex gap-3 pt-2">
                <button
                  onClick={handleCreateAsset}
                  disabled={newAssetSubmitting}
                  className="flex-1 bg-[#00d4ff] hover:bg-[#00b8e6] text-[#0f1117] font-semibold py-2.5 rounded-lg transition-colors disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {newAssetSubmitting && <Loader2 className="w-4 h-4 animate-spin" />}
                  Crear Activo
                </button>
                <Dialog.Close asChild>
                  <button className="px-6 bg-[#374151] hover:bg-[#4b5563] text-white font-semibold py-2.5 rounded-lg transition-colors">
                    Cancelar
                  </button>
                </Dialog.Close>
              </div>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
