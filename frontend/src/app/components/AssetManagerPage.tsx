import { useState, useCallback, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  Server, ShieldAlert, KeyRound, Plus, RefreshCw, AlertCircle,
  Play, Loader2, Eye, Info, Terminal, Monitor, HelpCircle, ChevronDown, ChevronRight, ExternalLink,
  Copy, Check, Lock, Pencil, Save, Trash2, Maximize2, ShieldX,
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

const M1_BASE = 'http://localhost:8001/api/v1';
const M2_BASE = 'http://localhost:8003/api/v1';

const fmt = new Intl.DateTimeFormat('es-ES', {
  day: '2-digit', month: 'short', year: 'numeric',
  hour: '2-digit', minute: '2-digit',
});

function authHeader(): HeadersInit {
  const token = getStoredToken();
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };
}

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

const severityClass = (sev: string) => {
  switch (sev.toUpperCase()) {
    case 'CRITICAL': return 'text-[#ff3b3b] border-[#ff3b3b]/30 bg-[#ff3b3b]/10';
    case 'HIGH':     return 'text-[#f59e0b] border-[#f59e0b]/30 bg-[#f59e0b]/10';
    case 'MEDIUM':   return 'text-[#00d4ff] border-[#00d4ff]/30 bg-[#00d4ff]/10';
    default:         return 'text-[#6b7280] border-[#374151] bg-[#374151]/20';
  }
};

const vulnSeverityClass = (sev: string) => {
  switch (sev.toUpperCase()) {
    case 'CRITICAL': return 'text-[#ff3b3b] border-[#ff3b3b]/30 bg-[#ff3b3b]/10';
    case 'HIGH':     return 'text-[#f59e0b] border-[#f59e0b]/30 bg-[#f59e0b]/10';
    case 'MEDIUM':   return 'text-[#fbbf24] border-[#fbbf24]/30 bg-[#fbbf24]/10';
    case 'LOW':      return 'text-[#00d4ff] border-[#00d4ff]/30 bg-[#00d4ff]/10';
    default:         return 'text-[#6b7280] border-[#374151] bg-[#374151]/20';
  }
};

// Shadow IT Tab ──────────────────────────────────────────────────────────────

interface ShadowITTabProps {
  onRegisterAsset: (ip: string) => void;
  registeredAssets: { ip: string; status: string }[];
}

function ShadowITTab({ onRegisterAsset, registeredAssets }: ShadowITTabProps) {
  const { snapshots, alreadyRegistered, loading, error, refetch } = useShadowIT(registeredAssets);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [rescanState, setRescanState] = useState<Record<string, RowState>>({});
  const [registeredExpanded, setRegisteredExpanded] = useState(false);
  const [blacklistDialogOpen, setBlacklistDialogOpen] = useState(false);
  const [blacklistTarget, setBlacklistTarget] = useState<string>('');
  const [blacklistMotivo, setBlacklistMotivo] = useState('');
  const [blacklistLoading, setBlacklistLoading] = useState(false);
  const [blacklistError, setBlacklistError] = useState<string | null>(null);
  const [blacklistSuccess, setBlacklistSuccess] = useState<string | null>(null);

  const handleRescan = async (snap: M2Snapshot) => {
    setRescanState(prev => ({ ...prev, [snap.snapshot_id]: { status: 'scanning' } }));
    try {
      const token = getStoredToken();
      const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
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

  const toggleRow = (id: string) => setExpandedRow(prev => (prev === id ? null : id));

  const handleBlacklistIP = async () => {
    if (!blacklistMotivo.trim()) { setBlacklistError('El motivo es obligatorio'); return; }
    const isValidIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(blacklistTarget) || /^[0-9a-fA-F:]+$/.test(blacklistTarget);
    if (!isValidIP) {
      setBlacklistError('M1 solo acepta direcciones IP. Para bloquear un dominio, registra su IP.');
      return;
    }
    setBlacklistLoading(true);
    setBlacklistError(null);
    try {
      const res = await fetch(`${M1_BASE}/assets`, {
        method: 'POST',
        headers: authHeader(),
        body: JSON.stringify({
          ip: blacklistTarget,
          tipo: 'OTRO',
          criticidad: 'ALTA',
          status: 'BLOQUEADA',
          responsable: 'sistema',
          notas: `BLOQUEADA — ${blacklistMotivo}`,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        const detail = (err as any).detail;
        if (Array.isArray(detail)) {
          throw { detail };
        }
        throw new Error(typeof detail === 'string' ? detail : `Error ${res.status}`);
      }
      setBlacklistDialogOpen(false);
      setBlacklistMotivo('');
      refetch();
      setBlacklistSuccess(`IP ${blacklistTarget} añadida a lista negra`);
      setTimeout(() => setBlacklistSuccess(null), 4000);
    } catch (e: any) {
      if (Array.isArray(e?.detail)) {
        setBlacklistError(e.detail.map((d: any) => d.msg).join(' · '));
      } else {
        setBlacklistError(e?.message ?? e?.detail ?? 'Error al bloquear la IP');
      }
    } finally {
      setBlacklistLoading(false);
    }
  };

  const blockedCount = alreadyRegistered.filter(s => s.isBlacklisted).length;

  return (
    <div className="space-y-3">
      {blockedCount > 0 && (
        <div className="flex items-center gap-2 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg px-4 py-2.5">
          <ShieldX className="w-4 h-4 text-[#ff3b3b] shrink-0" />
          <span className="text-sm text-[#ff3b3b]">
            {blockedCount} IP(s) en lista negra detectadas en la red
          </span>
        </div>
      )}

      {blacklistSuccess && (
        <div className="flex items-center gap-2 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded-lg px-4 py-2.5">
          <ShieldX className="w-4 h-4 text-[#22c55e] shrink-0" />
          <span className="text-sm text-[#22c55e]">{blacklistSuccess}</span>
        </div>
      )}

      <div className="flex items-start gap-3 bg-[#00d4ff]/5 border border-[#00d4ff]/20 rounded-lg px-4 py-3 text-sm text-[#9ca3af]">
        <Info className="w-4 h-4 text-[#00d4ff] shrink-0 mt-0.5" />
        <span>
          Hosts descubiertos por M2 (Nmap) no registrados en el inventario oficial.
          Clasificar como activo conocido o marcar como no autorizado.
        </span>
      </div>

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
                  No hay dispositivos descubiertos sin registrar.
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
                        if ((e.target as HTMLElement).closest('button')) return;
                        toggleRow(snap.snapshot_id);
                      }}
                    >
                      <td className="px-4 py-4 text-[#6b7280]">
                        {isExpanded
                          ? <ChevronDown className="w-3.5 h-3.5" />
                          : <ChevronRight className="w-3.5 h-3.5" />}
                      </td>

                      <td className="px-4 py-4">
                        <div className="text-white font-mono">{snap.target}</div>
                        <div className="text-xs text-[#6b7280] mt-0.5">{snap.snapshot_id}</div>
                      </td>

                      <td className="px-4 py-4">
                        <div className="flex items-center gap-1.5">
                          <OsIcon os={snap.os_family} />
                          <span className={snap.os_family ? 'text-[#9ca3af] text-xs' : 'text-[#6b7280] text-xs'}>
                            {snap.os_family ?? 'Desconocido'}
                          </span>
                        </div>
                      </td>

                      <td className="px-4 py-4">
                        {snap.ports_open ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded bg-[#1e2530] text-white text-xs font-mono">
                            {snap.ports_open}
                          </span>
                        ) : (
                          <span className="text-[#6b7280] text-xs">—</span>
                        )}
                      </td>

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

                      <td className="px-4 py-4 text-xs text-[#9ca3af] whitespace-nowrap">
                        {fmt.format(new Date(snap.created_at))}
                      </td>

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
                          <button
                            onClick={() => {
                              setBlacklistTarget(snap.target);
                              setBlacklistMotivo('');
                              setBlacklistError(null);
                              setBlacklistDialogOpen(true);
                            }}
                            className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] rounded-lg hover:bg-[#ff3b3b]/20 transition-colors"
                          >
                            <ShieldX className="w-3.5 h-3.5" />
                            Bloquear
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

      {alreadyRegistered.length > 0 && (
        <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg overflow-hidden">
          <button
            onClick={() => setRegisteredExpanded(prev => !prev)}
            className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-[#1e2530]/40 transition-colors"
          >
            {registeredExpanded
              ? <ChevronDown className="w-3.5 h-3.5 text-[#6b7280]" />
              : <ChevronRight className="w-3.5 h-3.5 text-[#6b7280]" />}
            <span className="text-xs text-[#6b7280]">
              IPs descubiertas ya en inventario ({alreadyRegistered.length})
            </span>
          </button>
          {registeredExpanded && (
            <table className="w-full text-sm text-left border-t border-[#1e2530]">
              <thead className="text-xs text-[#6b7280] uppercase bg-[#111318]">
                <tr>
                  <th className="px-4 py-2 font-semibold">IP</th>
                  <th className="px-4 py-2 font-semibold">Estado</th>
                  <th className="px-4 py-2 font-semibold">Acciones</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2530]">
                {alreadyRegistered.map(s => (
                  <tr key={s.snapshot_id} className="hover:bg-[#1e2530]/40">
                    <td className="px-4 py-2.5 font-mono text-white text-xs">{s.target}</td>
                    <td className="px-4 py-2.5">
                      {s.isBlacklisted ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] border-[#ff3b3b]/30 bg-[#ff3b3b]/10 text-[#ff3b3b]">
                          <ShieldX className="w-3 h-3" />BLOQUEADA
                        </span>
                      ) : s.registeredStatus === 'ACTIVO' ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded border text-[10px] border-[#22c55e]/30 bg-[#22c55e]/10 text-[#22c55e]">
                          ACTIVO
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded border text-[10px] border-[#374151] bg-[#374151]/10 text-[#6b7280]">
                          {s.registeredStatus ?? 'REGISTRADO'}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <button
                        onClick={() => onRegisterAsset(s.target)}
                        className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] rounded-lg hover:text-white transition-colors"
                      >
                        <ExternalLink className="w-3 h-3" />
                        Ver en inventario
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      <Dialog.Root
        open={blacklistDialogOpen}
        onOpenChange={(open) => { setBlacklistDialogOpen(open); if (!open) { setBlacklistMotivo(''); setBlacklistError(null); } }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50" />
          <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-sm bg-[#1a1d27] border border-[#ff3b3b]/30 rounded-lg p-6 shadow-2xl z-50">
            <Dialog.Title className="text-base font-semibold text-white mb-2 flex items-center gap-2">
              <ShieldX className="w-4 h-4 text-[#ff3b3b]" />
              Añadir a lista negra
            </Dialog.Title>
            <Dialog.Description className="text-sm text-[#9ca3af] mb-4">
              La IP <span className="font-mono text-white">{blacklistTarget}</span> será registrada como BLOQUEADA en el inventario.
              Quedará registrada en los logs de auditoría (ENS op.exp.1).
              Esta acción indica que la IP es sospechosa o no autorizada en la red.
            </Dialog.Description>
            <div className="mb-4">
              <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">
                Motivo del bloqueo <span className="text-[#ff3b3b]">*</span>
              </label>
              <input
                type="text"
                value={blacklistMotivo}
                onChange={e => { setBlacklistMotivo(e.target.value); setBlacklistError(null); }}
                className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#6b7280] focus:outline-none focus:border-[#ff3b3b] transition-colors"
                placeholder="ej. IP desconocida escaneando la red"
              />
              {blacklistError && <p className="text-xs text-[#ff3b3b] mt-1">{blacklistError}</p>}
            </div>
            <div className="flex gap-3">
              <button
                onClick={handleBlacklistIP}
                disabled={blacklistLoading}
                className="flex-1 flex items-center justify-center gap-2 py-2 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] hover:bg-[#ff3b3b]/20 font-semibold rounded-lg transition-colors disabled:opacity-60 disabled:cursor-not-allowed text-sm"
              >
                {blacklistLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldX className="w-4 h-4" />}
                Bloquear IP
              </button>
              <Dialog.Close asChild>
                <button className="px-5 bg-[#374151] hover:bg-[#4b5563] text-white font-semibold py-2 rounded-lg transition-colors text-sm">
                  Cancelar
                </button>
              </Dialog.Close>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}

// Vault Tab ──────────────────────────────────────────────────────────────────

interface VaultEntry {
  asset: string;
  type: string;
  ref: string;
  rotated: string;
}

const VAULT_ENTRIES: VaultEntry[] = [
  { asset: '10.202.15.15',  type: 'SSH Private Key',  ref: 'secret/scanops/assets/10/ssh_key',    rotated: '2026-05-13T10:00:00Z' },
  { asset: '10.202.15.100', type: 'SSH Password',      ref: 'secret/scanops/assets/1/ssh_pass',    rotated: '2026-05-13T10:00:00Z' },
  { asset: '10.202.15.15',  type: 'API Token M3',      ref: 'secret/scanops/scanner/api_token',    rotated: '2026-05-01T08:00:00Z' },
  { asset: 'Global',        type: 'MSF RPC Password',  ref: 'secret/scanops/msf/rpc_password',     rotated: '2026-04-20T12:00:00Z' },
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

// Dynamic form fields ────────────────────────────────────────────────────────

type FieldDef = {
  key: string;
  label: string;
  type: 'text' | 'select';
  placeholder?: string;
  options?: string[];
  fullWidth?: boolean;
};

function getFieldsForTipo(tipo: string): FieldDef[] {
  switch (tipo) {
    case 'SERVER': return [
      { key: 'os_family',    label: 'OS Family',     type: 'select', options: ['Linux', 'Windows', 'FreeBSD', 'Other'] },
      { key: 'os_version',   label: 'OS Version',    type: 'text',   placeholder: 'ej. Ubuntu 22.04 LTS' },
      { key: 'dominio',      label: 'Dominio',       type: 'text',   placeholder: 'ej. corp.scanops.local', fullWidth: true },
      { key: 'network_range',label: 'Network Range', type: 'text',   placeholder: 'ej. 10.202.15.0/24',    fullWidth: true },
      { key: 'departamento', label: 'Departamento',  type: 'text',   placeholder: 'ej. Sistemas' },
      { key: 'ubicacion',    label: 'Ubicación',     type: 'text',   placeholder: 'ej. Rack A-01 · CPD Madrid' },
    ];
    case 'ENDPOINT': return [
      { key: 'os_family',        label: 'OS Family',        type: 'select', options: ['Linux', 'Windows', 'macOS', 'Other'] },
      { key: 'os_version',       label: 'OS Version',       type: 'text',   placeholder: 'ej. Windows 11 Pro' },
      { key: 'departamento',     label: 'Departamento',     type: 'text',   placeholder: 'ej. RRHH' },
      { key: 'usuario_asignado', label: 'Usuario asignado', type: 'text',   placeholder: 'ej. juan.garcia@empresa.es' },
      { key: 'ubicacion',        label: 'Ubicación',        type: 'text',   placeholder: 'ej. Oficina B · Planta 2' },
    ];
    case 'RED': return [
      { key: 'mac_address',  label: 'MAC Address',   type: 'text', placeholder: 'ej. AA:BB:CC:DD:EE:FF' },
      { key: 'network_range',label: 'Network Range', type: 'text', placeholder: 'ej. 192.168.1.0/24',    fullWidth: true },
      { key: 'fabricante',   label: 'Fabricante',    type: 'text', placeholder: 'ej. Cisco / Fortinet' },
      { key: 'ubicacion',    label: 'Ubicación',     type: 'text', placeholder: 'ej. Rack B-02 · CPD Madrid' },
    ];
    case 'APLICACION': return [
      { key: 'dominio',      label: 'Dominio',           type: 'text',   placeholder: 'ej. app.scanops.local', fullWidth: true },
      { key: 'entorno',      label: 'Entorno',           type: 'select', options: ['Producción', 'Staging', 'Desarrollo'] },
      { key: 'departamento', label: 'Departamento',      type: 'text',   placeholder: 'ej. Desarrollo' },
      { key: 'os_version',   label: 'Stack tecnológico', type: 'text',   placeholder: 'ej. React + FastAPI' },
    ];
    case 'IOT': return [
      { key: 'mac_address',  label: 'MAC Address',  type: 'text', placeholder: 'ej. AA:BB:CC:DD:EE:FF' },
      { key: 'fabricante',   label: 'Fabricante',   type: 'text', placeholder: 'ej. Siemens / Honeywell' },
      { key: 'departamento', label: 'Departamento', type: 'text', placeholder: 'ej. Planta Industrial' },
      { key: 'ubicacion',    label: 'Ubicación',    type: 'text', placeholder: 'ej. Sala de servidores · Planta 0' },
    ];
    default: return [];
  }
}

// Main Page ──────────────────────────────────────────────────────────────────

const SCAN_TOOLS = ['nikto', 'nuclei', 'nmap'] as const;

type EditForm = {
  hostname: string;
  nombre: string;
  tipo: string;
  criticidad: string;
  responsable: string;
  status: string;
  notas: string;
};

const defaultEditForm = (): EditForm => ({
  hostname: '', nombre: '', tipo: 'SERVER', criticidad: 'MEDIA', responsable: '', status: 'ACTIVO', notas: '',
});

type NewAssetForm = {
  ip: string;
  hostname: string;
  nombre: string;
  tipo: string;
  criticidad: string;
  responsable: string;
  dominio: string;
  mac_address: string;
  network_range: string;
  os_family: string;
  os_version: string;
  departamento: string;
  ubicacion: string;
  entorno: string;
  fabricante: string;
  usuario_asignado: string;
  notas: string;
};

const emptyNewAssetForm = (): NewAssetForm => ({
  ip: '', hostname: '', nombre: '', tipo: 'SERVER', criticidad: 'MEDIA', responsable: '',
  dominio: '', mac_address: '', network_range: '', os_family: '', os_version: '',
  departamento: '', ubicacion: '', entorno: '', fabricante: '', usuario_asignado: '',
  notas: '',
});

export function AssetManagerPage() {
  const { assets, loading, error, refetch, createAsset, scanAsset, getVulnResults, pollScanStatus } = useAssets();
  const navigate = useNavigate();
  const location = useLocation();
  const [activeTab, setActiveTab] = useState('cmdb');

  useEffect(() => { refetch(); }, [location.pathname]);

  // Per-row scan state + tool selection
  const [rowState, setRowState] = useState<Record<number, RowState>>({});
  const [rowTool, setRowTool] = useState<Record<number, string>>({});

  // Sheet (asset detail)
  const [sheetOpen, setSheetOpen] = useState(false);
  const [sheetAsset, setSheetAsset] = useState<Asset | null>(null);
  const [sheetVulns, setSheetVulns] = useState<VulnResult[]>([]);
  const [sheetVulnsLoading, setSheetVulnsLoading] = useState(false);
  const [fullScanState, setFullScanState] = useState<RowState>({ status: 'idle' });

  // Sheet inline edit
  const [editingAsset, setEditingAsset] = useState(false);
  const [editForm, setEditForm] = useState<EditForm>(defaultEditForm());
  const [editSaving, setEditSaving] = useState(false);
  const [sheetToast, setSheetToast] = useState<{ msg: string; ok: boolean } | null>(null);

  // Delete
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);

  // Create dialog
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newAssetForm, setNewAssetForm] = useState<NewAssetForm>(emptyNewAssetForm());
  const [newAssetErrors, setNewAssetErrors] = useState<{ ip?: string; responsable?: string }>({});
  const [newAssetSubmitting, setNewAssetSubmitting] = useState(false);
  const [createApiError, setCreateApiError] = useState<string | null>(null);

  const handleScan = useCallback(async (asset: Asset, tool: string) => {
    setRowState(prev => ({ ...prev, [asset.id]: { status: 'scanning', msg: 'Iniciando...' } }));
    try {
      const task = await scanAsset(asset.id, [tool]);
      setRowState(prev => ({ ...prev, [asset.id]: { status: 'scanning', msg: 'Escaneando...' } }));
      const result = await pollScanStatus(task.task_id, asset.id,
        (msg) => setRowState(prev => ({ ...prev, [asset.id]: { status: 'scanning', msg } }))
      );
      if (result.status === 'SUCCESS') {
        setRowState(prev => ({ ...prev, [asset.id]: {
          status: 'done',
          msg: `✓ Escaneo completado · ${result.findings_count} hallazgos · ${fmt.format(new Date())}`,
        }}));
      } else if (result.status === 'FAILED') {
        setRowState(prev => ({ ...prev, [asset.id]: { status: 'error', msg: '✗ Escaneo fallido' } }));
      } else {
        setRowState(prev => ({ ...prev, [asset.id]: { status: 'error', msg: '✗ Timeout — escaneo tardó demasiado' } }));
      }
    } catch (e: any) {
      setRowState(prev => ({ ...prev, [asset.id]: { status: 'error', msg: `✗ Error: ${e.message}` } }));
    } finally {
      setTimeout(() => setRowState(prev => ({ ...prev, [asset.id]: { status: 'idle' } })), 8000);
    }
  }, [scanAsset, pollScanStatus]);

  const handleOpenSheet = useCallback(async (asset: Asset) => {
    setSheetAsset(asset);
    setSheetVulns([]);
    setFullScanState({ status: 'idle' });
    setEditingAsset(false);
    setSheetToast(null);
    setDeleteDialogOpen(false);
    setEditForm({
      hostname: asset.hostname ?? '',
      nombre: asset.nombre ?? '',
      tipo: asset.tipo,
      criticidad: asset.criticidad,
      responsable: asset.responsable ?? '',
      status: asset.status,
      notas: (asset as any).notas ?? '',
    });
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

  const handleSaveAsset = useCallback(async () => {
    if (!sheetAsset) return;
    setEditSaving(true);
    try {
      const res = await fetch(`${M1_BASE}/assets/${sheetAsset.id}`, {
        method: 'PUT',
        headers: authHeader(),
        body: JSON.stringify({
          hostname: editForm.hostname || null,
          nombre: editForm.nombre || null,
          tipo: editForm.tipo,
          criticidad: editForm.criticidad,
          responsable: editForm.responsable,
          status: editForm.status,
          ...(editForm.notas ? { notas: editForm.notas } : {}),
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as any).detail ?? `Error ${res.status}`);
      }
      const updated: Asset = await res.json();
      setSheetAsset(updated);
      setEditingAsset(false);
      refetch();
      setSheetToast({ msg: 'Activo actualizado', ok: true });
      setTimeout(() => setSheetToast(null), 4000);
    } catch (e: any) {
      const msg = e?.detail ?? e?.message ?? 'Error al actualizar';
      setSheetToast({ msg, ok: false });
      setTimeout(() => setSheetToast(null), 4000);
    } finally {
      setEditSaving(false);
    }
  }, [sheetAsset, editForm, refetch]);

  const handleDeleteAsset = useCallback(async (id: number) => {
    setDeleteLoading(true);
    try {
      const res = await fetch(`${M1_BASE}/assets/${id}`, {
        method: 'DELETE',
        headers: authHeader(),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as any)?.detail ?? `HTTP ${res.status}`);
      }
      setDeleteDialogOpen(false);
      setSheetOpen(false);
      await refetch();
    } catch (e: any) {
      setDeleteDialogOpen(false);
      setSheetToast({ msg: e?.message ?? 'Error al eliminar', ok: false });
      setTimeout(() => setSheetToast(null), 4000);
    } finally {
      setDeleteLoading(false);
    }
  }, [refetch]);

  const handleFullScan = useCallback(async () => {
    if (!sheetAsset) return;
    setFullScanState({ status: 'scanning', msg: 'Iniciando...' });
    try {
      const task = await scanAsset(sheetAsset.id, ['nuclei', 'nikto']);
      setFullScanState({ status: 'scanning', msg: 'Escaneando...' });
      const result = await pollScanStatus(task.task_id, sheetAsset.id,
        (msg) => setFullScanState({ status: 'scanning', msg })
      );
      if (result.status === 'SUCCESS') {
        setFullScanState({ status: 'done', msg: `✓ Completado · ${result.findings_count} hallazgos · ${fmt.format(new Date())}` });
      } else if (result.status === 'FAILED') {
        setFullScanState({ status: 'error', msg: '✗ Escaneo fallido' });
      } else {
        setFullScanState({ status: 'error', msg: '✗ Timeout — escaneo tardó demasiado' });
      }
    } catch {
      setFullScanState({ status: 'error', msg: '✗ Error al lanzar escaneo' });
    }
  }, [scanAsset, sheetAsset, pollScanStatus]);

  const handleCreateAsset = useCallback(async () => {
    const errors: typeof newAssetErrors = {};
    if (!newAssetForm.ip.trim()) errors.ip = 'IP es obligatoria';
    if (!newAssetForm.responsable.trim()) errors.responsable = 'Responsable es obligatorio';
    if (Object.keys(errors).length) { setNewAssetErrors(errors); return; }
    setNewAssetSubmitting(true);
    try {
      const {
        ip, hostname, nombre, tipo, criticidad, responsable,
        dominio, mac_address, network_range, os_family, os_version,
        departamento, ubicacion, entorno, fabricante, usuario_asignado, notas,
      } = newAssetForm;

      const notasParts = [
        usuario_asignado.trim() && `Usuario: ${usuario_asignado.trim()}`,
        fabricante.trim()       && `Fabricante: ${fabricante.trim()}`,
        entorno.trim()          && `Entorno: ${entorno.trim()}`,
        notas.trim(),
      ].filter(Boolean) as string[];
      const notasValue = notasParts.length ? notasParts.join(' · ') : undefined;

      const rawPayload: Record<string, string | undefined> = {
        ip:            ip.trim(),
        hostname:      hostname.trim()      || undefined,
        nombre:        nombre.trim()        || undefined,
        tipo,
        criticidad,
        responsable:   responsable.trim(),
        dominio:       dominio.trim()       || undefined,
        mac_address:   mac_address.trim()   || undefined,
        network_range: network_range.trim() || undefined,
        os_family:     os_family            || undefined,
        os_version:    os_version.trim()    || undefined,
        departamento:  departamento.trim()  || undefined,
        ubicacion:     ubicacion.trim()     || undefined,
        notas:         notasValue,
      };

      const payload = Object.fromEntries(
        Object.entries(rawPayload).filter(([, v]) => v !== undefined),
      );

      await createAsset(payload as any);
      setCreateDialogOpen(false);
      setNewAssetForm(emptyNewAssetForm());
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
    setNewAssetForm(emptyNewAssetForm());
    setNewAssetErrors({});
    setCreateApiError(null);
  };

  const handleOpenCreateDialog = useCallback((ip?: string) => {
    resetCreateForm();
    if (ip) setNewAssetForm(prev => ({ ...prev, ip }));
    setCreateDialogOpen(true);
  }, []);

  const dynamicFields = getFieldsForTipo(newAssetForm.tipo);

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />

        <main className="flex-1 overflow-auto p-6 space-y-6">
          {/* Header */}
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

          {/* Tabs */}
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
                        const activeTool = rowTool[asset.id] ?? 'nikto';
                        return (
                          <tr
                            key={asset.id}
                            className="hover:bg-[#1e2530]/50 transition-colors cursor-pointer"
                            onClick={(e) => {
                              if ((e.target as HTMLElement).closest('button')) return;
                              handleOpenSheet(asset);
                            }}
                          >
                            <td className="px-6 py-4 font-mono text-[#6b7280]">{asset.id}</td>
                            <td className="px-6 py-4">
                              <div className="text-white font-mono">{asset.ip}</div>
                              <div className="text-xs text-[#9ca3af] mt-0.5">{asset.hostname || 'Sin hostname'}</div>
                              {asset.nombre
                                ? <span className="text-xs text-[#9ca3af]">{asset.nombre}</span>
                                : null}
                            </td>
                            <td className="px-6 py-4">
                              <Badge variant="outline" className={`border ${
                                asset.criticidad === 'CRITICA' ? 'text-[#ff3b3b] border-[#ff3b3b]/30 bg-[#ff3b3b]/10' :
                                asset.criticidad === 'ALTA'    ? 'text-[#f59e0b] border-[#f59e0b]/30 bg-[#f59e0b]/10' :
                                'text-[#00d4ff] border-[#00d4ff]/30 bg-[#00d4ff]/10'
                              }`}>
                                {asset.criticidad}
                              </Badge>
                            </td>
                            <td className="px-6 py-4 text-[#9ca3af]">{asset.tipo}</td>
                            <td className="px-6 py-4 text-white">{asset.responsable}</td>
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-1.5">
                                <div className={`w-1.5 h-1.5 rounded-full ${
                                  asset.status === 'ACTIVO'         ? 'bg-[#22c55e]' :
                                  asset.status === 'MANTENIMIENTO'  ? 'bg-[#f59e0b]' :
                                  asset.status === 'PENDIENTE_ALTA' ? 'bg-[#00d4ff]' :
                                  'bg-[#6b7280]'
                                }`} />
                                <span className="text-xs text-[#9ca3af]">{asset.status}</span>
                              </div>
                            </td>
                            <td className="px-6 py-4">
                              <div className="flex flex-col gap-1.5">
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  {/* Tool toggles */}
                                  {SCAN_TOOLS.map((tool) => (
                                    <button
                                      key={tool}
                                      onClick={(e) => { e.stopPropagation(); setRowTool(prev => ({ ...prev, [asset.id]: tool })); }}
                                      className={`px-2 py-0.5 text-xs rounded border cursor-pointer transition-colors ${
                                        activeTool === tool
                                          ? 'border-[#00d4ff]/50 text-[#00d4ff] bg-[#00d4ff]/10'
                                          : 'border-[#1e2530] text-[#6b7280] bg-[#1a1d27] hover:border-[#374151] hover:text-[#9ca3af]'
                                      }`}
                                    >
                                      {tool}
                                    </button>
                                  ))}
                                  {/* Scan button */}
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleScan(asset, activeTool); }}
                                    disabled={rs.status === 'scanning'}
                                    className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] rounded-lg hover:bg-[#00d4ff]/20 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                                  >
                                    {rs.status === 'scanning'
                                      ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                      : <Play className="w-3.5 h-3.5" />}
                                    Escanear
                                  </button>
                                  {/* View button */}
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleOpenSheet(asset); }}
                                    className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#1e2530]/50 border border-[#1e2530] text-[#9ca3af] rounded-lg hover:bg-[#1e2530] hover:text-white transition-colors"
                                  >
                                    <Eye className="w-3.5 h-3.5" />
                                    Ver
                                  </button>
                                </div>
                                {rs.status === 'scanning' && rs.msg && (
                                  <div className="text-xs text-[#00d4ff] font-mono truncate max-w-[240px] animate-pulse">{rs.msg}</div>
                                )}
                                {rs.status === 'done' && rs.msg && (
                                  <div className="text-xs text-[#22c55e] font-mono truncate max-w-[240px]">{rs.msg}</div>
                                )}
                                {rs.status === 'error' && rs.msg && (
                                  <div className="text-xs text-[#ff3b3b] font-mono">{rs.msg}</div>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </TabsContent>

            <TabsContent value="shadow" className="mt-4">
              <ShadowITTab
                onRegisterAsset={(ip) => handleOpenCreateDialog(ip)}
                registeredAssets={assets}
              />
            </TabsContent>
            <TabsContent value="vault" className="mt-4">
              <VaultTab />
            </TabsContent>
          </Tabs>
        </main>
      </div>

      {/* ── Sheet: Asset Detail ── */}
      <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
        <SheetContent className="bg-[#1a1d27] border-l border-[#1e2530] text-white w-[600px] sm:max-w-[600px] overflow-y-auto">
          <SheetHeader className="pb-4 border-b border-[#1e2530]">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <SheetTitle className="text-white font-mono text-lg">
                  {sheetAsset?.ip ?? '—'}
                </SheetTitle>
                <p className="text-xs text-[#9ca3af]">{sheetAsset?.hostname || 'Sin hostname'}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => sheetAsset && navigate(`/assets/${sheetAsset.id}`)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] rounded-lg hover:text-white hover:bg-[#2a3040] transition-colors"
                >
                  <Maximize2 className="w-3.5 h-3.5" />
                  Vista completa
                </button>
                <button
                  onClick={() => setDeleteDialogOpen(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] rounded-lg hover:bg-[#ff3b3b]/20 transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Eliminar
                </button>
              </div>
            </div>
          </SheetHeader>

          {sheetAsset && (
            <div className="p-4 space-y-6">

              {/* Sheet inline toast */}
              {sheetToast && (
                <div className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm ${
                  sheetToast.ok
                    ? 'bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e]'
                    : 'bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b]'
                }`}>
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  {sheetToast.msg}
                </div>
              )}

              {/* ── Sección 1: Información del activo ── */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Información del activo</span>
                  {!editingAsset ? (
                    <button
                      onClick={() => setEditingAsset(true)}
                      className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] rounded-lg hover:text-white transition-colors"
                    >
                      <Pencil className="w-3.5 h-3.5" />
                      Editar
                    </button>
                  ) : (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleSaveAsset}
                        disabled={editSaving}
                        className="flex items-center gap-1.5 px-2.5 py-1 text-xs bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] rounded-lg hover:bg-[#22c55e]/20 transition-colors disabled:opacity-60"
                      >
                        {editSaving
                          ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          : <Save className="w-3.5 h-3.5" />}
                        Guardar
                      </button>
                      <button
                        onClick={() => {
                          setEditingAsset(false);
                          setEditForm({
                            hostname: sheetAsset.hostname ?? '',
                            nombre: sheetAsset.nombre ?? '',
                            tipo: sheetAsset.tipo,
                            criticidad: sheetAsset.criticidad,
                            responsable: sheetAsset.responsable ?? '',
                            status: sheetAsset.status,
                            notas: (sheetAsset as any).notas ?? '',
                          });
                        }}
                        className="px-2.5 py-1 text-xs bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] rounded-lg hover:text-white transition-colors"
                      >
                        Cancelar
                      </button>
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-3">
                  {/* IP — always readonly */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5 flex items-center gap-1.5">
                      IP
                      <span className="text-[10px] text-[#6b7280] bg-[#0f1117] border border-[#1e2530] px-1.5 py-0.5 rounded font-mono normal-case tracking-normal">Inmutable</span>
                    </div>
                    <div className="text-white font-mono text-xs">{sheetAsset.ip}</div>
                  </div>

                  {/* Hostname */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">Hostname</div>
                    {editingAsset ? (
                      <input
                        value={editForm.hostname}
                        onChange={e => setEditForm(p => ({ ...p, hostname: e.target.value }))}
                        className="bg-[#0f1117] border border-[#1e2530] rounded px-3 py-1.5 text-sm text-white w-full focus:outline-none focus:border-[#00d4ff] transition-colors font-mono"
                        placeholder="servidor-01.local"
                      />
                    ) : (
                      <div className="text-white font-mono text-xs">{sheetAsset.hostname || '—'}</div>
                    )}
                  </div>

                  {/* Nombre */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">Nombre personalizado</div>
                    {editingAsset ? (
                      <input
                        value={editForm.nombre}
                        onChange={e => setEditForm(p => ({ ...p, nombre: e.target.value }))}
                        className="bg-[#0f1117] border border-[#1e2530] rounded px-3 py-1.5 text-sm text-white w-full focus:outline-none focus:border-[#00d4ff] transition-colors"
                        placeholder="ej. Servidor Principal BBDD"
                      />
                    ) : (
                      <div className="text-white text-xs">{sheetAsset.nombre || '—'}</div>
                    )}
                  </div>

                  {/* Tipo */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">Tipo</div>
                    {editingAsset ? (
                      <select
                        value={editForm.tipo}
                        onChange={e => setEditForm(p => ({ ...p, tipo: e.target.value }))}
                        className="bg-[#0f1117] border border-[#1e2530] rounded px-3 py-1.5 text-sm text-white w-full focus:outline-none focus:border-[#00d4ff] transition-colors"
                      >
                        <option value="SERVER">SERVER</option>
                        <option value="ENDPOINT">ENDPOINT</option>
                        <option value="RED">RED</option>
                        <option value="APLICACION">APLICACION</option>
                        <option value="IOT">IOT</option>
                        <option value="OTRO">OTRO</option>
                      </select>
                    ) : (
                      <div className="text-white text-xs">{sheetAsset.tipo}</div>
                    )}
                  </div>

                  {/* Criticidad */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">Criticidad</div>
                    {editingAsset ? (
                      <select
                        value={editForm.criticidad}
                        onChange={e => setEditForm(p => ({ ...p, criticidad: e.target.value }))}
                        className="bg-[#0f1117] border border-[#1e2530] rounded px-3 py-1.5 text-sm text-white w-full focus:outline-none focus:border-[#00d4ff] transition-colors"
                      >
                        <option value="BAJA">BAJA</option>
                        <option value="MEDIA">MEDIA</option>
                        <option value="ALTA">ALTA</option>
                        <option value="CRITICA">CRITICA</option>
                      </select>
                    ) : (
                      <Badge variant="outline" className={`border text-xs w-fit ${severityClass(sheetAsset.criticidad)}`}>
                        {sheetAsset.criticidad}
                      </Badge>
                    )}
                  </div>

                  {/* Responsable */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">Responsable</div>
                    {editingAsset ? (
                      <input
                        value={editForm.responsable}
                        onChange={e => setEditForm(p => ({ ...p, responsable: e.target.value }))}
                        className="bg-[#0f1117] border border-[#1e2530] rounded px-3 py-1.5 text-sm text-white w-full focus:outline-none focus:border-[#00d4ff] transition-colors"
                        placeholder="admin@empresa.es"
                      />
                    ) : (
                      <div className="text-white text-xs">{sheetAsset.responsable || '—'}</div>
                    )}
                  </div>

                  {/* Estado */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">Estado</div>
                    {editingAsset ? (
                      <select
                        value={editForm.status}
                        onChange={e => setEditForm(p => ({ ...p, status: e.target.value }))}
                        className="bg-[#0f1117] border border-[#1e2530] rounded px-3 py-1.5 text-sm text-white w-full focus:outline-none focus:border-[#00d4ff] transition-colors"
                      >
                        <option value="ACTIVO">ACTIVO</option>
                        <option value="BAJA">BAJA</option>
                        <option value="MANTENIMIENTO">MANTENIMIENTO</option>
                        <option value="PENDIENTE_ALTA">PENDIENTE_ALTA</option>
                      </select>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <div className={`w-1.5 h-1.5 rounded-full ${
                          sheetAsset.status === 'ACTIVO'         ? 'bg-[#22c55e]' :
                          sheetAsset.status === 'MANTENIMIENTO'  ? 'bg-[#f59e0b]' :
                          sheetAsset.status === 'PENDIENTE_ALTA' ? 'bg-[#00d4ff]' :
                          'bg-[#6b7280]'
                        }`} />
                        <span className="text-xs text-[#9ca3af]">{sheetAsset.status}</span>
                      </div>
                    )}
                  </div>

                  {/* Notas — full width */}
                  <div className="col-span-2">
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">Notas</div>
                    {editingAsset ? (
                      <textarea
                        value={editForm.notas}
                        onChange={e => setEditForm(p => ({ ...p, notas: e.target.value }))}
                        rows={3}
                        className="bg-[#0f1117] border border-[#1e2530] rounded px-3 py-1.5 text-sm text-white w-full focus:outline-none focus:border-[#00d4ff] transition-colors resize-none"
                        placeholder="Observaciones adicionales..."
                      />
                    ) : (
                      <div className="text-xs text-[#9ca3af]">{(sheetAsset as any).notas || '—'}</div>
                    )}
                  </div>
                </div>
              </div>

              {/* ── Sección 2: Resultados de escaneo ── */}
              <div className="border-t border-[#1e2530] pt-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Resultados de escaneo</span>
                  {sheetVulns.length > 0 && (
                    <span className="px-2 py-0.5 rounded-full bg-[#1e2530] text-xs text-[#9ca3af] font-mono">{sheetVulns.length}</span>
                  )}
                </div>

                {sheetVulnsLoading ? (
                  <div className="flex items-center gap-2 text-xs text-[#6b7280] py-2">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" /> Cargando resultados...
                  </div>
                ) : sheetVulns.length === 0 ? (
                  <p className="text-xs text-[#6b7280] py-2">Sin resultados de escaneo. Lanza un escaneo desde el inventario.</p>
                ) : (
                  <div className="space-y-2">
                    {sheetVulns.slice(0, 10).map((v) => (
                      <div key={v.id} className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-3 space-y-1.5">
                        <div className="flex items-start gap-2 justify-between">
                          <div className="flex items-center gap-2 flex-1 min-w-0">
                            <span className={`shrink-0 text-[10px] px-2 py-0.5 rounded border font-semibold ${vulnSeverityClass(v.severity)}`}>
                              {v.severity}
                            </span>
                            <span className="text-xs text-white truncate">{v.title}</span>
                          </div>
                          <span className="shrink-0 text-[10px] px-1.5 py-0.5 rounded bg-[#1e2530] text-[#6b7280] font-mono">
                            {v.tool_source}
                          </span>
                        </div>
                        <div className="flex items-center gap-3">
                          {v.cve_id && (
                            <span className="text-[10px] font-mono text-[#00d4ff]">{v.cve_id}</span>
                          )}
                          <span className="text-[10px] text-[#6b7280]">{sheetAsset.ip}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <button
                  onClick={handleFullScan}
                  disabled={fullScanState.status === 'scanning'}
                  className="flex items-center gap-2 px-4 py-2 bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] hover:text-white rounded-lg text-sm transition-colors disabled:opacity-60 disabled:cursor-not-allowed w-full justify-center"
                >
                  {fullScanState.status === 'scanning'
                    ? <Loader2 className="w-4 h-4 animate-spin" />
                    : <Play className="w-4 h-4" />}
                  Lanzar escaneo completo
                </button>
                {fullScanState.status === 'done' && (
                  <p className="text-xs text-[#22c55e] text-center font-mono">{fullScanState.msg}</p>
                )}
                {fullScanState.status === 'error' && (
                  <p className="text-xs text-[#ff3b3b] text-center font-mono">{fullScanState.msg}</p>
                )}
              </div>

              {/* ── Sección 3: Metadatos ENS ── */}
              <div className="border-t border-[#1e2530] pt-4 space-y-3">
                <span className="text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Trazabilidad ENS Alto</span>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  {([
                    ['ID interno', String(sheetAsset.id)],
                    ['Fecha de registro', (sheetAsset as any).created_at ? fmt.format(new Date((sheetAsset as any).created_at)) : '—'],
                    ['Última actualización', (sheetAsset as any).updated_at ? fmt.format(new Date((sheetAsset as any).updated_at)) : '—'],
                    ['Descubierto por', (sheetAsset as any).discovered_by ?? 'Registro manual'],
                    ['Fuente externa', (sheetAsset as any).external_source ?? '—'],
                    ['Rango de red', (sheetAsset as any).network_range ?? '—'],
                  ] as [string, string][]).map(([label, value]) => (
                    <div key={label}>
                      <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">{label}</div>
                      <div className="text-white font-mono">{value}</div>
                    </div>
                  ))}
                </div>
                <p className="text-[10px] text-[#6b7280]">
                  Registro auditado bajo ENS op.exp.1 · RD 311/2022
                </p>
              </div>

            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* ── Dialog: Confirmar eliminación ── */}
      <Dialog.Root open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50" />
          <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-sm bg-[#1a1d27] border border-[#ff3b3b]/30 rounded-lg p-6 shadow-2xl z-50">
            <Dialog.Title className="text-base font-semibold text-white mb-2 flex items-center gap-2">
              <Trash2 className="w-4 h-4 text-[#ff3b3b]" />
              Confirmar eliminación
            </Dialog.Title>
            <Dialog.Description className="text-sm text-[#9ca3af] mb-5">
              Esta acción eliminará el activo{' '}
              <span className="font-mono text-white">{sheetAsset?.ip}</span>{' '}
              del inventario. La operación quedará registrada en los logs de auditoría (ENS op.exp.1).
            </Dialog.Description>
            <div className="flex gap-3">
              <button
                onClick={() => sheetAsset && handleDeleteAsset(sheetAsset.id)}
                disabled={deleteLoading}
                className="flex-1 flex items-center justify-center gap-2 py-2 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] hover:bg-[#ff3b3b]/20 font-semibold rounded-lg transition-colors disabled:opacity-60 disabled:cursor-not-allowed text-sm"
              >
                {deleteLoading
                  ? <Loader2 className="w-4 h-4 animate-spin" />
                  : <Trash2 className="w-4 h-4" />}
                Eliminar activo
              </button>
              <Dialog.Close asChild>
                <button className="px-5 bg-[#374151] hover:bg-[#4b5563] text-white font-semibold py-2 rounded-lg transition-colors text-sm">
                  Cancelar
                </button>
              </Dialog.Close>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* ── Dialog: Nuevo Activo ── */}
      <Dialog.Root
        open={createDialogOpen}
        onOpenChange={(open) => { setCreateDialogOpen(open); if (!open) resetCreateForm(); }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50" />
          <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-[#1a1d27] border border-[#1e2530] rounded-lg shadow-2xl z-50">
            <div className="p-6 overflow-y-auto max-h-[80vh]">
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

                {/* Nombre personalizado */}
                <div>
                  <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">Nombre personalizado</label>
                  <input
                    type="text"
                    value={newAssetForm.nombre}
                    onChange={e => setNewAssetForm(p => ({ ...p, nombre: e.target.value }))}
                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] transition-colors"
                    placeholder="ej. Servidor Principal BBDD"
                  />
                </div>

                {/* Tipo + Criticidad */}
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">Tipo</label>
                    <select
                      value={newAssetForm.tipo}
                      onChange={e => {
                        const newTipo = e.target.value;
                        setNewAssetForm(p => ({
                          ...p,
                          tipo: newTipo,
                          dominio: '', mac_address: '', network_range: '', os_family: '',
                          os_version: '', departamento: '', ubicacion: '', entorno: '',
                          fabricante: '', usuario_asignado: '',
                        }));
                      }}
                      className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#00d4ff] transition-colors"
                    >
                      <option value="SERVER">SERVER</option>
                      <option value="ENDPOINT">ENDPOINT</option>
                      <option value="RED">RED</option>
                      <option value="APLICACION">APLICACION</option>
                      <option value="IOT">IOT</option>
                      <option value="OTRO">OTRO</option>
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

                {/* Dynamic fields */}
                {dynamicFields.length > 0 && (
                  <div className="border-t border-[#1e2530] pt-3">
                    <p className="text-xs text-[#6b7280] mb-3">Detalles específicos — {newAssetForm.tipo}</p>
                    <div className="grid grid-cols-2 gap-3">
                      {dynamicFields.map((field) => (
                        <div key={field.key} className={field.fullWidth ? 'col-span-2' : ''}>
                          <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">{field.label}</label>
                          {field.type === 'select' ? (
                            <select
                              value={(newAssetForm as any)[field.key]}
                              onChange={e => setNewAssetForm(p => ({ ...p, [field.key]: e.target.value }))}
                              className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#00d4ff] transition-colors"
                            >
                              <option value="">— Seleccionar —</option>
                              {field.options?.map(o => (
                                <option key={o} value={o}>{o}</option>
                              ))}
                            </select>
                          ) : (
                            <input
                              type="text"
                              value={(newAssetForm as any)[field.key]}
                              onChange={e => setNewAssetForm(p => ({ ...p, [field.key]: e.target.value }))}
                              placeholder={field.placeholder}
                              className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] transition-colors"
                            />
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Notas — always at the bottom */}
                <div>
                  <label className="block text-sm font-medium text-[#e5e7eb] mb-1.5">Notas</label>
                  <textarea
                    value={newAssetForm.notas}
                    onChange={e => setNewAssetForm(p => ({ ...p, notas: e.target.value }))}
                    rows={2}
                    className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] transition-colors resize-none"
                    placeholder="Observaciones adicionales..."
                  />
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
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
