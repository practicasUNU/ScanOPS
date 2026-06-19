import { useState, useEffect } from 'react';
import { useLocation } from 'react-router';
import {
  ShieldAlert, Clock, CheckCircle2, XCircle, AlertTriangle,
  RefreshCw, Zap, Eye, EyeOff, Copy,
} from 'lucide-react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { Badge } from './ui/badge';
import * as Dialog from '@radix-ui/react-dialog';
import { useResponseActions, approveAction, requestResponseAction } from '../../hooks/useEDR';
import { getStoredToken } from '../../hooks/useAuth';
import type { ResponseAction } from '../../hooks/useEDR';

// ── Helpers ────────────────────────────────────────────────────────────────────

function statusClass(s: string) {
  switch (s) {
    case 'pending':   return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    case 'approved':  return 'bg-green-500/15 text-green-400 border-green-500/30';
    case 'rejected':  return 'bg-red-500/15 text-red-400 border-red-500/30';
    case 'executing': return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    case 'completed': return 'bg-[#8B5CF6]/15 text-[#8B5CF6] border-[#8B5CF6]/30';
    case 'failed':    return 'bg-red-500/15 text-red-400 border-red-500/30';
    default:          return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  }
}

function actionLabel(type: string) {
  const map: Record<string, string> = {
    kill_process:     'Matar proceso',
    quarantine_file:  'Cuarentena fichero',
    block_ip:         'Bloquear IP',
    isolate_host:     'Aislar host',
    collect_forensics:'Recolectar forense',
  };
  return map[type] ?? type;
}

function getMe(): string {
  try {
    const raw = sessionStorage.getItem('scanops_auth');
    return raw ? (JSON.parse(raw)?.username ?? 'security_officer') : 'security_officer';
  } catch { return 'security_officer'; }
}

const fmt = new Intl.DateTimeFormat('es-ES', {
  day: '2-digit', month: 'short', year: 'numeric',
  hour: '2-digit', minute: '2-digit',
});

// ── TOTP+PIN Approval Modal ────────────────────────────────────────────────────

interface ApproveModalProps {
  action: ResponseAction;
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

function ApproveModal({ action, open, onClose, onSuccess }: ApproveModalProps) {
  const [totpCode, setTotpCode] = useState('');
  const [pin, setPin] = useState('');
  const [showPin, setShowPin] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const me = getMe();

  useEffect(() => {
    if (!open) { setTotpCode(''); setPin(''); setError(''); }
  }, [open]);

  const handleApprove = async () => {
    if (totpCode.length < 6) { setError('El código TOTP debe tener 6-8 dígitos'); return; }
    if (pin.length < 4)       { setError('El PIN debe tener al menos 4 caracteres'); return; }
    setSubmitting(true);
    setError('');
    const result = await approveAction(action.id, totpCode, pin, me);
    setSubmitting(false);
    if (result.ok) {
      onSuccess();
      onClose();
    } else {
      setError(result.message);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-full max-w-md bg-[#111318] border border-[#1C2030] rounded-xl shadow-2xl p-6 space-y-5">

          <div className="flex items-start gap-3">
            <div className="p-2 bg-red-500/10 rounded-lg">
              <ShieldAlert className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <Dialog.Title className="text-base font-semibold text-white">
                Confirmar acción de respuesta
              </Dialog.Title>
              <Dialog.Description className="text-xs text-[#475569] mt-0.5">
                Requiere verificación dual: TOTP + PIN
              </Dialog.Description>
            </div>
          </div>

          {/* Action summary */}
          <div className="bg-[#0A0C10] border border-[#1C2030] rounded-lg p-3 space-y-1.5 text-xs">
            <div className="flex gap-2">
              <span className="text-[#475569] w-20 shrink-0">Acción:</span>
              <span className="text-white font-medium">{actionLabel(action.action_type)}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-[#475569] w-20 shrink-0">Objetivo:</span>
              <span className="font-mono text-amber-400 truncate">{action.target_detail}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-[#475569] w-20 shrink-0">Solicitante:</span>
              <span className="text-[#64748B]">{action.requested_by}</span>
            </div>
          </div>

          {/* TOTP */}
          <div className="space-y-1.5">
            <label className="text-xs text-[#64748B] font-medium">
              Código TOTP (del autenticador vinculado a esta acción)
            </label>
            <input
              type="text"
              inputMode="numeric"
              maxLength={8}
              value={totpCode}
              onChange={e => setTotpCode(e.target.value.replace(/\D/g, ''))}
              placeholder="123456"
              className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg px-3 py-2 text-center text-lg font-mono tracking-[0.4em] text-white placeholder:text-[#374151] focus:outline-none focus:border-[#8B5CF6] transition-colors"
            />
          </div>

          {/* PIN */}
          <div className="space-y-1.5">
            <label className="text-xs text-[#64748B] font-medium">PIN de autorización</label>
            <div className="relative">
              <input
                type={showPin ? 'text' : 'password'}
                value={pin}
                onChange={e => setPin(e.target.value)}
                placeholder="••••"
                className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg px-3 py-2 pr-10 text-white font-mono placeholder:text-[#374151] focus:outline-none focus:border-[#8B5CF6] transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowPin(!showPin)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[#475569] hover:text-white transition-colors"
              >
                {showPin ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {error && (
            <div className="flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              {error}
            </div>
          )}

          <div className="flex gap-3 pt-1">
            <button
              onClick={onClose}
              className="flex-1 px-4 py-2 bg-[#1C2030] hover:bg-[#252a36] text-[#64748B] rounded-lg text-sm transition-colors"
            >
              Cancelar
            </button>
            <button
              onClick={handleApprove}
              disabled={submitting}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-600 disabled:opacity-50 text-white font-semibold rounded-lg text-sm transition-colors"
            >
              {submitting ? (
                <><RefreshCw className="w-4 h-4 animate-spin" />Verificando...</>
              ) : (
                <><CheckCircle2 className="w-4 h-4" />Aprobar acción</>
              )}
            </button>
          </div>

        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ── Request New Action Modal ───────────────────────────────────────────────────

interface RequestModalProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
  preselect?: { assetId?: number; processName?: string; anomalyType?: string };
}

function RequestModal({ open, onClose, onSuccess, preselect }: RequestModalProps) {
  const [form, setForm] = useState({
    asset_id: String(preselect?.assetId ?? ''),
    action_type: preselect?.anomalyType?.includes('C2') ? 'block_ip' : 'kill_process',
    target_detail: preselect?.processName ? `PID:${preselect.processName}` : '',
    justification: preselect?.anomalyType ? `Anomalía detectada: ${preselect.anomalyType}` : '',
    pin: '',
  });
  const [showPin, setShowPin] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [qrData, setQrData] = useState<{ totp_qr_base64: string; totp_secret: string; approval_instructions: string } | null>(null);
  const me = getMe();

  useEffect(() => {
    if (!open) { setError(''); setQrData(null); }
  }, [open]);

  const handleSubmit = async () => {
    if (!form.asset_id) { setError('Asset ID es obligatorio'); return; }
    if (!form.target_detail) { setError('Objetivo es obligatorio'); return; }
    if (form.pin.length < 4) { setError('PIN mínimo 4 caracteres'); return; }
    setSubmitting(true);
    setError('');
    const result = await requestResponseAction({
      asset_id: Number(form.asset_id),
      action_type: form.action_type,
      target_detail: form.target_detail,
      requested_by: me,
      justification: form.justification,
      pin: form.pin,
    });
    setSubmitting(false);
    if (result.ok && result.data) {
      setQrData({ totp_qr_base64: result.data.totp_qr_base64, totp_secret: result.data.totp_secret, approval_instructions: result.data.approval_instructions });
    } else {
      setError(result.message);
    }
  };

  const handleDone = () => { onSuccess(); onClose(); };

  return (
    <Dialog.Root open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-full max-w-lg bg-[#111318] border border-[#1C2030] rounded-xl shadow-2xl p-6 space-y-4 max-h-[90vh] overflow-y-auto">

          <div className="flex items-start gap-3">
            <div className="p-2 bg-amber-500/10 rounded-lg">
              <Zap className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <Dialog.Title className="text-base font-semibold text-white">
                Nueva acción de respuesta
              </Dialog.Title>
              <Dialog.Description className="text-xs text-[#475569] mt-0.5">
                Se generará un código TOTP para la aprobación dual
              </Dialog.Description>
            </div>
          </div>

          {!qrData ? (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs text-[#64748B]">Asset ID *</label>
                  <input
                    type="number"
                    value={form.asset_id}
                    onChange={e => setForm(f => ({ ...f, asset_id: e.target.value }))}
                    className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#8B5CF6] transition-colors"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-[#64748B]">Tipo de acción *</label>
                  <select
                    value={form.action_type}
                    onChange={e => setForm(f => ({ ...f, action_type: e.target.value }))}
                    className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg px-3 py-2 text-sm text-[#d1d5db] focus:outline-none focus:border-[#8B5CF6] transition-colors"
                  >
                    <option value="kill_process">Matar proceso</option>
                    <option value="quarantine_file">Cuarentena fichero</option>
                    <option value="block_ip">Bloquear IP</option>
                    <option value="isolate_host">Aislar host</option>
                    <option value="collect_forensics">Recolectar forense</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-[#64748B]">Objetivo *
                  <span className="ml-1 text-[#475569]">(ej. PID:1234, /path/to/file, 1.2.3.4)</span>
                </label>
                <input
                  type="text"
                  value={form.target_detail}
                  onChange={e => setForm(f => ({ ...f, target_detail: e.target.value }))}
                  className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#8B5CF6] transition-colors"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs text-[#64748B]">Justificación</label>
                <textarea
                  value={form.justification}
                  onChange={e => setForm(f => ({ ...f, justification: e.target.value }))}
                  rows={2}
                  className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg px-3 py-2 text-sm text-white resize-none focus:outline-none focus:border-[#8B5CF6] transition-colors"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs text-[#64748B]">PIN de aprobación *</label>
                <div className="relative">
                  <input
                    type={showPin ? 'text' : 'password'}
                    value={form.pin}
                    onChange={e => setForm(f => ({ ...f, pin: e.target.value }))}
                    placeholder="••••"
                    className="w-full bg-[#0A0C10] border border-[#1C2030] rounded-lg px-3 py-2 pr-10 text-sm text-white font-mono focus:outline-none focus:border-[#8B5CF6] transition-colors"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPin(!showPin)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#475569] hover:text-white"
                  >
                    {showPin ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {error && (
                <div className="flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  {error}
                </div>
              )}

              <div className="flex gap-3 pt-1">
                <button onClick={onClose} className="flex-1 px-4 py-2 bg-[#1C2030] hover:bg-[#252a36] text-[#64748B] rounded-lg text-sm transition-colors">
                  Cancelar
                </button>
                <button onClick={handleSubmit} disabled={submitting} className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-white font-semibold rounded-lg text-sm transition-colors">
                  {submitting ? <><RefreshCw className="w-4 h-4 animate-spin" />Creando...</> : <><Zap className="w-4 h-4" />Crear acción</>}
                </button>
              </div>
            </>
          ) : (
            /* TOTP QR step */
            <div className="space-y-4 text-center">
              <div className="space-y-1">
                <p className="text-sm font-semibold text-white">Escanea el QR con tu autenticador</p>
                <p className="text-xs text-[#475569]">Deberás introducir el código para aprobar la acción</p>
              </div>

              <div className="flex justify-center">
                <img
                  src={`data:image/png;base64,${qrData.totp_qr_base64}`}
                  alt="TOTP QR Code"
                  className="w-40 h-40 rounded-lg border border-[#1C2030]"
                />
              </div>

              <div className="bg-[#0A0C10] border border-[#1C2030] rounded-lg p-3 text-left space-y-1">
                <p className="text-[10px] text-[#475569] uppercase tracking-wider">Secret manual</p>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-[#8B5CF6] break-all">{qrData.totp_secret}</span>
                  <button
                    onClick={() => navigator.clipboard.writeText(qrData.totp_secret)}
                    className="text-[#475569] hover:text-white shrink-0"
                  >
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-left">
                <p className="text-xs text-amber-400">{qrData.approval_instructions}</p>
              </div>

              <button
                onClick={handleDone}
                className="w-full px-4 py-2 bg-[#8B5CF6] hover:bg-[#00b8e6] text-[#0A0C10] font-semibold rounded-lg text-sm transition-colors"
              >
                Entendido — cerrar
              </button>
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export function IncidentResponsePage() {
  const location = useLocation();
  const preselect = location.state?.preselect as { assetId?: number; processName?: string; anomalyType?: string } | undefined;

  const [statusFilter, setStatusFilter] = useState('pending');
  const [approveTarget, setApproveTarget] = useState<ResponseAction | null>(null);
  const [showRequestModal, setShowRequestModal] = useState(false);

  const { actions, total, loading, error, refetch } =
    useResponseActions(undefined, statusFilter || undefined);

  // Mock data for demo
  const mockActions = [
    { id: 1, asset_id: 15, action_type: 'kill_process', target_detail: 'explorer.exe (PID: 2144)', status: 'pending', requested_by: 'M8-IA', created_at: new Date(Date.now() - 600000).toISOString(), execution_output: null },
    { id: 2, asset_id: 22, action_type: 'quarantine_file', target_detail: 'C:\\Windows\\Temp\\malware.exe', status: 'approved', requested_by: 'system_manager', created_at: new Date(Date.now() - 1800000).toISOString(), execution_output: 'File quarantined successfully' },
    { id: 3, asset_id: 8, action_type: 'block_ip', target_detail: '192.168.1.105:445', status: 'completed', requested_by: 'security_officer', created_at: new Date(Date.now() - 3600000).toISOString(), execution_output: 'IP blocked in firewall' },
    { id: 4, asset_id: 31, action_type: 'isolate_host', target_detail: 'DESKTOP-XYZ123', status: 'completed', requested_by: 'M8-IA', created_at: new Date(Date.now() - 7200000).toISOString(), execution_output: 'Host isolated from network' },
  ];

  // Always use mock data for demo
  const displayActions = mockActions;
  const displayTotal = mockActions.length;

  return (
    <div className="flex h-screen bg-[#0A0C10] text-[#d1d5db] overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-red-400" />
                Incident Response
              </h1>
              <p className="text-xs text-[#475569] mt-1">
                Cola de aprobación TOTP+PIN · Historial de acciones de respuesta
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowRequestModal(true)}
                className="flex items-center gap-2 px-4 py-2 bg-[#8B5CF6]/10 hover:bg-[#8B5CF6]/20 border border-[#8B5CF6]/30 text-[#8B5CF6] rounded-lg text-xs font-medium transition-colors"
              >
                <Zap className="w-3.5 h-3.5" />
                Nueva acción
              </button>
              <button
                onClick={refetch}
                className="flex items-center gap-1.5 px-3 py-2 bg-[#111318] border border-[#1C2030] rounded-lg text-xs text-[#64748B] hover:text-white hover:border-[#8B5CF6]/40 transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Actualizar
              </button>
            </div>
          </div>

          {/* Status filter tabs */}
          <div className="flex gap-2 bg-[#111318] border border-[#1C2030] rounded-lg p-1 w-fit">
            {(['pending', 'approved', 'completed', 'failed', ''] as const).map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  statusFilter === s
                    ? 'bg-[#8B5CF6]/10 text-[#8B5CF6] border border-[#8B5CF6]/30'
                    : 'text-[#64748B] hover:text-white'
                }`}
              >
                {s === '' ? 'Todos' :
                 s === 'pending' ? '⏳ Pendientes' :
                 s === 'approved' ? '✓ Aprobadas' :
                 s === 'completed' ? '✔ Completadas' :
                 '✗ Fallidas'}
              </button>
            ))}
          </div>

          {/* Actions Table */}
          <div className="bg-[#111318] border border-[#1C2030] rounded-xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#1C2030]">
              <h2 className="text-sm font-semibold text-white">
                Acciones de respuesta
                <span className="ml-2 text-[10px] font-mono text-[#475569]">{displayTotal} registros</span>
              </h2>
            </div>

            {loading ? (
              <div className="flex items-center justify-center py-12 text-[#475569] text-sm gap-2">
                <RefreshCw className="w-4 h-4 animate-spin" />
                Cargando acciones...
              </div>
            ) : error ? (
              <div className="flex items-center justify-center py-12 text-red-400 text-sm gap-2">
                <AlertTriangle className="w-4 h-4" />
                {error}
              </div>
            ) : displayActions.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-[#475569] text-sm gap-2">
                <CheckCircle2 className="w-8 h-8 opacity-30" />
                No hay acciones {statusFilter === 'pending' ? 'pendientes' : `con estado "${statusFilter}"`}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#1C2030] text-[#475569]">
                      <th className="text-left px-4 py-2 font-medium">ID / Asset</th>
                      <th className="text-left px-4 py-2 font-medium">Acción</th>
                      <th className="text-left px-4 py-2 font-medium">Objetivo</th>
                      <th className="text-left px-4 py-2 font-medium">Estado</th>
                      <th className="text-left px-4 py-2 font-medium">Solicitante</th>
                      <th className="text-left px-4 py-2 font-medium">Fecha</th>
                      <th className="text-left px-4 py-2 font-medium">Operaciones</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayActions.map((a) => (
                      <tr key={a.id} className="border-b border-[#1C2030]/50 hover:bg-[#1C2030]/40 transition-colors">
                        <td className="px-4 py-3">
                          <span className="font-mono text-[#475569]">#{a.id}</span>
                          <span className="ml-2 text-[#64748B]">A-{a.asset_id}</span>
                        </td>
                        <td className="px-4 py-3 font-medium text-white">
                          {actionLabel(a.action_type)}
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-amber-400 truncate max-w-[160px] block">
                            {a.target_detail}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <Badge className={`${statusClass(a.status)} border text-[10px] font-mono px-2 py-0.5`}>
                            {a.status.toUpperCase()}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-[#64748B]">{a.requested_by}</td>
                        <td className="px-4 py-3 text-[#475569] font-mono">
                          {fmt.format(new Date(a.created_at))}
                        </td>
                        <td className="px-4 py-3">
                          {a.status === 'pending' && (
                            <div className="flex gap-2">
                              <button
                                onClick={() => setApproveTarget(a)}
                                className="flex items-center gap-1 px-2.5 py-1 bg-green-500/10 hover:bg-green-500/20 border border-green-500/30 text-green-400 rounded text-[10px] font-medium transition-colors"
                              >
                                <CheckCircle2 className="w-3 h-3" />
                                Aprobar
                              </button>
                              <button
                                className="flex items-center gap-1 px-2.5 py-1 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 rounded text-[10px] font-medium transition-colors"
                              >
                                <XCircle className="w-3 h-3" />
                                Rechazar
                              </button>
                            </div>
                          )}
                          {a.status === 'completed' && a.execution_output && (
                            <span className="text-[#475569] italic truncate max-w-[160px] block">
                              {String(a.execution_output).substring(0, 60)}
                            </span>
                          )}
                          {a.status === 'executing' && (
                            <span className="flex items-center gap-1 text-blue-400">
                              <RefreshCw className="w-3 h-3 animate-spin" />
                              Ejecutando...
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

        </main>
      </div>

      {/* Modals */}
      {approveTarget && (
        <ApproveModal
          action={approveTarget}
          open={!!approveTarget}
          onClose={() => setApproveTarget(null)}
          onSuccess={refetch}
        />
      )}

      <RequestModal
        open={showRequestModal}
        preselect={preselect}
        onClose={() => setShowRequestModal(false)}
        onSuccess={refetch}
      />
    </div>
  );
}
