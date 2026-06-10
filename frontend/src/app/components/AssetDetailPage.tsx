import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useParams, useNavigate } from 'react-router';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { Badge } from './ui/badge';
import * as Dialog from '@radix-ui/react-dialog';
import {
  ChevronLeft, Pencil, Save, Trash2, Play, Loader2, AlertCircle, Zap,
  CheckCircle2, ShieldAlert, Shield, Monitor, Search, Download,
  RefreshCw, XCircle,
} from 'lucide-react';
import { useAssets, type VulnResult } from '../../hooks/useAssets';
import { getStoredToken } from '../../hooks/useAuth';

const M1_BASE = 'http://localhost:8001/api/v1';
const SCAN_TOOLS = ['nikto', 'nuclei', 'nmap'] as const;

function authHeader(): HeadersInit {
  const token = getStoredToken();
  return token
    ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };
}

const fmt = new Intl.DateTimeFormat('es-ES', {
  day: '2-digit', month: 'short', year: 'numeric',
  hour: '2-digit', minute: '2-digit',
});

interface AssetDetail {
  id: number;
  ip: string;
  hostname: string | null;
  nombre?: string | null;
  tipo: string;
  criticidad: string;
  status: string;
  responsable: string | null;
  notas?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  discovered_by?: string | null;
  external_source?: string | null;
  network_range?: string | null;
  dominio?: string | null;
  mac_address?: string | null;
  os_family?: string | null;
  os_version?: string | null;
  departamento?: string | null;
  ubicacion?: string | null;
  ssh_user?: string | null;
  ssh_password?: string | null;
}

type EditForm = {
  hostname: string;
  nombre: string;
  tipo: string;
  criticidad: string;
  responsable: string;
  status: string;
  os_family: string;
  os_version: string;
  dominio: string;
  network_range: string;
  departamento: string;
  ubicacion: string;
  mac_address: string;
  notas: string;
  ssh_user: string;
  ssh_password: string;
};

function toEditForm(a: AssetDetail): EditForm {
  return {
    hostname: a.hostname ?? '',
    nombre: a.nombre ?? '',
    tipo: a.tipo,
    criticidad: a.criticidad,
    responsable: a.responsable ?? '',
    status: a.status,
    os_family: a.os_family ?? '',
    os_version: a.os_version ?? '',
    dominio: a.dominio ?? '',
    network_range: a.network_range ?? '',
    departamento: a.departamento ?? '',
    ubicacion: a.ubicacion ?? '',
    mac_address: a.mac_address ?? '',
    notas: a.notas ?? '',
    ssh_user: a.ssh_user ?? '',
    ssh_password: a.ssh_password ?? '',
  };
}

const criticidadClass = (c: string) => {
  switch (c) {
    case 'CRITICA': return 'text-[#ff3b3b] border-[#ff3b3b]/30 bg-[#ff3b3b]/10';
    case 'ALTA':    return 'text-[#f59e0b] border-[#f59e0b]/30 bg-[#f59e0b]/10';
    case 'MEDIA':   return 'text-[#00d4ff] border-[#00d4ff]/30 bg-[#00d4ff]/10';
    default:        return 'text-[#6b7280] border-[#374151] bg-[#374151]/20';
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

function statusDotClass(status: string) {
  switch (status) {
    case 'ACTIVO':         return 'bg-[#22c55e]';
    case 'MANTENIMIENTO':  return 'bg-[#f59e0b]';
    case 'PENDIENTE_ALTA': return 'bg-[#00d4ff]';
    default:               return 'bg-[#6b7280]';
  }
}

const inputClass =
  'w-full bg-[#0f1117] border border-[#1e2530] rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#00d4ff] transition-colors';

// ── Interfaces logs ──────────────────────────────────────────────
interface SIEMAlertAsset {
  alert_id: string;
  timestamp: string;
  agent_id: string;
  agent_name: string;
  agent_ip: string;
  rule_id: string;
  rule_desc: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  raw_log: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  success?: boolean;
  src_ip?: string;
  src_user?: string;
  action_type?: string;
  command?: string;
  port?: string;
}

interface ServerStatAsset {
  agent_name: string;
  agent_ip: string;
  total: number;
  failures: number;
  successes: number;
  sudo_cmds: number;
  unique_ips: string[];
  unique_users: string[];
  critical_count: number;
  high_count: number;
}

// ── Helpers logs ─────────────────────────────────────────────────
function fmtDatetimeAsset(ts: string): string {
  try {
    return new Date(ts).toLocaleString('es-ES', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch { return ts; }
}

function fmtTimeAsset(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString('es-ES', {
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch { return ts; }
}

function actionBadgeAsset(action: string | undefined) {
  const cfg: Record<string, { cls: string; label: string }> = {
    SSH_LOGIN_OK:     { cls: 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]',  label: '✓ SSH OK' },
    SSH_LOGIN_FAIL:   { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',  label: '✗ SSH FAIL' },
    SSH_INVALID_USER: { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',  label: '✗ INVÁLIDO' },
    SSH_ABORT:        { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',  label: '⚡ ABORT' },
    SESSION_OPEN:     { cls: 'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]',  label: '▶ SESIÓN' },
    SESSION_CLOSE:    { cls: 'bg-[#374151]/30 border-[#4b5563]/30 text-[#9ca3af]',  label: '■ FIN SESIÓN' },
    SUDO_COMMAND:     { cls: 'bg-[#a78bfa]/10 border-[#a78bfa]/30 text-[#a78bfa]',  label: '⚡ SUDO' },
    SUDO_FAIL:        { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',  label: '✗ SUDO FAIL' },
    SU_OK:            { cls: 'bg-[#a78bfa]/10 border-[#a78bfa]/30 text-[#a78bfa]',  label: '▲ SU OK' },
    SU_FAIL:          { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',  label: '✗ SU FAIL' },
    USER_CREATED:     { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',  label: '+ USUARIO' },
    USER_DELETED:     { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',  label: '− USUARIO' },
    USER_MODIFIED:    { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',  label: '✎ USUARIO' },
    GROUP_CREATED:    { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',  label: '+ GRUPO' },
    PASSWORD_CHANGED: { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',  label: '🔑 PASSWD' },
    ACCOUNT_LOCKED:   { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',  label: '🔒 BLOQUEADO' },
    ACCOUNT_LOCKOUT:  { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',  label: '🔒 LOCKOUT' },
    AUTH_FAILURE:     { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',  label: '✗ AUTH FAIL' },
    PRIV_ESCALATION:  { cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',  label: '⚠ ESCALADA' },
    OTHER:            { cls: 'bg-[#374151]/30 border-[#4b5563]/30 text-[#6b7280]',  label: 'OTRO' },
  };
  const c = cfg[action ?? 'OTHER'] ?? cfg['OTHER'];
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-full border text-[10px] font-semibold whitespace-nowrap ${c.cls}`}>
      {c.label}
    </span>
  );
}

export function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { scanAsset, getVulnResults, pollScanStatus } = useAssets();

  const [asset, setAsset] = useState<AssetDetail | null>(null);
  const [pageLoading, setPageLoading] = useState(true);
  const [pageError, setPageError] = useState<string | null>(null);

  const [vulns, setVulns] = useState<VulnResult[]>([]);
  const [vulnsLoading, setVulnsLoading] = useState(false);
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);
  const [filterDate, setFilterDate] = useState('all');
  const [filterTool, setFilterTool] = useState('all');

  const [editing, setEditing] = useState(false);
  const [editForm, setEditForm] = useState<EditForm>({
    hostname: '', nombre: '', tipo: 'SERVER', criticidad: 'MEDIA', responsable: '',
    status: 'ACTIVO', os_family: '', os_version: '', dominio: '',
    network_range: '', departamento: '', ubicacion: '', mac_address: '', notas: '',
    ssh_user: '', ssh_password: '',
  });
  const [saving, setSaving] = useState(false);

  const [selectedTool, setSelectedTool] = useState<string>('nikto');
  const [scanState, setScanState] = useState<{ status: 'idle' | 'scanning' | 'done' | 'error'; msg?: string }>({ status: 'idle' });
  const [fullScanState, setFullScanState] = useState<{ status: 'idle' | 'scanning' | 'done' | 'error'; msg?: string }>({ status: 'idle' });

  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const [toast, setToast] = useState<{ ok: boolean; msg: string } | null>(null);

  // ── Tab activa ───────────────────────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState<'info' | 'vulns' | 'pipeline' | 'logs'>('info');

  // ── Estados logs de acceso ───────────────────────────────────────────────────
  const [logEvents, setLogEvents]       = useState<SIEMAlertAsset[]>([]);
  const [logStat, setLogStat]           = useState<ServerStatAsset | null>(null);
  const [logBruteIPs, setLogBruteIPs]   = useState<string[]>([]);
  const [logLoading, setLogLoading]     = useState(false);
  const [logError, setLogError]         = useState(false);
  const [logLastLoad, setLogLastLoad]   = useState<Date | null>(null);
  const [logExpanded, setLogExpanded]   = useState<string | null>(null);
  const [logSearch, setLogSearch]       = useState('');
  const [logFilterAction, setLogFilterAction] = useState('ALL');
  const [logFilterSeverity, setLogFilterSeverity] = useState('ALL');
  const [logFilterResult, setLogFilterResult] = useState<'ALL'|'SUCCESS'|'FAIL'>('ALL');
  const [logFilterIP, setLogFilterIP]   = useState('ALL');
  const [logDateFrom, setLogDateFrom]   = useState('');
  const [logDateTo, setLogDateTo]       = useState('');
  const [logPage, setLogPage]           = useState(1);
  const LOG_PAGE_SIZE = 20;
  const [logLiveMode, setLogLiveMode]           = useState(false);
  const [logLiveCountdown, setLogLiveCountdown] = useState(60);

  const showToast = useCallback((ok: boolean, msg: string) => {
    setToast({ ok, msg });
    setTimeout(() => setToast(null), 4000);
  }, []);

  const fetchAsset = useCallback(async () => {
    if (!id) return;
    setPageLoading(true);
    setPageError(null);
    try {
      const res = await fetch(`${M1_BASE}/assets/${id}`, { headers: authHeader() });
      if (!res.ok) throw new Error(res.status === 404 ? 'Activo no encontrado' : `Error ${res.status}`);
      const data: AssetDetail = await res.json();
      setAsset(data);
      setEditForm(toEditForm(data));
    } catch (e: any) {
      setPageError(e?.message ?? 'Error al cargar el activo');
    } finally {
      setPageLoading(false);
    }
  }, [id]);

  useEffect(() => { fetchAsset(); }, [fetchAsset]);

  const loadLogs = useCallback(async () => {
    if (!asset) return;
    setLogLoading(true); setLogError(false);
    try {
      const token = getStoredToken();
      const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await fetch(
        'http://localhost:8006/siem/auth-events?limit=500',
        { headers, signal: AbortSignal.timeout(15000) }
      );
      if (!res.ok) throw new Error();
      const data = await res.json() as {
        events: SIEMAlertAsset[];
        server_stats?: ServerStatAsset[];
        brute_force_ips?: string[];
      };
      const myEvents = (data.events ?? []).filter(e => e.agent_ip === asset.ip);
      setLogEvents(myEvents);
      const myStat = (data.server_stats ?? []).find(s => s.agent_ip === asset.ip) ?? null;
      setLogStat(myStat);
      setLogBruteIPs(data.brute_force_ips ?? []);
      setLogLastLoad(new Date());
    } catch { setLogError(true); }
    finally { setLogLoading(false); }
  }, [asset]);

  useEffect(() => {
    if (activeTab === 'logs' && asset) loadLogs();
  }, [activeTab, asset]);

  useEffect(() => {
    if (!logLiveMode) { setLogLiveCountdown(60); return; }
    setLogLiveCountdown(60);
    const countdown = setInterval(() => {
      setLogLiveCountdown(prev => (prev <= 1 ? 60 : prev - 1));
    }, 1000);
    const refresh = setInterval(() => { loadLogs(); }, 60000);
    return () => { clearInterval(countdown); clearInterval(refresh); };
  }, [logLiveMode, loadLogs]);

  useEffect(() => {
    if (!asset) return;
    setVulnsLoading(true);
    getVulnResults(asset.id)
      .then(v => setVulns(v))
      .catch(() => setVulns([]))
      .finally(() => setVulnsLoading(false));
  }, [asset?.id, getVulnResults]);

  const handleSave = useCallback(async () => {
    if (!asset) return;
    setSaving(true);
    try {
      const payload = {
        hostname:      editForm.hostname      || null,
        nombre:        editForm.nombre        || null,
        tipo:          editForm.tipo,
        criticidad:    editForm.criticidad,
        responsable:   editForm.responsable,
        status:        editForm.status,
        os_family:     editForm.os_family     || null,
        os_version:    editForm.os_version    || null,
        dominio:       editForm.dominio       || null,
        network_range: editForm.network_range || null,
        departamento:  editForm.departamento  || null,
        ubicacion:     editForm.ubicacion     || null,
        mac_address:   editForm.mac_address   || null,
        notas:         editForm.notas         || null,
        ssh_user:      editForm.ssh_user      || null,
        ssh_password:  editForm.ssh_password  || null,
      };
      const res = await fetch(`${M1_BASE}/assets/${asset.id}`, {
        method: 'PUT',
        headers: authHeader(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as any).detail ?? `Error ${res.status}`);
      }
      const updated: AssetDetail = await res.json();
      setAsset(updated);
      setEditForm(toEditForm(updated));
      setEditing(false);
      showToast(true, 'Activo actualizado correctamente');
    } catch (e: any) {
      showToast(false, e?.message ?? 'Error al actualizar');
    } finally {
      setSaving(false);
    }
  }, [asset, editForm, showToast]);

  const handleDelete = useCallback(async () => {
    if (!asset) return;
    setDeleteLoading(true);
    try {
      const res = await fetch(`${M1_BASE}/assets/${asset.id}`, {
        method: 'DELETE',
        headers: authHeader(),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as any).detail ?? `HTTP ${res.status}`);
      }
      navigate('/assets');
    } catch (e: any) {
      setDeleteDialogOpen(false);
      showToast(false, e?.message ?? 'Error al eliminar');
    } finally {
      setDeleteLoading(false);
    }
  }, [asset, navigate, showToast]);

  const handleScan = useCallback(async () => {
    if (!asset) return;
    setScanState({ status: 'scanning', msg: 'Iniciando...' });
    try {
      const task = await scanAsset(asset.id, [selectedTool]);
      setScanState({ status: 'scanning', msg: 'Escaneando...' });
      const result = await pollScanStatus(task.task_id, asset.id,
        (msg) => setScanState({ status: 'scanning', msg })
      );
      if (result.status === 'SUCCESS') {
        setScanState({ status: 'done', msg: `✓ Completado · ${result.findings_count} hallazgos · ${fmt.format(new Date())}` });
      } else if (result.status === 'FAILED') {
        setScanState({ status: 'error', msg: '✗ Escaneo fallido' });
      } else {
        setScanState({ status: 'error', msg: '✗ Timeout — escaneo tardó demasiado' });
      }
    } catch {
      setScanState({ status: 'error', msg: '✗ Error al lanzar escaneo' });
    } finally {
      setTimeout(() => setScanState({ status: 'idle' }), 8000);
    }
  }, [asset, scanAsset, selectedTool, pollScanStatus]);

  const handleFullScan = useCallback(async () => {
    if (!asset) return;
    setFullScanState({ status: 'scanning', msg: 'Iniciando...' });
    try {
      const task = await scanAsset(asset.id, ['nuclei', 'nikto']);
      setFullScanState({ status: 'scanning', msg: 'Escaneando...' });
      const result = await pollScanStatus(task.task_id, asset.id,
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
    } finally {
      setTimeout(() => setFullScanState({ status: 'idle' }), 8000);
    }
  }, [asset, scanAsset, pollScanStatus]);

  // ── Pipeline completo M2→M3→M8→M4 ──────────────────────────────────────────
  type PipelinePhase = 'idle'|'m2'|'m3'|'m8'|'m4'|'done'|'error';
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [pipelinePhase, setPipelinePhase] = useState<PipelinePhase>('idle');
  const [pipelineLogs, setPipelineLogs] = useState<{ts:string; level:'info'|'success'|'warn'|'error'; msg:string}[]>([]);
  const [pipelineOpen, setPipelineOpen] = useState(false);
  const [pipelineQr, setPipelineQr] = useState('');
  const [pipelineApprovalId, setPipelineApprovalId] = useState<number|null>(null);
  const [pipelineAuthorized, setPipelineAuthorized] = useState(false);
  const [pipelineExecResult, setPipelineExecResult] = useState<any>(null);
  const [pipelineErrors, setPipelineErrors] = useState<string[]>([]);
  const pipelineLogRef = useRef<HTMLDivElement>(null);

  const plog = (msg: string, level: 'info'|'success'|'warn'|'error' = 'info') => {
    const ts = new Date().toLocaleTimeString('es-ES');
    const entry = { ts, level, msg };
    setPipelineLogs(p => {
      const updated = [...p, entry];
      try {
        sessionStorage.setItem(
          `scanops_pipeline_${asset?.id}`,
          JSON.stringify({ logs: updated, phase: pipelinePhase })
        );
      } catch {}
      return updated;
    });
    if (level === 'error') {
      setPipelineErrors(p => [...p, msg]);
    }
  };

  useEffect(() => {
    if (pipelineLogRef.current) {
      pipelineLogRef.current.scrollTop = pipelineLogRef.current.scrollHeight;
    }
  }, [pipelineLogs]);

  useEffect(() => {
    if (!asset?.id) return;
    try {
      const stored = sessionStorage.getItem(`scanops_pipeline_${asset.id}`);
      if (stored) {
        const { logs, phase } = JSON.parse(stored);
        if (logs?.length > 0) {
          setPipelineLogs(logs);
          setPipelinePhase(phase ?? 'done');
          setPipelineOpen(true);
        }
      }
    } catch {}
  }, [asset?.id]);

  const handleRunPipeline = async () => {
    if (!asset) return;
    setPipelineRunning(true);
    setPipelineOpen(true);
    setPipelineLogs([]);
    setPipelineErrors([]);
    setPipelineQr('');
    setPipelineApprovalId(null);

    try {
      // ── FASE M2: Reconocimiento ─────────────────────────────
      setPipelinePhase('m2');
      plog(`[M2] Iniciando reconocimiento sobre ${asset.ip}...`);
      const m2Res = await fetch(
        `http://localhost:8003/api/v1/scan?target=${encodeURIComponent(asset.ip)}`,
        { method: 'POST', headers: authHeader(), signal: AbortSignal.timeout(120000) }
      );
      if (!m2Res.ok) throw new Error(`M2 falló: HTTP ${m2Res.status}`);
      const m2Data = await m2Res.json();
      const ports = m2Data.reconnaissance?.ports_discovered?.length ?? 0;
      plog(`[M2] ✓ ${ports} puertos descubiertos en ${m2Data.summary?.scan_duration_seconds?.toFixed(1)}s`, 'success');
      m2Data.reconnaissance?.ports_discovered?.forEach((p: any) => {
        plog(`[M2]   → ${p.port}/${p.protocol} ${p.service} ${p.version ?? ''}`, 'info');
      });

      // ── FASE M3: Vulnerabilidades ───────────────────────────
      setPipelinePhase('m3');
      plog(`[M3] Lanzando Nmap + Nuclei + Nikto + ffuf + whatweb + testssl sobre ${asset.ip}...`);
      const m3Launch = await fetch(
        `http://localhost:8002/api/v1/scan/asset/${asset.id}`,
        { method: 'POST', headers: authHeader(),
          body: JSON.stringify({ scan_types: ['nmap','nuclei','nikto','ffuf','whatweb','testssl'],
            description: `Pipeline completo: ${asset.ip}` }),
          signal: AbortSignal.timeout(15000) }
      );
      if (!m3Launch.ok) throw new Error(`M3 falló al lanzar: HTTP ${m3Launch.status}`);
      plog(`[M3] Escaneo lanzado — esperando resultados (puede tardar 2-3 min)...`);

      await new Promise(r => setTimeout(r, 15000));
      let m3Findings = 0;
      for (let i = 0; i < 40; i++) {
        await new Promise(r => setTimeout(r, 5000));
        try {
          const rRes = await fetch(`http://localhost:8002/api/v1/scan/results/${asset.id}`,
            { headers: authHeader(), signal: AbortSignal.timeout(8000) });
          if (rRes.ok) {
            const rData = await rRes.json();
            if ((rData.total_findings ?? 0) > 0) {
              m3Findings = rData.total_findings;
              plog(`[M3] ✓ ${m3Findings} vulnerabilidades encontradas`, 'success');
              const allFindings = Object.values(rData.findings_by_scanner ?? {}).flat() as any[];
              allFindings.filter((f: any) => ['CRITICAL','HIGH'].includes(f.severity))
                .slice(0, 5)
                .forEach((f: any) => plog(`[M3]   → [${f.severity}] ${f.title}`, f.severity === 'CRITICAL' ? 'error' : 'warn'));
              break;
            }
          }
        } catch { continue; }
        if (i % 3 === 0) plog(`[M3] Escaneando... ${15 + (i+1)*5}s`);
      }
      if (m3Findings === 0) plog(`[M3] ⚠ Sin hallazgos — continuando con M8`, 'warn');

      // ── FASE M8: IA Reasoning ───────────────────────────────
      setPipelinePhase('m8');
      plog(`[M8] Invocando Ollama/Mistral para análisis de vectores...`);
      const m8Launch = await fetch(
        `http://localhost:8002/api/v1/scan/assets/${asset.id}/attack-vector`,
        { method: 'POST', headers: authHeader(), signal: AbortSignal.timeout(15000) }
      );
      if (!m8Launch.ok) throw new Error(`M8 falló: HTTP ${m8Launch.status}`);
      const { task_id: m8TaskId } = await m8Launch.json();
      plog(`[M8] Tarea lanzada — Mistral procesando (puede tardar 3-5 min)...`);

      let m8Result: any = null;
      for (let a = 0; a < 60; a++) {
        await new Promise(r => setTimeout(r, 4000));
        try {
          const rRes = await fetch(
            `http://localhost:8002/api/v1/scan/assets/${asset.id}/attack-vector/result/${m8TaskId}`,
            { headers: authHeader(), signal: AbortSignal.timeout(8000) }
          );
          if (rRes.ok) {
            const rData = await rRes.json();
            if (rData.status === 'SUCCESS' && rData.result) {
              m8Result = rData.result;
              const modulo = m8Result?.msf_module ?? m8Result?.attack_module ?? 'exploit/multi/handler';
              const riesgo = String(m8Result?.risk_level ?? m8Result?.riesgo ?? 'ALTO').toUpperCase();
              const confianza = String(m8Result?.confidence ?? m8Result?.confianza ?? 'alto').toUpperCase();
              const ensArt = m8Result?.ens_article ?? m8Result?.ens ?? 'op.exp.2';
              plog(`[M8] ✓ Vector generado por Mistral/Ollama`, 'success');
              plog(`[M8]   → Módulo: ${modulo}`, 'info');
              plog(`[M8]   → Riesgo: ${riesgo} | Confianza: ${confianza}`, 'info');
              plog(`[M8]   → ENS: ${ensArt} — Requiere aprobación humana (op.pl.1)`, 'info');
              break;
            }
            if (rData.status === 'FAILED' || rData.status === 'FAILURE') throw new Error('M8 falló durante la inferencia');
          }
        } catch (e: any) {
          if (e.message?.includes('M8 falló')) throw e;
          continue;
        }
        if (a % 5 === 0) plog(`[M8] Analizando... [${a+1}/60]`);
      }
      if (!m8Result) throw new Error('M8 timeout — Ollama tardó demasiado');

      // ── FASE M4: Solicitud de aprobación ────────────────────
      setPipelinePhase('m4');
      plog(`[M4] Creando solicitud de aprobación en la cola...`);
      const cveId = m8Result.msf_module?.split('/').pop()?.toUpperCase() ?? `VECTOR-${asset.ip}`;
      const m4Res = await fetch('http://localhost:8004/api/m4/request-approval', {
        method: 'POST',
        headers: authHeader(),
        body: JSON.stringify({ cve: cveId, ip: asset.ip, user_email: 'admin@scanops.local', pin: '1234' }),
        signal: AbortSignal.timeout(10000),
      });
      if (!m4Res.ok) throw new Error(`M4 falló: HTTP ${m4Res.status}`);
      const m4Data = await m4Res.json();
      setPipelineApprovalId(m4Data.approval_id);
      setPipelineQr(m4Data.qr_code_base64 ?? '');
      plog(`[M4] ✓ Solicitud #${m4Data.approval_id} creada — PIN: 1234`, 'success');
      plog(`[M4] ⏳ Esperando aprobación del Security Officer en M4 Explotación`, 'warn');

      setPipelinePhase('done');
      plog(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, 'info');
      plog(`[✓] PIPELINE COMPLETO — ${asset.ip}`, 'success');
      plog(`[✓] M2: Reconocimiento completado`, 'success');
      plog(`[✓] M3: Vulnerabilidades identificadas`, 'success');
      plog(`[✓] M8: Vector de ataque generado por IA`, 'success');
      plog(`[✓] M4: Solicitud #${m4Data.approval_id} en cola de aprobación`, 'success');
      plog(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, 'info');
      plog(`[→] Escanea el QR y ve a M4 Explotación para autorizar`, 'warn');

    } catch (e: any) {
      setPipelinePhase('error');
      plog(`[✗] Error: ${e.message}`, 'error');
    } finally {
      setPipelineRunning(false);
    }
  };

  const scanDates = useMemo(() => {
    const dates = new Set(vulns.map(v =>
      v.created_at ? new Date(v.created_at).toLocaleDateString('es-ES') : null
    ).filter(Boolean) as string[]);
    return Array.from(dates).sort().reverse();
  }, [vulns]);

  const scanTools = useMemo(() =>
    Array.from(new Set(vulns.map(v => v.tool_source).filter(Boolean))),
    [vulns]
  );

  const filteredVulns = useMemo(() => vulns.filter(v => {
    const dateMatch = filterDate === 'all' ||
      (v.created_at && new Date(v.created_at).toLocaleDateString('es-ES') === filterDate);
    const toolMatch = filterTool === 'all' || v.tool_source === filterTool;
    return dateMatch && toolMatch;
  }), [vulns, filterDate, filterTool]);

  // ── Filtrado logs ────────────────────────────────────────────────────────────
  const logFiltered = logEvents.filter(e => {
    const q = logSearch.toLowerCase();
    const matchSearch = !q ||
      (e.rule_desc ?? '').toLowerCase().includes(q) ||
      (e.raw_log ?? '').toLowerCase().includes(q) ||
      (e.src_ip ?? '').toLowerCase().includes(q) ||
      (e.src_user ?? '').toLowerCase().includes(q) ||
      (e.command ?? '').toLowerCase().includes(q);
    const matchAction   = logFilterAction === 'ALL' || e.action_type === logFilterAction;
    const matchSeverity = logFilterSeverity === 'ALL' || e.severity === logFilterSeverity;
    const matchResult   = logFilterResult === 'ALL' ||
      (logFilterResult === 'SUCCESS' && !!e.success) ||
      (logFilterResult === 'FAIL' && !e.success);
    const matchIP       = logFilterIP === 'ALL' || e.src_ip === logFilterIP;
    const matchDateFrom = !logDateFrom || e.timestamp >= logDateFrom;
    const matchDateTo   = !logDateTo   || e.timestamp <= logDateTo + 'T23:59:59';
    return matchSearch && matchAction && matchSeverity && matchResult && matchIP && matchDateFrom && matchDateTo;
  });

  const logTotalPages = Math.max(1, Math.ceil(logFiltered.length / LOG_PAGE_SIZE));
  const logPaged = logFiltered.slice((logPage - 1) * LOG_PAGE_SIZE, logPage * LOG_PAGE_SIZE);
  const logSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  const exportLogsCSV = () => {
    const headers = ['Timestamp','Tipo Acción','Resultado','Severidad','IP Origen','Puerto','Usuario','Comando','MITRE Táctica','MITRE Técnica','Raw Log'];
    const escape = (val: unknown) => {
      const s = val == null ? '' : String(val);
      return (s.includes(',') || s.includes('"') || s.includes('\n')) ? `"${s.replace(/"/g,'""')}"` : s;
    };
    const rows = logFiltered.map(e => [
      escape(e.timestamp), escape(e.action_type ?? ''),
      escape(e.success ? 'EXITOSO' : 'FALLIDO'), escape(e.severity),
      escape(e.src_ip ?? ''), escape(e.port ?? ''), escape(e.src_user ?? ''),
      escape(e.command ?? ''), escape(e.mitre_tactic ?? ''), escape(e.mitre_technique ?? ''),
      escape(e.raw_log),
    ].join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scanops_logs_${asset?.ip}_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
  };

  if (pageLoading) {
    return (
      <div className="flex h-screen bg-[#0f1117]">
        <Sidebar />
        <div className="flex-1 flex flex-col overflow-hidden">
          <TopBar role="System Manager" />
          <main className="flex-1 flex items-center justify-center">
            <div className="flex items-center gap-3 text-[#6b7280]">
              <Loader2 className="w-5 h-5 animate-spin" />
              <span>Cargando activo...</span>
            </div>
          </main>
        </div>
      </div>
    );
  }

  if (pageError || !asset) {
    return (
      <div className="flex h-screen bg-[#0f1117]">
        <Sidebar />
        <div className="flex-1 flex flex-col overflow-hidden">
          <TopBar role="System Manager" />
          <main className="flex-1 flex items-center justify-center">
            <div className="text-center space-y-4">
              <AlertCircle className="w-10 h-10 text-[#ff3b3b] mx-auto" />
              <p className="text-white text-lg">{pageError ?? 'Activo no encontrado'}</p>
              <button
                onClick={() => navigate('/assets')}
                className="flex items-center gap-2 px-4 py-2 bg-[#1a1d27] border border-[#1e2530] text-[#9ca3af] rounded-lg hover:text-white transition-colors mx-auto"
              >
                <ChevronLeft className="w-4 h-4" />
                Volver al inventario
              </button>
            </div>
          </main>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />
        <main className="flex-1 overflow-auto p-6 space-y-5">

          {toast && (
            <div className={`flex items-center gap-2 rounded-lg px-4 py-3 text-sm ${
              toast.ok
                ? 'bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e]'
                : 'bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b]'
            }`}>
              <AlertCircle className="w-4 h-4 shrink-0" />
              {toast.msg}
            </div>
          )}

          {/* Header row 1: back + breadcrumb + badges */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <button
                onClick={() => navigate('/assets')}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-[#1a1d27] border border-[#1e2530] text-[#9ca3af] rounded-lg hover:text-white hover:bg-[#1e2530] transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
                Inventario
              </button>
              <span className="text-[#6b7280] text-sm">
                M1 · Asset Manager / <span className="text-white font-mono">{asset.ip}</span>
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5">
                <div className={`w-1.5 h-1.5 rounded-full ${statusDotClass(asset.status)}`} />
                <span className="text-xs text-[#9ca3af]">{asset.status}</span>
              </div>
              <Badge variant="outline" className={`border text-xs ${criticidadClass(asset.criticidad)}`}>
                {asset.criticidad}
              </Badge>
            </div>
          </div>

          {/* Header row 2: title + action buttons */}
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-mono font-semibold text-white">
                {asset.nombre || asset.hostname || asset.ip}
              </h1>
              {asset.nombre && asset.hostname && (
                <p className="text-xs text-[#6b7280] font-mono mt-0.5">{asset.hostname}</p>
              )}
              {!asset.nombre && (
                <p className="text-sm text-[#9ca3af] font-mono mt-0.5">{asset.ip}</p>
              )}
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => { setEditing(true); setEditForm(toEditForm(asset)); }}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] rounded-lg hover:bg-[#00d4ff]/20 transition-colors"
              >
                <Pencil className="w-3.5 h-3.5" />
                Editar
              </button>
              <button
                onClick={handleScan}
                disabled={scanState.status === 'scanning'}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] rounded-lg hover:bg-[#22c55e]/20 transition-colors disabled:opacity-60"
              >
                {scanState.status === 'scanning' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                Escanear
              </button>
              <button
                onClick={() => setDeleteDialogOpen(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] rounded-lg hover:bg-[#ff3b3b]/20 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Eliminar
              </button>
              <button
                onClick={() => { setPipelineOpen(true); if (!pipelineRunning && pipelinePhase === 'idle') handleRunPipeline(); }}
                disabled={pipelineRunning}
                className="flex items-center gap-2 px-4 py-1.5 bg-[#7c3aed]/10 border border-[#7c3aed]/30 text-[#a78bfa] rounded-lg text-sm font-semibold hover:bg-[#7c3aed]/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {pipelineRunning
                  ? <><Loader2 className="w-3.5 h-3.5 animate-spin"/>Pipeline en curso...</>
                  : <><Zap className="w-3.5 h-3.5"/>Ejecutar Pipeline</>}
              </button>
            </div>
          </div>

          {/* ── Tab bar ── */}
          <div className="border-b border-[#1e2530] flex gap-0">
            {([
              { id: 'info',     label: 'Información' },
              { id: 'vulns',    label: 'Vulnerabilidades' },
              { id: 'pipeline', label: 'Pipeline' },
              { id: 'logs',     label: 'Logs de Acceso' },
            ] as const).map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'border-[#00d4ff] text-[#00d4ff]'
                    : 'border-transparent text-[#9ca3af] hover:text-white hover:border-[#374151]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {activeTab === 'info' && (
          <div className="grid grid-cols-12 gap-5">

            {/* LEFT: col-span-7 */}
            <div className="col-span-7 space-y-5">

              {/* Card 1: Asset Info */}
              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-sm font-semibold text-[#9ca3af] uppercase tracking-wider">Información del activo</h2>
                  {editing && (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleSave}
                        disabled={saving}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] rounded-lg hover:bg-[#22c55e]/20 transition-colors disabled:opacity-60"
                      >
                        {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
                        Guardar
                      </button>
                      <button
                        onClick={() => { setEditing(false); setEditForm(toEditForm(asset)); }}
                        className="px-3 py-1.5 text-xs bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] rounded-lg hover:text-white transition-colors"
                      >
                        Cancelar
                      </button>
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-3 gap-4">
                  {/* IP */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1 flex items-center gap-1.5">
                      IP
                      <span className="text-[10px] text-[#6b7280] bg-[#0f1117] border border-[#1e2530] px-1.5 py-0.5 rounded font-mono normal-case tracking-normal">Inmutable</span>
                    </div>
                    <div className="text-white font-mono text-sm">{asset.ip}</div>
                  </div>

                  {/* Hostname */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Hostname</div>
                    {editing
                      ? <input value={editForm.hostname} onChange={e => setEditForm(p => ({ ...p, hostname: e.target.value }))} className={inputClass} placeholder="servidor-01.local" />
                      : <div className="text-white font-mono text-sm">{asset.hostname ?? '—'}</div>}
                  </div>

                  {/* Nombre personalizado */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Nombre personalizado</div>
                    {editing
                      ? <input value={editForm.nombre} onChange={e => setEditForm(p => ({ ...p, nombre: e.target.value }))} className={inputClass} placeholder="ej. Servidor Principal BBDD" />
                      : <div className="text-white text-sm">{asset.nombre ?? '—'}</div>}
                  </div>

                  {/* Tipo */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Tipo</div>
                    {editing
                      ? (
                        <select value={editForm.tipo} onChange={e => setEditForm(p => ({ ...p, tipo: e.target.value }))} className={inputClass}>
                          <option value="SERVER">SERVER</option>
                          <option value="ENDPOINT">ENDPOINT</option>
                          <option value="RED">RED</option>
                          <option value="APLICACION">APLICACION</option>
                          <option value="IOT">IOT</option>
                          <option value="OTRO">OTRO</option>
                        </select>
                      )
                      : <div className="text-white text-sm">{asset.tipo}</div>}
                  </div>

                  {/* Criticidad */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Criticidad</div>
                    {editing
                      ? (
                        <select value={editForm.criticidad} onChange={e => setEditForm(p => ({ ...p, criticidad: e.target.value }))} className={inputClass}>
                          <option value="BAJA">BAJA</option>
                          <option value="MEDIA">MEDIA</option>
                          <option value="ALTA">ALTA</option>
                          <option value="CRITICA">CRITICA</option>
                        </select>
                      )
                      : <Badge variant="outline" className={`border text-xs w-fit ${criticidadClass(asset.criticidad)}`}>{asset.criticidad}</Badge>}
                  </div>

                  {/* Responsable */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Responsable</div>
                    {editing
                      ? <input value={editForm.responsable} onChange={e => setEditForm(p => ({ ...p, responsable: e.target.value }))} className={inputClass} placeholder="admin@empresa.es" />
                      : <div className="text-white text-sm">{asset.responsable ?? '—'}</div>}
                  </div>

                  {/* Estado */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Estado</div>
                    {editing
                      ? (
                        <select value={editForm.status} onChange={e => setEditForm(p => ({ ...p, status: e.target.value }))} className={inputClass}>
                          <option value="ACTIVO">ACTIVO</option>
                          <option value="BAJA">BAJA</option>
                          <option value="MANTENIMIENTO">MANTENIMIENTO</option>
                          <option value="PENDIENTE_ALTA">PENDIENTE_ALTA</option>
                        </select>
                      )
                      : (
                        <div className="flex items-center gap-1.5">
                          <div className={`w-1.5 h-1.5 rounded-full ${statusDotClass(asset.status)}`} />
                          <span className="text-sm text-white">{asset.status}</span>
                        </div>
                      )}
                  </div>

                  {/* OS Family */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">OS Family</div>
                    {editing
                      ? (
                        <select value={editForm.os_family} onChange={e => setEditForm(p => ({ ...p, os_family: e.target.value }))} className={inputClass}>
                          <option value="">— Sin especificar —</option>
                          <option value="Linux">Linux</option>
                          <option value="Windows">Windows</option>
                          <option value="macOS">macOS</option>
                          <option value="FreeBSD">FreeBSD</option>
                          <option value="Other">Other</option>
                        </select>
                      )
                      : <div className="text-white text-sm">{asset.os_family ?? '—'}</div>}
                  </div>

                  {/* OS Version */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">OS Version</div>
                    {editing
                      ? <input value={editForm.os_version} onChange={e => setEditForm(p => ({ ...p, os_version: e.target.value }))} className={inputClass} placeholder="ej. Ubuntu 22.04 LTS" />
                      : <div className="text-white text-sm">{asset.os_version ?? '—'}</div>}
                  </div>

                  {/* Dominio */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Dominio</div>
                    {editing
                      ? <input value={editForm.dominio} onChange={e => setEditForm(p => ({ ...p, dominio: e.target.value }))} className={inputClass} placeholder="ej. corp.scanops.local" />
                      : <div className="text-white font-mono text-sm">{asset.dominio ?? '—'}</div>}
                  </div>

                  {/* Network Range */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Network Range</div>
                    {editing
                      ? <input value={editForm.network_range} onChange={e => setEditForm(p => ({ ...p, network_range: e.target.value }))} className={inputClass} placeholder="ej. 10.202.15.0/24" />
                      : <div className="text-white font-mono text-sm">{asset.network_range ?? '—'}</div>}
                  </div>

                  {/* Departamento */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Departamento</div>
                    {editing
                      ? <input value={editForm.departamento} onChange={e => setEditForm(p => ({ ...p, departamento: e.target.value }))} className={inputClass} placeholder="ej. Sistemas" />
                      : <div className="text-white text-sm">{asset.departamento ?? '—'}</div>}
                  </div>

                  {/* Ubicación */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Ubicación</div>
                    {editing
                      ? <input value={editForm.ubicacion} onChange={e => setEditForm(p => ({ ...p, ubicacion: e.target.value }))} className={inputClass} placeholder="ej. Rack A-01" />
                      : <div className="text-white text-sm">{asset.ubicacion ?? '—'}</div>}
                  </div>

                  {/* MAC Address */}
                  <div>
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">MAC Address</div>
                    {editing
                      ? <input value={editForm.mac_address} onChange={e => setEditForm(p => ({ ...p, mac_address: e.target.value }))} className={inputClass} placeholder="AA:BB:CC:DD:EE:FF" />
                      : <div className="text-white font-mono text-sm">{asset.mac_address ?? '—'}</div>}
                  </div>

                  {/* Notas — full width */}
                  <div className="col-span-3">
                    <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-1">Notas</div>
                    {editing
                      ? <textarea value={editForm.notas} onChange={e => setEditForm(p => ({ ...p, notas: e.target.value }))} rows={3} className={`${inputClass} resize-none`} placeholder="Observaciones adicionales..." />
                      : <div className="text-sm text-[#9ca3af]">{asset.notas ?? '—'}</div>}
                  </div>
                </div>

                {/* ── Credenciales SSH ── */}
                <div className="mt-5 bg-[#1a1d27] border border-[#1e2530] rounded-xl p-5">
                  <div className="flex items-center gap-2 mb-4">
                    <Shield className="w-4 h-4 text-[#f59e0b]" />
                    <h3 className="text-sm font-semibold text-white">Credenciales SSH</h3>
                    <span className="text-xs text-[#4b5563]">· ENS op.acc.1 · Acceso a logs del activo</span>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="flex flex-col gap-1.5">
                      <label className="text-xs text-[#9ca3af]">Usuario SSH</label>
                      {editing ? (
                        <input
                          value={editForm.ssh_user}
                          onChange={e => setEditForm(p => ({ ...p, ssh_user: e.target.value }))}
                          placeholder="admin"
                          className={inputClass}
                        />
                      ) : (
                        <span className="text-sm font-mono text-white">
                          {asset.ssh_user || <span className="text-[#4b5563]">No configurado</span>}
                        </span>
                      )}
                    </div>
                    <div className="flex flex-col gap-1.5">
                      <label className="text-xs text-[#9ca3af]">Contraseña SSH</label>
                      {editing ? (
                        <input
                          type="password"
                          value={editForm.ssh_password}
                          onChange={e => setEditForm(p => ({ ...p, ssh_password: e.target.value }))}
                          placeholder="••••••••"
                          className={inputClass}
                        />
                      ) : (
                        <span className="text-sm font-mono text-white">
                          {asset.ssh_password ? '••••••••' : <span className="text-[#4b5563]">No configurada</span>}
                        </span>
                      )}
                    </div>
                  </div>
                  {!editing && asset.ssh_user && (
                    <div className="mt-3 flex items-center gap-1.5 text-xs text-[#22c55e]">
                      <CheckCircle2 className="w-3 h-3" />
                      Credenciales configuradas — los logs de acceso usarán estas credenciales
                    </div>
                  )}
                  {!editing && !asset.ssh_user && (
                    <div className="mt-3 flex items-center gap-1.5 text-xs text-[#f59e0b]">
                      <AlertCircle className="w-3 h-3" />
                      Sin credenciales — se usará el fallback <code className="font-mono">admin:test123</code>
                    </div>
                  )}
                </div>
              </div>

              {/* Card 2: Scan Results */}
              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-sm font-semibold text-[#9ca3af] uppercase tracking-wider">Resultados de escaneo</h2>
                  {vulns.length > 0 && (
                    <span className="px-2 py-0.5 rounded-full bg-[#1e2530] text-xs text-[#9ca3af] font-mono">{filteredVulns.length}/{vulns.length}</span>
                  )}
                </div>

                {vulns.length > 0 && (
                  <div className="flex items-center gap-2 mb-3">
                    <select
                      value={filterDate}
                      onChange={e => setFilterDate(e.target.value)}
                      className="bg-[#0f1117] border border-[#1e2530] text-sm text-[#9ca3af] rounded-lg px-3 py-1.5 focus:outline-none focus:border-[#00d4ff] transition-colors"
                    >
                      <option value="all">Todos los días</option>
                      {scanDates.map(d => <option key={d} value={d}>{d}</option>)}
                    </select>
                    <select
                      value={filterTool}
                      onChange={e => setFilterTool(e.target.value)}
                      className="bg-[#0f1117] border border-[#1e2530] text-sm text-[#9ca3af] rounded-lg px-3 py-1.5 focus:outline-none focus:border-[#00d4ff] transition-colors"
                    >
                      <option value="all">Todas las herramientas</option>
                      {scanTools.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </div>
                )}

                {vulnsLoading ? (
                  <div className="flex items-center gap-2 text-xs text-[#6b7280] py-4">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Cargando resultados...
                  </div>
                ) : vulns.length === 0 ? (
                  <div className="text-center py-6 space-y-3">
                    <p className="text-sm text-[#6b7280]">Sin resultados de escaneo.</p>
                    <button
                      onClick={handleFullScan}
                      disabled={fullScanState.status === 'scanning'}
                      className="flex items-center gap-2 px-4 py-2 bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] hover:text-white rounded-lg text-sm transition-colors mx-auto disabled:opacity-60"
                    >
                      {fullScanState.status === 'scanning' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                      Lanzar escaneo completo
                    </button>
                  </div>
                ) : filteredVulns.length === 0 ? (
                  <p className="text-sm text-[#6b7280] py-4 text-center">Sin resultados para los filtros seleccionados.</p>
                ) : (
                  <div className="space-y-2">
                    {filteredVulns.map((v) => (
                      <div
                        key={v.id}
                        className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-3 space-y-1.5 cursor-pointer hover:border-[#374151] transition-colors"
                        onClick={() => setExpandedVuln(expandedVuln === v.id ? null : v.id)}
                      >
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
                          {v.created_at && (
                            <span className="text-[10px] text-[#6b7280] font-mono">
                              {fmt.format(new Date(v.created_at))}
                            </span>
                          )}
                        </div>
                        {expandedVuln === v.id && (
                          <div className="text-xs text-[#9ca3af] mt-2 pt-2 border-t border-[#1e2530]">
                            <p className="font-mono text-[10px] text-[#6b7280] mb-1">
                              IP: {asset.ip} · Herramienta: {v.tool_source} · {new Date(v.created_at).toLocaleDateString('es-ES')}
                            </p>
                            <p className="line-clamp-none">{v.title}</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* RIGHT: col-span-5 */}
            <div className="col-span-5 space-y-5">

              {/* Card 3: Launch Scan */}
              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
                <h2 className="text-sm font-semibold text-[#9ca3af] uppercase tracking-wider mb-4">Lanzar escaneo</h2>

                <div className="flex items-center gap-2 mb-4">
                  {SCAN_TOOLS.map((tool) => (
                    <button
                      key={tool}
                      onClick={() => setSelectedTool(tool)}
                      className={`px-3 py-1.5 text-xs rounded border transition-colors ${
                        selectedTool === tool
                          ? 'border-[#00d4ff]/50 text-[#00d4ff] bg-[#00d4ff]/10'
                          : 'border-[#1e2530] text-[#6b7280] bg-[#1a1d27] hover:border-[#374151] hover:text-[#9ca3af]'
                      }`}
                    >
                      {tool}
                    </button>
                  ))}
                </div>

                <button
                  onClick={handleScan}
                  disabled={scanState.status === 'scanning'}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] hover:bg-[#00d4ff]/20 rounded-lg text-sm font-semibold transition-colors disabled:opacity-60 disabled:cursor-not-allowed mb-3"
                >
                  {scanState.status === 'scanning' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                  Iniciar escaneo
                </button>

                {scanState.status === 'scanning' && scanState.msg && <p className="text-xs text-[#00d4ff] font-mono text-center mb-2 animate-pulse">{scanState.msg}</p>}
                {scanState.status === 'done' && <p className="text-xs text-[#22c55e] font-mono text-center mb-2">{scanState.msg}</p>}
                {scanState.status === 'error' && <p className="text-xs text-[#ff3b3b] font-mono text-center mb-2">{scanState.msg}</p>}

                <button
                  onClick={handleFullScan}
                  disabled={fullScanState.status === 'scanning'}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-[#1e2530] border border-[#1e2530] text-[#9ca3af] hover:text-white rounded-lg text-sm transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {fullScanState.status === 'scanning' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                  Escaneo completo (nuclei + nikto)
                </button>

                {fullScanState.status === 'scanning' && fullScanState.msg && <p className="text-xs text-[#00d4ff] font-mono text-center mt-2 animate-pulse">{fullScanState.msg}</p>}
                {fullScanState.status === 'done' && <p className="text-xs text-[#22c55e] font-mono text-center mt-2">{fullScanState.msg}</p>}
                {fullScanState.status === 'error' && <p className="text-xs text-[#ff3b3b] font-mono text-center mt-2">{fullScanState.msg}</p>}
              </div>

              {/* Card 4: ENS Metadata */}
              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
                <h2 className="text-sm font-semibold text-[#9ca3af] uppercase tracking-wider mb-4">Trazabilidad ENS Alto</h2>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  {([
                    ['ID interno',            String(asset.id)],
                    ['Fecha de registro',     asset.created_at  ? fmt.format(new Date(asset.created_at))  : '—'],
                    ['Última actualización',  asset.updated_at  ? fmt.format(new Date(asset.updated_at))  : '—'],
                    ['Descubierto por',       asset.discovered_by ?? 'Registro manual'],
                    ['Fuente externa',        asset.external_source ?? '—'],
                    ['Rango de red',          asset.network_range   ?? '—'],
                  ] as [string, string][]).map(([label, value]) => (
                    <div key={label}>
                      <div className="text-[10px] text-[#6b7280] uppercase font-semibold tracking-wider mb-0.5">{label}</div>
                      <div className="text-white font-mono">{value}</div>
                    </div>
                  ))}
                </div>
                <p className="text-[10px] text-[#6b7280] mt-4 pt-3 border-t border-[#1e2530]">
                  ENS op.exp.1 · RD 311/2022
                </p>
              </div>

              {/* Card 5: Quick Actions */}
              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
                <h2 className="text-sm font-semibold text-[#9ca3af] uppercase tracking-wider mb-4">Acciones rápidas</h2>
                <div className="space-y-2">
                  {([
                    ['Ver en M2+M3 Scanner',  '/surface'],
                    ['Ver en M8 IA Reasoning', '/ai-reasoning'],
                    ['Ver en M4 Explotación',  '/exploitation'],
                  ] as [string, string][]).map(([label, path]) => (
                    <button
                      key={path}
                      onClick={() => {
                        if (path === '/surface') {
                          // Enviamos la IP y la pestaña destino en el estado de la navegación
                          navigate(path, { 
                            state: { 
                              searchIp: asset.ip, 
                              defaultTab: 'findings' 
                            } 
                          });
                        } else {
                          navigate(path);
                        }
                      }}
                      className="w-full px-4 py-2.5 text-sm text-[#9ca3af] border border-[#1e2530] rounded-lg hover:text-white hover:border-[#374151] transition-colors text-left cursor-pointer"
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

            </div>
          </div>
          )} {/* end activeTab === 'info' */}

          {activeTab === 'logs' && (
          <div className="space-y-4">

            {/* KPI card del activo */}
            {logStat && (
              <div className={`bg-[#1a1d27] border rounded-xl p-4 ${logStat.critical_count > 0 ? 'border-[#ff3b3b]/40' : logStat.high_count > 0 ? 'border-[#f59e0b]/30' : 'border-[#1e2530]'}`}>
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <div className="text-sm font-semibold text-[#a78bfa]">{asset.nombre || asset.hostname || asset.ip}</div>
                    <div className="text-[10px] font-mono text-[#4b5563]">{asset.ip}</div>
                  </div>
                  {(logStat.critical_count > 0 || logStat.high_count > 0) && (
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${logStat.critical_count > 0 ? 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]' : 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]'}`}>
                      {logStat.critical_count > 0 ? `${logStat.critical_count} CRITICAL` : `${logStat.high_count} HIGH`}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-4 gap-2 text-center">
                  <div className="bg-[#0f1117] rounded-lg p-2"><div className="text-lg font-bold text-white">{logStat.total}</div><div className="text-[10px] text-[#6b7280]">Total</div></div>
                  <div className="bg-[#0f1117] rounded-lg p-2"><div className={`text-lg font-bold ${logStat.failures > 0 ? 'text-[#ff3b3b]' : 'text-white'}`}>{logStat.failures}</div><div className="text-[10px] text-[#6b7280]">Fallos</div></div>
                  <div className="bg-[#0f1117] rounded-lg p-2"><div className="text-lg font-bold text-[#22c55e]">{logStat.successes}</div><div className="text-[10px] text-[#6b7280]">Éxitos</div></div>
                  <div className="bg-[#0f1117] rounded-lg p-2"><div className={`text-lg font-bold ${logStat.sudo_cmds > 0 ? 'text-[#a78bfa]' : 'text-white'}`}>{logStat.sudo_cmds}</div><div className="text-[10px] text-[#6b7280]">Sudo</div></div>
                </div>
                <div className="mt-2 flex gap-3 text-[10px] text-[#6b7280]">
                  <span>{logStat.unique_users.length} usuario{logStat.unique_users.length !== 1 ? 's' : ''}</span>
                  <span>·</span>
                  <span>{logStat.unique_ips.length} IP{logStat.unique_ips.length !== 1 ? 's' : ''} origen</span>
                </div>
              </div>
            )}

            {/* Alerta brute force */}
            {logBruteIPs.length > 0 && (
              <div className="flex items-start gap-3 px-4 py-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 rounded-xl">
                <ShieldAlert className="w-4 h-4 text-[#ff3b3b] mt-0.5 shrink-0" />
                <div>
                  <div className="text-sm font-semibold text-[#ff3b3b]">⚠ Fuerza bruta detectada</div>
                  <div className="text-xs text-[#9ca3af] mt-0.5">IPs con ≥5 fallos en 10 min: <span className="font-mono text-white">{logBruteIPs.join(', ')}</span></div>
                  <div className="text-[10px] text-[#6b7280] mt-1">ENS op.acc.6 — Bloqueo recomendado</div>
                </div>
              </div>
            )}

            {/* Tabla */}
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl overflow-hidden flex flex-col">

              {/* Header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2530]">
                <div className="flex items-center gap-2">
                  <Monitor className="w-4 h-4 text-[#a78bfa]" />
                  <span className="text-sm font-semibold text-white">Logs de Acceso</span>
                  <span className="text-xs text-[#4b5563]">· SSH auth.log · ENS op.acc.1, op.acc.6, op.exp.5</span>
                </div>
                <div className="flex items-center gap-2">
                  {logLastLoad && <span className="text-[10px] text-[#4b5563] font-mono">Última carga: {fmtTimeAsset(logLastLoad.toISOString())}</span>}
                  <button
                    onClick={() => setLogLiveMode(m => !m)}
                    className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded border transition-colors ${
                      logLiveMode
                        ? 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]'
                        : 'border-[#1e2530] text-[#9ca3af] hover:text-white hover:border-[#374151]'
                    }`}
                    title={logLiveMode ? 'Desactivar refresco automático' : 'Activar refresco automático cada 60s'}
                  >
                    {logLiveMode && <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] animate-pulse" />}
                    {logLiveMode ? `Live · ${logLiveCountdown}s` : 'Live'}
                  </button>
                  <button onClick={loadLogs} disabled={logLoading}
                    className="flex items-center gap-1.5 text-xs text-[#9ca3af] hover:text-[#a78bfa] transition-colors disabled:opacity-50">
                    <RefreshCw className={`w-3.5 h-3.5 ${logLoading ? 'animate-spin' : ''}`} />
                    Actualizar
                  </button>
                  {!logLoading && logFiltered.length > 0 && (
                    <button onClick={exportLogsCSV}
                      className="flex items-center gap-1.5 text-xs font-semibold text-white bg-[#a78bfa] hover:bg-[#9061f9] transition-colors px-3 py-1.5 rounded-lg">
                      <Download className="w-3.5 h-3.5" /> Exportar CSV
                    </button>
                  )}
                </div>
              </div>

              {/* Filtros */}
              <div className="px-4 py-3 border-b border-[#1e2530] grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2 items-end">
                <div className="col-span-2 flex flex-col gap-1">
                  <label className="text-[10px] text-[#6b7280] uppercase tracking-wider">Búsqueda</label>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#4b5563]" />
                    <input value={logSearch} onChange={e => setLogSearch(e.target.value)}
                      placeholder="usuario, IP, comando..."
                      className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-[#374151] focus:outline-none focus:border-[#a78bfa]" />
                  </div>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-[#6b7280] uppercase tracking-wider">Desde</label>
                  <input type="date" value={logDateFrom} onChange={e => setLogDateFrom(e.target.value)}
                    className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa] [color-scheme:dark]" />
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-[#6b7280] uppercase tracking-wider">Hasta</label>
                  <input type="date" value={logDateTo} onChange={e => setLogDateTo(e.target.value)}
                    className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa] [color-scheme:dark]" />
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-[#6b7280] uppercase tracking-wider">Tipo acción</label>
                  <select value={logFilterAction} onChange={e => setLogFilterAction(e.target.value)}
                    className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa]">
                    <option value="ALL">Todas</option>
                    <option value="SSH_LOGIN_OK">SSH OK</option>
                    <option value="SSH_LOGIN_FAIL">SSH Fail</option>
                    <option value="SSH_INVALID_USER">Inválido</option>
                    <option value="SESSION_OPEN">Sesión abierta</option>
                    <option value="SESSION_CLOSE">Sesión cerrada</option>
                    <option value="SUDO_COMMAND">Sudo</option>
                    <option value="SUDO_FAIL">Sudo fail</option>
                    <option value="SU_OK">Su OK</option>
                    <option value="SU_FAIL">Su fail</option>
                    <option value="USER_CREATED">Usuario creado</option>
                    <option value="USER_DELETED">Usuario eliminado</option>
                    <option value="PASSWORD_CHANGED">Passwd cambiada</option>
                    <option value="ACCOUNT_LOCKED">Cuenta bloqueada</option>
                    <option value="AUTH_FAILURE">Auth failure</option>
                    <option value="PRIV_ESCALATION">Escalada</option>
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-[#6b7280] uppercase tracking-wider">Severidad</label>
                  <select value={logFilterSeverity} onChange={e => setLogFilterSeverity(e.target.value)}
                    className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-[#a78bfa]">
                    <option value="ALL">Todas</option>
                    {logSeverities.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div className="flex gap-1.5 items-end">
                  <button onClick={() => setLogPage(1)}
                    className="flex-1 text-xs font-semibold text-white bg-[#00d4ff] hover:bg-[#00b8d9] transition-colors px-3 py-1.5 rounded-lg">
                    Filtrar
                  </button>
                  <button onClick={() => {
                    setLogSearch(''); setLogFilterAction('ALL'); setLogFilterSeverity('ALL');
                    setLogFilterResult('ALL'); setLogFilterIP('ALL');
                    setLogDateFrom(''); setLogDateTo(''); setLogPage(1);
                  }}
                    className="text-xs text-[#9ca3af] hover:text-white border border-[#1e2530] hover:border-[#4b5563] transition-colors px-2 py-1.5 rounded-lg">
                    <XCircle className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Contenido */}
              <div className="flex-1 overflow-auto min-h-[300px]">
                {logLoading && <div className="flex justify-center items-center py-10"><Loader2 className="w-5 h-5 animate-spin text-[#a78bfa]" /></div>}
                {!logLoading && logError && (
                  <div className="m-4 flex items-center gap-2 px-4 py-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg text-sm text-[#ff3b3b]">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    M5 SIEM no disponible — no se pudo conectar a <code className="font-mono text-xs">localhost:8006</code>
                  </div>
                )}
                {!logLoading && !logError && logFiltered.length === 0 && (
                  <p className="text-[#6b7280] text-sm text-center py-8">
                    {logEvents.length === 0
                      ? `Sin logs de acceso registrados para ${asset.ip}.`
                      : 'Sin resultados para los filtros aplicados.'}
                  </p>
                )}
                {!logLoading && !logError && logFiltered.length > 0 && (
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-[#1a1d27] z-10">
                      <tr className="text-left text-[#6b7280] border-b border-[#1e2530]">
                        <th className="px-3 py-2 font-medium">Fecha / Hora</th>
                        <th className="px-3 py-2 font-medium">Usuario</th>
                        <th className="px-3 py-2 font-medium">Tipo Acción</th>
                        <th className="px-3 py-2 font-medium">Severidad</th>
                        <th className="px-3 py-2 font-medium">IP Origen</th>
                        <th className="px-3 py-2 font-medium">Puerto</th>
                        <th className="px-3 py-2 font-medium"></th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2530]">
                      {logPaged.map(ev => {
                        const sevColor: Record<string, string> = {
                          CRITICAL: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]',
                          HIGH:     'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]',
                          MEDIUM:   'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]',
                          LOW:      'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]',
                          INFO:     'bg-[#374151]/30 border-[#4b5563]/30 text-[#9ca3af]',
                        };
                        const isExp = logExpanded === ev.alert_id;
                        const isBF  = ev.src_ip != null && logBruteIPs.includes(ev.src_ip);
                        return (
                          <>
                            <tr key={ev.alert_id}
                              onClick={() => setLogExpanded(isExp ? null : ev.alert_id)}
                              className={`hover:bg-[#1e2530]/40 transition-colors cursor-pointer ${
                                ev.severity === 'CRITICAL' ? 'border-l-2 border-[#ff3b3b]' :
                                ev.severity === 'HIGH'     ? 'border-l-2 border-[#f59e0b]' : ''
                              }`}
                            >
                              <td className="px-3 py-2 font-mono text-[#9ca3af] whitespace-nowrap">{fmtDatetimeAsset(ev.timestamp)}</td>
                              <td className="px-3 py-2 font-mono text-white">{ev.src_user ?? <span className="text-[#4b5563]">—</span>}</td>
                              <td className="px-3 py-2">
                                <div className="flex items-center gap-1">
                                  <span className={`text-[10px] text-[#4b5563] transition-transform inline-block ${isExp ? 'rotate-90' : ''}`}>▶</span>
                                  {actionBadgeAsset(ev.action_type)}
                                </div>
                              </td>
                              <td className="px-3 py-2">
                                <span className={`inline-flex px-2 py-0.5 rounded-full border text-[10px] font-semibold ${sevColor[ev.severity] ?? sevColor.INFO}`}>
                                  {ev.severity}
                                </span>
                              </td>
                              <td className="px-3 py-2 font-mono text-xs">
                                {ev.src_ip
                                  ? <span className={isBF ? 'text-[#ff3b3b] font-semibold' : 'text-[#9ca3af]'}>
                                      {ev.src_ip}{isBF && <span className="ml-1">⚠</span>}
                                    </span>
                                  : <span className="text-[#4b5563]">—</span>}
                              </td>
                              <td className="px-3 py-2 font-mono text-[#6b7280]">{ev.port ?? '—'}</td>
                              <td className="px-3 py-2 w-4" />
                            </tr>
                            {isExp && (
                              <tr key={`${ev.alert_id}-d`}>
                                <td colSpan={7} className="px-4 py-3 bg-[#0f1117] border-l-2 border-[#a78bfa]">
                                  <div className="space-y-3 text-xs">
                                    <div>
                                      <span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-1">Raw Log</span>
                                      <code className="text-[#9ca3af] font-mono break-all leading-5">{ev.raw_log}</code>
                                    </div>
                                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                                      <div>
                                        <span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">Resultado</span>
                                        <span className={ev.success ? 'text-[#22c55e] font-semibold' : 'text-[#ff3b3b] font-semibold'}>
                                          {ev.success ? '✓ EXITOSO' : '✗ FALLIDO'}
                                        </span>
                                      </div>
                                      <div>
                                        <span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">Timestamp UTC</span>
                                        <span className="text-white font-mono">{ev.timestamp}</span>
                                      </div>
                                      {ev.command && (
                                        <div className="col-span-2">
                                          <span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">Comando ejecutado</span>
                                          <code className="text-[#a78bfa] font-mono">{ev.command}</code>
                                        </div>
                                      )}
                                      {ev.mitre_tactic && (
                                        <div>
                                          <span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">MITRE Táctica</span>
                                          <span className="text-white">{ev.mitre_tactic}</span>
                                        </div>
                                      )}
                                      {ev.mitre_technique && (
                                        <div>
                                          <span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">MITRE Técnica</span>
                                          <span className="text-white font-mono">{ev.mitre_technique}</span>
                                        </div>
                                      )}
                                      <div>
                                        <span className="text-[10px] text-[#6b7280] uppercase tracking-wider block mb-0.5">Norma ENS</span>
                                        <span className="text-[#00d4ff]">op.acc.1 · op.acc.6 · op.exp.5</span>
                                      </div>
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Paginación */}
              {logTotalPages > 1 && (
                <div className="flex items-center justify-between px-4 py-2 border-t border-[#1e2530]">
                  <button onClick={() => setLogPage(p => Math.max(1, p - 1))} disabled={logPage === 1}
                    className="text-xs text-[#9ca3af] hover:text-white disabled:opacity-30 px-3 py-1 rounded border border-[#1e2530] hover:border-[#a78bfa] transition-colors">
                    ← Anterior
                  </button>
                  <span className="text-xs text-[#6b7280]">
                    Página {logPage} de {logTotalPages} · {logFiltered.length} de {logEvents.length} eventos
                  </span>
                  <button onClick={() => setLogPage(p => Math.min(logTotalPages, p + 1))} disabled={logPage === logTotalPages}
                    className="text-xs text-[#9ca3af] hover:text-white disabled:opacity-30 px-3 py-1 rounded border border-[#1e2530] hover:border-[#a78bfa] transition-colors">
                    Siguiente →
                  </button>
                </div>
              )}

              {/* Footer */}
              <div className="px-4 py-2 border-t border-[#1e2530] flex items-center justify-between text-[10px] text-[#4b5563] font-mono">
                <span>{logFiltered.length} eventos filtrados · {logEvents.length} total</span>
                <span>ENS RD 311/2022 · op.acc.1 · op.acc.6 · op.exp.5</span>
              </div>
            </div>
          </div>
          )} {/* end activeTab === 'logs' */}

        </main>
      </div>

      {/* Pipeline Modal */}
      {pipelineOpen && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-2xl w-full max-w-2xl mx-4 mb-4 sm:mb-0 shadow-2xl flex flex-col max-h-[80vh]">

            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2530]">
              <div className="flex items-center gap-3">
                <Zap className="w-5 h-5 text-[#a78bfa]"/>
                <div>
                  <h3 className="text-sm font-bold text-white">Pipeline Completo — {asset?.ip}</h3>
                  <p className="text-xs text-[#6b7280]">M2 → M3 → M8 → M4</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => {
                    setPipelineLogs([]);
                    setPipelineErrors([]);
                    setPipelinePhase('idle');
                    setPipelineAuthorized(false);
                    setPipelineExecResult(null);
                    try { sessionStorage.removeItem(`scanops_pipeline_${asset?.id}`); } catch {}
                  }}
                  className="text-[10px] text-[#4b5563] hover:text-[#9ca3af] font-mono underline"
                >
                  Limpiar
                </button>
                {(['m2','m3','m8','m4'] as const).map((phase, i) => (
                  <div key={phase} className={`text-xs font-mono px-2 py-0.5 rounded border ${
                    pipelinePhase === phase
                      ? 'bg-[#a78bfa]/20 border-[#a78bfa]/40 text-[#a78bfa] animate-pulse'
                      : (['done','error'].includes(pipelinePhase) && i < 4) || (['m3','m8','m4'].indexOf(phase) < ['m2','m3','m8','m4'].indexOf(pipelinePhase as any))
                        ? 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]'
                        : 'bg-[#1e2530] border-[#374151] text-[#4b5563]'
                  }`}>
                    {phase.toUpperCase()}
                  </div>
                ))}
                {!pipelineRunning && (
                  <button onClick={() => setPipelineOpen(false)} className="text-[#6b7280] hover:text-white text-lg">×</button>
                )}
              </div>
            </div>

            {/* Error banner */}
            {pipelineErrors.length > 0 && (
              <div className="mx-4 mt-3 bg-[#ff3b3b]/10 border border-[#ff3b3b]/20 rounded-lg px-4 py-2.5">
                <div className="flex items-center gap-2 mb-1.5">
                  <AlertCircle className="w-4 h-4 text-[#ff3b3b] shrink-0"/>
                  <span className="text-xs font-bold text-[#ff3b3b]">
                    {pipelineErrors.length} error{pipelineErrors.length > 1 ? 'es' : ''} en el pipeline
                  </span>
                </div>
                <ul className="space-y-0.5">
                  {pipelineErrors.map((e, i) => (
                    <li key={i} className="text-[10px] text-[#ff3b3b] font-mono">• {e}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Log terminal */}
            <div ref={pipelineLogRef}
                 className="flex-1 overflow-y-auto bg-[#0f1117] p-4 font-mono text-xs space-y-0.5 min-h-[200px]">
              {pipelineLogs.length === 0 && (
                <p className="text-[#374151]">Iniciando pipeline...</p>
              )}
              {pipelineLogs.map((l, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-[#374151] shrink-0">{l.ts}</span>
                  <span className={
                    l.level === 'success' ? 'text-[#22c55e]' :
                    l.level === 'error'   ? 'text-[#ff3b3b]' :
                    l.level === 'warn'    ? 'text-[#f59e0b]' :
                    'text-[#9ca3af]'
                  }>{l.msg}</span>
                </div>
              ))}
              {pipelineRunning && (
                <div className="flex items-center gap-2 text-[#a78bfa] mt-2">
                  <Loader2 className="w-3 h-3 animate-spin"/>
                  <span>Procesando...</span>
                </div>
              )}
            </div>

            {/* Footer — QR cuando done */}
            {pipelinePhase === 'done' && (
              <div className="px-5 py-4 border-t border-[#1e2530] space-y-3">

                {/* Fila QR + Ir a M4 */}
                <div className="flex items-center gap-4">
                  {pipelineQr && (
                    <>
                      <img src={`data:image/png;base64,${pipelineQr}`}
                           alt="QR TOTP M4" className="w-16 h-16 rounded border border-[#1e2530]"/>
                      <div>
                        <p className="text-xs font-semibold text-white">Aprobación #{pipelineApprovalId} lista en M4</p>
                        <p className="text-xs text-[#6b7280] mt-0.5">Escanea el QR con Google Authenticator</p>
                        <p className="text-xs text-[#f59e0b] font-mono mt-0.5">PIN: 1234</p>
                      </div>
                    </>
                  )}
                  <button
                    onClick={() => window.open('/exploitation', '_blank')}
                    className="ml-auto px-4 py-2 bg-[#a78bfa]/10 border border-[#a78bfa]/30 text-[#a78bfa] rounded-lg text-xs font-semibold hover:bg-[#a78bfa]/20">
                    Ir a M4 →
                  </button>
                </div>

                {/* Botón confirmación */}
                {!pipelineAuthorized ? (
                  <button
                    onClick={async () => {
                      setPipelineAuthorized(true);
                      plog(`[✓] AUTORIZACIÓN CONFIRMADA — Pipeline ENS completado al 100%`, 'success');
                      plog(`[✓] Evidencia registrada: M2+M3+M8+M4 — ENS op.exp.2, op.acc.5`, 'success');
                      try {
                        sessionStorage.setItem(
                          `scanops_pipeline_${asset?.id}`,
                          JSON.stringify({ logs: pipelineLogs, phase: 'authorized' })
                        );
                      } catch {}

                      if (pipelineApprovalId) {
                        plog(`[EXEC] Lanzando ataque de fuerza bruta SSH sobre ${asset?.ip}...`, 'warn');
                        try {
                          const execRes = await fetch(
                            `http://localhost:8004/api/m4/execute/${pipelineApprovalId}`,
                            {
                              method: 'POST',
                              headers: authHeader(),
                              signal: AbortSignal.timeout(30000),
                            }
                          );
                          if (execRes.ok) {
                            const execData = await execRes.json();
                            setPipelineExecResult(execData);
                            if (execData.success) {
                              plog(`[EXEC] ✓ ACCESO OBTENIDO`, 'success');
                              plog(`[EXEC]   → Target: ${execData.target_ip}:22 (SSH)`, 'success');
                              plog(`[EXEC]   → Usuario: admin | Contraseña: ${execData.password_found}`, 'success');
                              plog(`[EXEC]   → Intentos: ${execData.attempts} | Duración: ${execData.duration}s`, 'success');
                              plog(`[EXEC] ★ VULNERABILIDAD CONFIRMADA — Sistema comprometido`, 'error');
                            } else {
                              plog(`[EXEC] ✗ Sin credenciales válidas encontradas`, 'warn');
                              plog(`[EXEC]   → Intentos: ${execData.attempts} | Duración: ${execData.duration}s`, 'info');
                            }
                          } else {
                            plog(`[EXEC] ✗ Error al ejecutar: HTTP ${execRes.status}`, 'error');
                          }
                        } catch (e: any) {
                          plog(`[EXEC] ✗ Error de conexión: ${e.message}`, 'error');
                        }
                      }
                    }}
                    className="w-full py-2.5 bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] rounded-lg text-xs font-semibold hover:bg-[#22c55e]/20 transition-colors flex items-center justify-center gap-2">
                    <CheckCircle2 className="w-4 h-4"/>
                    He autorizado en M4 — Marcar pipeline como completado
                  </button>
                ) : (
                  <div className="w-full py-2.5 bg-[#22c55e]/20 border border-[#22c55e]/40 rounded-lg flex items-center justify-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-[#22c55e]"/>
                    <span className="text-xs font-bold text-[#22c55e]">Pipeline ENS completado al 100% ✓</span>
                  </div>
                )}

                {pipelineExecResult && (
                  <div className={`rounded-lg border p-3 ${
                    pipelineExecResult.success
                      ? 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30'
                      : 'bg-[#1e2530] border-[#374151]'
                  }`}>
                    <div className="flex items-center gap-2 mb-2">
                      {pipelineExecResult.success
                        ? <><ShieldAlert className="w-4 h-4 text-[#ff3b3b]"/>
                            <span className="text-xs font-bold text-[#ff3b3b]">VULNERABILIDAD EXPLOTADA</span></>
                        : <><Shield className="w-4 h-4 text-[#22c55e]"/>
                            <span className="text-xs font-bold text-[#22c55e]">Sin acceso obtenido</span></>
                      }
                    </div>
                    <div className="grid grid-cols-2 gap-1 text-[10px] font-mono">
                      <span className="text-[#6b7280]">Target:</span>
                      <span className="text-white">{pipelineExecResult.target_ip}:22</span>
                      <span className="text-[#6b7280]">Servicio:</span>
                      <span className="text-white">SSH</span>
                      {pipelineExecResult.success && (
                        <>
                          <span className="text-[#6b7280]">Credenciales:</span>
                          <span className="text-[#ff3b3b] font-bold">admin:{pipelineExecResult.password_found}</span>
                        </>
                      )}
                      <span className="text-[#6b7280]">Intentos:</span>
                      <span className="text-white">{pipelineExecResult.attempts}</span>
                      <span className="text-[#6b7280]">Duración:</span>
                      <span className="text-white">{pipelineExecResult.duration}s</span>
                    </div>
                  </div>
                )}

              </div>
            )}

            {/* Footer — Error */}
            {pipelinePhase === 'error' && (
              <div className="px-5 py-3 border-t border-[#1e2530] flex items-center gap-3">
                <AlertCircle className="w-4 h-4 text-[#ff3b3b]"/>
                <span className="text-xs text-[#ff3b3b]">Pipeline fallido — revisa los logs</span>
                <button
                  onClick={() => { setPipelineLogs([]); setPipelineErrors([]); setPipelinePhase('idle'); handleRunPipeline(); }}
                  className="ml-auto px-3 py-1.5 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] rounded text-xs hover:bg-[#ff3b3b]/20">
                  Reintentar
                </button>
              </div>
            )}

          </div>
        </div>
      )}

      {/* Delete Dialog */}
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
              <span className="font-mono text-white">{asset.ip}</span>{' '}
              del inventario. La operación quedará registrada en los logs de auditoría (ENS op.exp.1).
            </Dialog.Description>
            <div className="flex gap-3">
              <button
                onClick={handleDelete}
                disabled={deleteLoading}
                className="flex-1 flex items-center justify-center gap-2 py-2 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] hover:bg-[#ff3b3b]/20 font-semibold rounded-lg transition-colors disabled:opacity-60 text-sm"
              >
                {deleteLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
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
    </div>
  );
}
