import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import {
  CheckCircle2, AlertTriangle, XCircle, Download, FileText,
  Minus, Loader2, Search,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router';

const M7_BASE = 'http://localhost:8007';

function getToken(): string | null {
  try {
    const raw = sessionStorage.getItem('scanops_auth');
    return raw ? JSON.parse(raw)?.access_token ?? null : null;
  } catch { return null; }
}

function authH(): HeadersInit {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

interface ENSMeasure {
  id: string;
  name: string;
  category: string;
  categoryCode: string;
  implementedBy: string[];
  status: 'compliant' | 'partial' | 'non-compliant' | 'not-applicable';
  evidence: string;
}

const ENS_MEASURES: ENSMeasure[] = [
  // ─── ORGANIZACIÓN ─────────────────────────────────────────────
  { id: 'org.1', name: 'Política de seguridad', category: 'Organización', categoryCode: 'org',
    implementedBy: ['M1'], status: 'partial',
    evidence: 'Política de acceso a activos implementada en M1. PSI formal pendiente.' },
  { id: 'org.2', name: 'Normativa de seguridad', category: 'Organización', categoryCode: 'org',
    implementedBy: [], status: 'partial',
    evidence: 'Marco normativo ENS en desarrollo. RD 311/2022 mapeado en M8 RAG.' },
  { id: 'org.3', name: 'Procedimientos de seguridad', category: 'Organización', categoryCode: 'org',
    implementedBy: ['M4', 'M8'], status: 'compliant',
    evidence: 'Procedimiento de aprobación TOTP+PIN en M4. Human-in-the-loop validado en M8.' },
  { id: 'org.4', name: 'Proceso de autorización', category: 'Organización', categoryCode: 'org',
    implementedBy: ['M4'], status: 'compliant',
    evidence: 'Kill switch global + aprobación TOTP obligatoria antes de toda explotación (M4).' },

  // ─── PLANIFICACIÓN ────────────────────────────────────────────
  { id: 'op.pl.1', name: 'Análisis de riesgos', category: 'Planificación', categoryCode: 'op.pl',
    implementedBy: ['M3', 'M8'], status: 'compliant',
    evidence: 'M3 escanea vulnerabilidades. M8 prioriza por CVSS × criticidad activo. Ciclo semanal automatizado.' },
  { id: 'op.pl.2', name: 'Arquitectura de seguridad', category: 'Planificación', categoryCode: 'op.pl',
    implementedBy: ['M1', 'M2'], status: 'compliant',
    evidence: 'Inventario de activos (M1) + reconocimiento de superficie (M2) documentan la arquitectura.' },
  { id: 'op.pl.3', name: 'Adquisición de nuevos componentes', category: 'Planificación', categoryCode: 'op.pl',
    implementedBy: ['M1'], status: 'partial',
    evidence: 'Shadow IT tab en M1 detecta activos no registrados. Proceso formal de alta pendiente.' },
  { id: 'op.pl.4', name: 'Dimensionamiento', category: 'Planificación', categoryCode: 'op.pl',
    implementedBy: [], status: 'not-applicable',
    evidence: 'No aplica en el alcance actual del sistema.' },
  { id: 'op.pl.5', name: 'Componentes certificados', category: 'Planificación', categoryCode: 'op.pl',
    implementedBy: [], status: 'partial',
    evidence: 'Stack de herramientas open source auditadas. Certificación formal pendiente.' },

  // ─── CONTROL DE ACCESO ────────────────────────────────────────
  { id: 'op.acc.1', name: 'Identificación', category: 'Control de Acceso', categoryCode: 'op.acc',
    implementedBy: ['M1', 'M5'], status: 'compliant',
    evidence: 'JWT + MFA TOTP obligatorio. Identidades gestionadas en orchestrator.' },
  { id: 'op.acc.2', name: 'Requisitos de acceso', category: 'Control de Acceso', categoryCode: 'op.acc',
    implementedBy: ['M4'], status: 'compliant',
    evidence: 'RBAC implementado: system_manager / security_officer / auditor.' },
  { id: 'op.acc.3', name: 'Segregación de funciones', category: 'Control de Acceso', categoryCode: 'op.acc',
    implementedBy: ['M4'], status: 'partial',
    evidence: 'Roles diferenciados en frontend. Segregación Resp.Sistema/Resp.Seguridad en M4 pendiente de completar.' },
  { id: 'op.acc.4', name: 'Proceso de gestión de derechos', category: 'Control de Acceso', categoryCode: 'op.acc',
    implementedBy: ['M5'], status: 'partial',
    evidence: 'Wazuh monitoriza accesos. Gestión formal de altas/bajas pendiente.' },
  { id: 'op.acc.5', name: 'Mecanismo de autenticación', category: 'Control de Acceso', categoryCode: 'op.acc',
    implementedBy: ['M4', 'M8'], status: 'compliant',
    evidence: 'TOTP + PIN bloqueante en M4. MFA obligatorio en login. Sesión JWT 8h.' },
  { id: 'op.acc.6', name: 'Acceso local', category: 'Control de Acceso', categoryCode: 'op.acc',
    implementedBy: ['M5'], status: 'compliant',
    evidence: 'Wazuh HIDS monitoriza accesos locales en todos los agentes.' },
  { id: 'op.acc.7', name: 'Acceso remoto', category: 'Control de Acceso', categoryCode: 'op.acc',
    implementedBy: ['M2', 'M5'], status: 'compliant',
    evidence: 'M2 detecta servicios de acceso remoto expuestos. M5 monitoriza SSH/RDP.' },

  // ─── EXPLOTACIÓN ──────────────────────────────────────────────
  { id: 'op.exp.1', name: 'Inventario de activos', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M1'], status: 'compliant',
    evidence: 'Inventario CMDB centralizado en M1. CRUD completo, Shadow IT, integración Vault.' },
  { id: 'op.exp.2', name: 'Configuración de seguridad', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M3', 'M8', 'M7'], status: 'compliant',
    evidence: 'Nuclei+Nikto+Nmap en M3. IA mapea CVEs a medidas ENS en M8. Informe técnico en M7.' },
  { id: 'op.exp.3', name: 'Gestión de la configuración', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M1', 'M5'], status: 'compliant',
    evidence: 'Orchestrator gestiona ciclo semanal. Dashboard en tiempo real. Logs centralizados.' },
  { id: 'op.exp.4', name: 'Mantenimiento y actualizaciones', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M3'], status: 'partial',
    evidence: 'M3 detecta versiones vulnerables. Plan de remediación en M7. Aplicación de parches manual.' },
  { id: 'op.exp.5', name: 'Gestión de cambios', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M4', 'M5'], status: 'compliant',
    evidence: 'Audit logs inmutables en M4. Wazuh HIDS detecta cambios de configuración en M5.' },
  { id: 'op.exp.6', name: 'Protección frente a código dañino', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M5'], status: 'compliant',
    evidence: 'Suricata IPS bloquea tráfico malicioso. CrowdSec protección perimetral activa.' },
  { id: 'op.exp.7', name: 'Gestión de incidentes', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M5'], status: 'compliant',
    evidence: 'Alertas Telegram/Email en M5. LUCÍA (CCN-CERT) integration disponible. Honeypots Cowrie.' },
  { id: 'op.exp.8', name: 'Registro de la actividad de los usuarios', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M1', 'M5'], status: 'compliant',
    evidence: 'ScanLogger JSON en todos los módulos. Audit logs en M1. Graylog centralizado.' },
  { id: 'op.exp.9', name: 'Registro de la gestión de incidentes', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M5', 'M7'], status: 'compliant',
    evidence: 'Alertas persistidas en BD SIEM. Histórico de informes en M7.' },
  { id: 'op.exp.10', name: 'Protección de los registros de actividad', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M7'], status: 'compliant',
    evidence: 'PDFs AES-256 inmutables en M7. Cadena de custodia en disco.' },
  { id: 'op.exp.11', name: 'Protección de claves criptográficas', category: 'Explotación', categoryCode: 'op.exp',
    implementedBy: ['M1'], status: 'compliant',
    evidence: 'HashiCorp Vault gestiona todos los secretos. AES-256. ENS mp.info.3.' },

  // ─── SERVICIOS EXTERNOS ───────────────────────────────────────
  { id: 'op.ext.1', name: 'Contratación y acuerdos de nivel de servicio', category: 'Servicios Externos', categoryCode: 'op.ext',
    implementedBy: [], status: 'not-applicable',
    evidence: 'Plataforma interna. No aplica en alcance actual.' },
  { id: 'op.ext.2', name: 'Gestión diaria', category: 'Servicios Externos', categoryCode: 'op.ext',
    implementedBy: [], status: 'not-applicable',
    evidence: 'No aplica en alcance actual.' },

  // ─── CONTINUIDAD ──────────────────────────────────────────────
  { id: 'op.cont.1', name: 'Análisis de impacto', category: 'Continuidad', categoryCode: 'op.cont',
    implementedBy: ['M8'], status: 'partial',
    evidence: 'M8 evalúa impacto real de cada vulnerabilidad. Análisis formal BIA pendiente.' },
  { id: 'op.cont.2', name: 'Plan de continuidad', category: 'Continuidad', categoryCode: 'op.cont',
    implementedBy: ['M4'], status: 'partial',
    evidence: 'Kill switch de emergencia en M4. Plan BCP formal pendiente.' },
  { id: 'op.cont.3', name: 'Pruebas periódicas', category: 'Continuidad', categoryCode: 'op.cont',
    implementedBy: ['M4'], status: 'partial',
    evidence: 'Ciclo semanal automatizado como prueba continua. Tests E2E Playwright pendientes.' },

  // ─── MONITORIZACIÓN ───────────────────────────────────────────
  { id: 'op.mon.1', name: 'Detección de intrusión', category: 'Monitorización', categoryCode: 'op.mon',
    implementedBy: ['M5'], status: 'compliant',
    evidence: 'Suricata IDS/IPS + Wazuh HIDS + Cowrie honeypot activos 24/7.' },
  { id: 'op.mon.2', name: 'Sistema de métricas', category: 'Monitorización', categoryCode: 'op.mon',
    implementedBy: ['M5', 'M7'], status: 'compliant',
    evidence: 'KPIs SIEM en tiempo real. Dashboard métricas globales. Informes M7 semanales.' },

  // ─── PERSONAL ─────────────────────────────────────────────────
  { id: 'mp.per.1', name: 'Caracterización del puesto de trabajo', category: 'Personal', categoryCode: 'mp.per',
    implementedBy: [], status: 'partial',
    evidence: 'Roles definidos (system_manager/security_officer/auditor). Perfiles formales pendientes.' },
  { id: 'mp.per.2', name: 'Deberes y obligaciones', category: 'Personal', categoryCode: 'mp.per',
    implementedBy: [], status: 'partial', evidence: 'Pendiente documentación formal.' },
  { id: 'mp.per.3', name: 'Concienciación', category: 'Personal', categoryCode: 'mp.per',
    implementedBy: [], status: 'partial', evidence: 'Pendiente plan de formación.' },
  { id: 'mp.per.4', name: 'Formación', category: 'Personal', categoryCode: 'mp.per',
    implementedBy: [], status: 'partial', evidence: 'Pendiente.' },
  { id: 'mp.per.5', name: 'Personal alternativo', category: 'Personal', categoryCode: 'mp.per',
    implementedBy: [], status: 'not-applicable', evidence: 'No aplica en alcance actual.' },

  // ─── EQUIPOS ──────────────────────────────────────────────────
  { id: 'mp.eq.1', name: 'Puesto de trabajo despejado', category: 'Equipos', categoryCode: 'mp.eq',
    implementedBy: [], status: 'not-applicable', evidence: 'No aplica en plataforma software.' },
  { id: 'mp.eq.2', name: 'Bloqueo de puesto de trabajo', category: 'Equipos', categoryCode: 'mp.eq',
    implementedBy: ['M5'], status: 'partial',
    evidence: 'Sesión JWT expira en 8h. Bloqueo automático pendiente.' },
  { id: 'mp.eq.3', name: 'Protección de portátiles', category: 'Equipos', categoryCode: 'mp.eq',
    implementedBy: [], status: 'not-applicable', evidence: 'No aplica.' },

  // ─── COMUNICACIONES ───────────────────────────────────────────
  { id: 'mp.com.1', name: 'Perímetro seguro', category: 'Comunicaciones', categoryCode: 'mp.com',
    implementedBy: ['M5'], status: 'compliant',
    evidence: 'Suricata IPS en perímetro. CrowdSec bloqueando IPs agresoras.' },
  { id: 'mp.com.2', name: 'Protección de la confidencialidad', category: 'Comunicaciones', categoryCode: 'mp.com',
    implementedBy: ['M1'], status: 'partial',
    evidence: 'Vault AES-256 para secretos. HTTPS pendiente de implementar (US-8.12).' },
  { id: 'mp.com.3', name: 'Protección de la autenticidad', category: 'Comunicaciones', categoryCode: 'mp.com',
    implementedBy: ['M4'], status: 'compliant',
    evidence: 'JWT firmado + TOTP en todas las operaciones críticas.' },
  { id: 'mp.com.4', name: 'Segregación de redes', category: 'Comunicaciones', categoryCode: 'mp.com',
    implementedBy: ['M4', 'M5'], status: 'partial',
    evidence: 'Honeypots en red aislada. Segmentación de red staging M4 pendiente.' },
  { id: 'mp.com.5', name: 'Medios alternativos', category: 'Comunicaciones', categoryCode: 'mp.com',
    implementedBy: [], status: 'not-applicable', evidence: 'No aplica.' },

  // ─── SOPORTES ─────────────────────────────────────────────────
  { id: 'mp.si.1', name: 'Etiquetado', category: 'Soportes', categoryCode: 'mp.si',
    implementedBy: ['M1'], status: 'compliant',
    evidence: 'Criticidad ENS en cada activo: BAJA/MEDIA/ALTA/CRITICA. Automático en M1.' },
  { id: 'mp.si.2', name: 'Criptografía', category: 'Soportes', categoryCode: 'mp.si',
    implementedBy: ['M1', 'M7'], status: 'compliant',
    evidence: 'Vault AES-256 para credenciales. PDFs AES-256 en M7. mp.info.3 + mp.info.4.' },
  { id: 'mp.si.3', name: 'Custodia', category: 'Soportes', categoryCode: 'mp.si',
    implementedBy: ['M7'], status: 'compliant',
    evidence: 'Histórico inmutable de auditorías en M7. Cadena de custodia persistida en disco.' },
  { id: 'mp.si.4', name: 'Transporte', category: 'Soportes', categoryCode: 'mp.si',
    implementedBy: [], status: 'partial', evidence: 'HTTPS pendiente (US-8.12).' },
  { id: 'mp.si.5', name: 'Borrado y destrucción', category: 'Soportes', categoryCode: 'mp.si',
    implementedBy: ['M1'], status: 'partial',
    evidence: 'Soft delete con deleted_at en M1. Borrado seguro formal pendiente.' },

  // ─── SOFTWARE ─────────────────────────────────────────────────
  { id: 'mp.sw.1', name: 'Desarrollo de aplicaciones', category: 'Software', categoryCode: 'mp.sw',
    implementedBy: [], status: 'partial',
    evidence: 'CI/CD con ruff+bandit en PRs. SSDLC formal pendiente.' },
  { id: 'mp.sw.2', name: 'Aceptación y puesta en servicio', category: 'Software', categoryCode: 'mp.sw',
    implementedBy: [], status: 'partial',
    evidence: '>80% cobertura tests pytest. Proceso formal de aceptación pendiente.' },

  // ─── INFORMACIÓN ──────────────────────────────────────────────
  { id: 'mp.info.1', name: 'Datos de carácter personal', category: 'Información', categoryCode: 'mp.info',
    implementedBy: [], status: 'partial',
    evidence: 'RGPD pendiente de análisis formal. No se procesan datos personales en el MVP.' },
  { id: 'mp.info.2', name: 'Calificación de la información', category: 'Información', categoryCode: 'mp.info',
    implementedBy: ['M1', 'M8'], status: 'compliant',
    evidence: 'Activos clasificados por criticidad. M8 mapea hallazgos a medidas ENS.' },
  { id: 'mp.info.3', name: 'Cifrado de la información', category: 'Información', categoryCode: 'mp.info',
    implementedBy: ['M1'], status: 'compliant',
    evidence: 'HashiCorp Vault AES-256. Credenciales nunca en texto plano. 6 secretos gestionados.' },
  { id: 'mp.info.4', name: 'Firma electrónica', category: 'Información', categoryCode: 'mp.info',
    implementedBy: ['M7'], status: 'compliant',
    evidence: 'PDFs firmados AES-256 con metadatos de autoría inmanipulables. PyMuPDF.' },
  { id: 'mp.info.5', name: 'Sellos de tiempo', category: 'Información', categoryCode: 'mp.info',
    implementedBy: ['M4', 'M7'], status: 'compliant',
    evidence: 'Timestamps UTC en todos los audit logs y evidencias M4. PDFs con fecha de generación.' },
  { id: 'mp.info.6', name: 'Limpieza de documentos', category: 'Información', categoryCode: 'mp.info',
    implementedBy: [], status: 'not-applicable', evidence: 'No aplica.' },

  // ─── SERVICIOS ────────────────────────────────────────────────
  { id: 'mp.s.1', name: 'Protección del correo electrónico', category: 'Servicios', categoryCode: 'mp.s',
    implementedBy: ['M5'], status: 'partial',
    evidence: 'SMTP configurado en M5 para alertas. Anti-spam/DKIM pendiente.' },
  { id: 'mp.s.2', name: 'Protección de servicios y aplicaciones web', category: 'Servicios', categoryCode: 'mp.s',
    implementedBy: ['M3', 'M5'], status: 'compliant',
    evidence: 'Nikto + ZAP + Nuclei escanean apps web en M3. Suricata protege perímetro web.' },
  { id: 'mp.s.3', name: 'Protección frente a la denegación de servicio', category: 'Servicios', categoryCode: 'mp.s',
    implementedBy: ['M5'], status: 'compliant',
    evidence: 'CrowdSec bloquea IPs agresoras automáticamente. Suricata IPS activo.' },
  { id: 'mp.s.4', name: 'Protección de los soportes de información', category: 'Servicios', categoryCode: 'mp.s',
    implementedBy: ['M7'], status: 'compliant',
    evidence: 'Informes cifrados AES-256. Histórico con cadena de custodia.' },
];

const compliantCount = ENS_MEASURES.filter(m => m.status === 'compliant').length;
const partialCount   = ENS_MEASURES.filter(m => m.status === 'partial').length;
const nonCompliant   = ENS_MEASURES.filter(m => m.status === 'non-compliant').length;
const notApplicable  = ENS_MEASURES.filter(m => m.status === 'not-applicable').length;
const applicable     = ENS_MEASURES.length - notApplicable;
const compliancePct  = Math.round((compliantCount / applicable) * 100);

const MODULE_ROUTES: Record<string, string> = {
  M1: '/assets', M2: '/surface', M3: '/surface',
  M4: '/exploitation', M5: '/alerts', M7: '/reporting', M8: '/ai-reasoning',
};

const ALL_CATEGORIES = [
  'Todas', 'Organización', 'Planificación', 'Control de Acceso', 'Explotación',
  'Monitorización', 'Personal', 'Comunicaciones', 'Soportes', 'Software',
  'Información', 'Servicios', 'Continuidad', 'Servicios Externos', 'Equipos',
];

interface HistoryFile {
  name: string;
  date: string;
}

export function CompliancePage() {
  const navigate = useNavigate();

  const [search, setSearch] = useState('');
  const [catFilter, setCatFilter] = useState('Todas');
  const [statusFilter, setStatusFilter] = useState('Todos');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [dlLoading, setDlLoading] = useState<Record<string, boolean>>({});
  const [dlError, setDlError]   = useState<Record<string, boolean>>({});

  const [history, setHistory]     = useState<HistoryFile[]>([]);
  const [histLoading, setHistLoading] = useState(true);
  const [histError, setHistError]   = useState(false);
  const [histDlLoading, setHistDlLoading] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${M7_BASE}/report/history`, {
          headers: authH(),
          signal: AbortSignal.timeout(6000),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json() as { archivos?: string[] };
        const files = (data.archivos ?? []).map((name: string) => {
          const m = name.match(/(\d{8})_(\d{6})/);
          let date = name;
          if (m) {
            const d = m[1];
            const t = m[2];
            date = `${d.slice(0,4)}-${d.slice(4,6)}-${d.slice(6,8)} ${t.slice(0,2)}:${t.slice(2,4)}`;
          }
          return { name, date };
        });
        setHistory(files);
      } catch {
        setHistError(true);
      } finally {
        setHistLoading(false);
      }
    };
    load();
  }, []);

  const handleDownload = async (url: string, filename: string, key: string) => {
    setDlLoading(p => ({ ...p, [key]: true }));
    setDlError(p => ({ ...p, [key]: false }));
    try {
      const res = await fetch(url, { headers: authH(), signal: AbortSignal.timeout(30000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(href);
    } catch {
      setDlError(p => ({ ...p, [key]: true }));
      setTimeout(() => setDlError(p => ({ ...p, [key]: false })), 4000);
    } finally {
      setDlLoading(p => ({ ...p, [key]: false }));
    }
  };

  const handleHistDownload = async (file: string) => {
    setHistDlLoading(p => ({ ...p, [file]: true }));
    try {
      const res = await fetch(`${M7_BASE}/report/history/${encodeURIComponent(file)}`, {
        headers: authH(),
        signal: AbortSignal.timeout(30000),
      });
      if (!res.ok) throw new Error();
      const blob = await res.blob();
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = file;
      a.click();
      URL.revokeObjectURL(href);
    } catch { /* silencioso */ } finally {
      setHistDlLoading(p => ({ ...p, [file]: false }));
    }
  };

  const filtered = ENS_MEASURES.filter(m => {
    const q = search.toLowerCase();
    const matchSearch = !q || m.id.toLowerCase().includes(q) || m.name.toLowerCase().includes(q);
    const matchCat = catFilter === 'Todas' || m.category === catFilter;
    const matchStatus =
      statusFilter === 'Todos' ||
      (statusFilter === 'Conforme' && m.status === 'compliant') ||
      (statusFilter === 'Parcial' && m.status === 'partial') ||
      (statusFilter === 'No conforme' && m.status === 'non-compliant') ||
      (statusFilter === 'No aplica' && m.status === 'not-applicable');
    return matchSearch && matchCat && matchStatus;
  });

  const scoreColor = compliancePct >= 80 ? '#22c55e' : compliancePct >= 60 ? '#f59e0b' : '#ff3b3b';

  const statusBadge = (status: ENSMeasure['status']) => {
    const cfg = {
      compliant:      { cls: 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]', icon: <CheckCircle2 className="w-3.5 h-3.5" />, label: 'Conforme' },
      partial:        { cls: 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]', icon: <AlertTriangle className="w-3.5 h-3.5" />, label: 'Parcial' },
      'non-compliant':{ cls: 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]', icon: <XCircle className="w-3.5 h-3.5" />, label: 'No conforme' },
      'not-applicable':{ cls: 'bg-[#374151]/30 border-[#4b5563]/30 text-[#6b7280]', icon: <Minus className="w-3.5 h-3.5" />, label: 'No aplica' },
    }[status];
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-xs font-semibold ${cfg.cls}`}>
        {cfg.icon}{cfg.label}
      </span>
    );
  };

  const selected = selectedId ? ENS_MEASURES.find(m => m.id === selectedId) : null;

  const REPORTS = [
    { key: 'executive', label: 'Informe Ejecutivo', url: `${M7_BASE}/report/executive`, filename: 'ScanOps_Informe_Ejecutivo.pdf' },
    { key: 'technical', label: 'Informe Técnico',   url: `${M7_BASE}/report/technical`, filename: 'ScanOps_Informe_Tecnico.pdf' },
    { key: 'soa',       label: 'Declaración de Aplicabilidad (SoA)', url: `${M7_BASE}/report/soa`, filename: 'ScanOps_SoA_ENS.pdf' },
    { key: 'audit',     label: 'Auditoría Completa (ZIP)', url: `${M7_BASE}/report/full-audit`, filename: 'ScanOps_Auditoria_Completa.zip' },
  ];

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="Auditor" />

        <main className="flex-1 overflow-auto p-6 space-y-6">

          {/* ── SECCIÓN A — Cabecera ── */}
          <div className="flex items-start justify-between gap-6 flex-wrap">
            <div>
              <h1 className="text-2xl font-semibold text-white mb-1">Cumplimiento ENS Alto</h1>
              <p className="text-[#9ca3af] text-sm">73 medidas del Anexo II — RD 311/2022</p>
            </div>
            {/* Score circular */}
            <div className="flex items-center gap-3">
              <div className="relative w-20 h-20">
                <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
                  <circle cx="40" cy="40" r="34" fill="none" stroke="#1e2530" strokeWidth="8" />
                  <circle
                    cx="40" cy="40" r="34" fill="none"
                    stroke={scoreColor} strokeWidth="8"
                    strokeDasharray={`${2 * Math.PI * 34}`}
                    strokeDashoffset={`${2 * Math.PI * 34 * (1 - compliancePct / 100)}`}
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-lg font-bold" style={{ color: scoreColor }}>{compliancePct}%</span>
                </div>
              </div>
              <div className="text-sm text-[#9ca3af]">
                <div className="font-semibold text-white mb-0.5">Índice de cumplimiento</div>
                <div>Mínimo ENS Alto: <span className="text-[#22c55e]">≥80%</span></div>
                <div className="text-xs mt-0.5">{applicable} medidas aplicables</div>
              </div>
            </div>
          </div>

          {/* 4 KPI cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Conformes',    value: compliantCount, color: '#22c55e' },
              { label: 'Parciales',    value: partialCount,   color: '#f59e0b' },
              { label: 'No conformes', value: nonCompliant,   color: '#ff3b3b' },
              { label: 'No aplica',    value: notApplicable,  color: '#6b7280' },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-4 flex items-center gap-3">
                <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: color }} />
                <div>
                  <div className="text-2xl font-bold text-white">{value}</div>
                  <div className="text-xs text-[#9ca3af]">{label}</div>
                </div>
              </div>
            ))}
          </div>

          {/* ── SECCIÓN B — Filtros + Tabla ── */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl overflow-hidden">
            {/* Filtros */}
            <div className="p-4 border-b border-[#1e2530] flex flex-wrap gap-3">
              <div className="relative flex-1 min-w-48">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#4b5563]" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Buscar por ID o nombre..."
                  className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder:text-[#374151] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
              <select
                value={catFilter}
                onChange={e => setCatFilter(e.target.value)}
                className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#00d4ff]"
              >
                {ALL_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#00d4ff]"
              >
                {['Todos', 'Conforme', 'Parcial', 'No conforme', 'No aplica'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <span className="text-xs text-[#6b7280] self-center">{filtered.length} medidas</span>
            </div>

            {/* Tabla */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-[#6b7280] border-b border-[#1e2530] bg-[#0f1117]/50">
                    <th className="px-4 py-3 font-medium w-24">ID</th>
                    <th className="px-4 py-3 font-medium">Nombre</th>
                    <th className="px-4 py-3 font-medium w-36">Categoría</th>
                    <th className="px-4 py-3 font-medium w-40">Módulos</th>
                    <th className="px-4 py-3 font-medium w-36">Estado</th>
                    <th className="px-4 py-3 font-medium">Evidencia</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2530]">
                  {filtered.map(m => (
                    <>
                      <tr
                        key={m.id}
                        onClick={() => setSelectedId(selectedId === m.id ? null : m.id)}
                        className="cursor-pointer hover:bg-[#1e2530]/50 transition-colors"
                      >
                        <td className="px-4 py-3 font-mono text-xs text-[#00d4ff]">{m.id}</td>
                        <td className="px-4 py-3 text-white text-sm">{m.name}</td>
                        <td className="px-4 py-3 text-[#9ca3af] text-xs">{m.category}</td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {m.implementedBy.length > 0
                              ? m.implementedBy.map(mod => (
                                  <span key={mod} className="px-1.5 py-0.5 bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/20 rounded text-xs font-mono">{mod}</span>
                                ))
                              : <span className="px-1.5 py-0.5 bg-[#374151]/30 text-[#6b7280] border border-[#4b5563]/20 rounded text-xs">Sin módulo</span>
                            }
                          </div>
                        </td>
                        <td className="px-4 py-3">{statusBadge(m.status)}</td>
                        <td className="px-4 py-3 text-xs text-[#9ca3af] max-w-xs truncate" title={m.evidence}>{m.evidence}</td>
                      </tr>

                      {/* Panel de detalle expandido */}
                      {selectedId === m.id && (
                        <tr key={`${m.id}-detail`}>
                          <td colSpan={6} className="px-6 py-5 bg-[#0f1117] border-l-2 border-[#00d4ff]">
                            <div className="space-y-4">
                              <div className="flex items-start justify-between gap-4 flex-wrap">
                                <div>
                                  <span className="font-mono text-[#00d4ff] text-sm font-bold">{m.id}</span>
                                  <span className="text-white font-semibold text-sm ml-2">{m.name}</span>
                                  <div className="text-xs text-[#9ca3af] mt-0.5">{m.category} · RD 311/2022 — Anexo II — {m.categoryCode}</div>
                                </div>
                                {statusBadge(m.status)}
                              </div>

                              <div>
                                <div className="text-xs text-[#6b7280] uppercase tracking-wider mb-1">Evidencia técnica</div>
                                <div className="text-sm text-white">{m.evidence}</div>
                              </div>

                              {m.implementedBy.length > 0 && (
                                <div>
                                  <div className="text-xs text-[#6b7280] uppercase tracking-wider mb-2">Módulos que la implementan</div>
                                  <div className="flex flex-wrap gap-2">
                                    {m.implementedBy.map(mod => (
                                      <button
                                        key={mod}
                                        onClick={e => { e.stopPropagation(); navigate(MODULE_ROUTES[mod] ?? '/dashboard'); }}
                                        className="px-3 py-1.5 bg-[#00d4ff]/10 hover:bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/30 rounded-lg text-xs font-semibold transition-colors"
                                      >
                                        Ver en {mod} →
                                      </button>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>

              {filtered.length === 0 && (
                <div className="text-center text-[#6b7280] text-sm py-12">Sin medidas que coincidan con los filtros.</div>
              )}
            </div>
          </div>

          {/* ── SECCIÓN C — Descarga de informes M7 ── */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Informes de cumplimiento</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {REPORTS.map(r => (
                <div key={r.key} className="flex items-center justify-between p-4 bg-[#0f1117] border border-[#1e2530] rounded-xl hover:border-[#00d4ff]/30 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-[#00d4ff]/10 rounded-lg flex items-center justify-center shrink-0">
                      <FileText className="w-5 h-5 text-[#00d4ff]" />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-white">{r.label}</div>
                      <div className="text-xs text-[#6b7280] font-mono">{r.filename}</div>
                    </div>
                  </div>
                  <button
                    onClick={() => handleDownload(r.url, r.filename, r.key)}
                    disabled={dlLoading[r.key]}
                    className="px-3 py-2 bg-[#00d4ff]/10 hover:bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/30 font-semibold rounded-lg transition-colors flex items-center gap-1.5 text-xs disabled:opacity-50 shrink-0"
                  >
                    {dlLoading[r.key]
                      ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Descargando...</>
                      : dlError[r.key]
                      ? <><XCircle className="w-3.5 h-3.5 text-[#ff3b3b]" /> Error</>
                      : <><Download className="w-3.5 h-3.5" /> Descargar</>
                    }
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* ── SECCIÓN D — Historial desde M7 ── */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Historial de auditorías</h2>

            {histLoading && (
              <div className="flex justify-center py-8">
                <Loader2 className="w-6 h-6 animate-spin text-[#00d4ff]" />
              </div>
            )}

            {!histLoading && histError && (
              <div className="flex items-center gap-2 px-4 py-3 bg-[#f59e0b]/10 border border-[#f59e0b]/20 rounded-lg text-sm text-[#f59e0b]">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                M7 no disponible — no se pudo cargar el historial.
              </div>
            )}

            {!histLoading && !histError && history.length === 0 && (
              <p className="text-[#6b7280] text-sm text-center py-6">Sin historial disponible.</p>
            )}

            {!histLoading && !histError && history.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-[#6b7280] border-b border-[#1e2530]">
                      <th className="pb-3 pr-4 font-medium">Archivo</th>
                      <th className="pb-3 pr-4 font-medium">Fecha</th>
                      <th className="pb-3 font-medium">Acciones</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2530]">
                    {history.map(f => (
                      <tr key={f.name} className="hover:bg-[#1e2530]/40 transition-colors">
                        <td className="py-3 pr-4 font-mono text-xs text-white">{f.name}</td>
                        <td className="py-3 pr-4 text-xs text-[#9ca3af] font-mono">{f.date}</td>
                        <td className="py-3">
                          <button
                            onClick={() => handleHistDownload(f.name)}
                            disabled={histDlLoading[f.name]}
                            className="px-3 py-1.5 bg-[#00d4ff]/10 hover:bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/30 rounded-lg transition-colors flex items-center gap-1.5 text-xs font-semibold disabled:opacity-50"
                          >
                            {histDlLoading[f.name]
                              ? <><Loader2 className="w-3 h-3 animate-spin" /> Descargando...</>
                              : <><Download className="w-3 h-3" /> Descargar</>
                            }
                          </button>
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
    </div>
  );
}
