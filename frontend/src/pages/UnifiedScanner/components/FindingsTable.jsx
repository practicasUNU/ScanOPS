import { useState, useMemo } from 'react';
import { ChevronUp, ChevronDown, Search, ShieldAlert } from 'lucide-react';
import { Badge } from '@/app/components/ui/badge';
import { ScrollArea } from '@/app/components/ui/scroll-area';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/app/components/ui/sheet';

// Fallback mock data — used when the API is unavailable or returns no findings
const MOCK_FINDINGS = [
  {
    id: 'F-001', activo: '10.0.1.10', herramienta: 'Nuclei',
    nombre: 'CVE-2024-1234 — Apache RCE',
    severidad: 'CRITICAL',
    medida_ens: 'op.exp.4',
    descripcion: 'Ejecución remota de código sin autenticación en Apache HTTP Server < 2.4.57.',
    articulo_ens: 'op.exp.4 — Protección frente a código dañino: el sistema no aplica medidas de detección y bloqueo de exploits conocidos.',
    cvss: '9.8', port: '80/tcp', cve: 'CVE-2024-1234',
  },
  {
    id: 'F-002', activo: '10.0.1.15', herramienta: 'Nmap',
    nombre: 'Puerto 3389 (RDP) expuesto',
    severidad: 'HIGH',
    medida_ens: 'mp.com.1',
    descripcion: 'El servicio RDP está accesible desde la red de gestión sin restricciones de IP.',
    articulo_ens: 'mp.com.1 — Perímetro seguro: acceso no autorizado a protocolos de administración remota.',
    cvss: '7.5', port: '3389/tcp', cve: null,
  },
  {
    id: 'F-003', activo: '10.0.1.20', herramienta: 'Trivy',
    nombre: 'Imagen Docker con paquetes vulnerables',
    severidad: 'HIGH',
    medida_ens: 'op.exp.4',
    descripcion: 'La imagen base nginx:1.19 contiene 14 CVEs con parche disponible.',
    articulo_ens: 'op.exp.4 — Actualización y parcheo: componentes sin actualizar con vulnerabilidades conocidas.',
    cvss: '7.2', port: null, cve: 'Multiple',
  },
  {
    id: 'F-004', activo: '10.0.1.10', herramienta: 'Nuclei',
    nombre: 'Cabeceras de seguridad ausentes (CSP, HSTS)',
    severidad: 'MEDIUM',
    medida_ens: 'mp.sw.1',
    descripcion: 'El servidor web no envía Content-Security-Policy ni Strict-Transport-Security.',
    articulo_ens: 'mp.sw.1 — Desarrollo de aplicaciones: ausencia de controles de seguridad en capa de transporte.',
    cvss: '4.3', port: '443/tcp', cve: null,
  },
  {
    id: 'F-005', activo: '10.0.1.30', herramienta: 'Nmap',
    nombre: 'SSH versión antigua (OpenSSH 7.2)',
    severidad: 'MEDIUM',
    medida_ens: 'op.exp.4',
    descripcion: 'OpenSSH 7.2 tiene vulnerabilidades de enumeración de usuarios.',
    articulo_ens: 'op.exp.4 — Gestión de vulnerabilidades: versiones desactualizadas en servicios de acceso remoto.',
    cvss: '5.3', port: '22/tcp', cve: 'CVE-2016-6210',
  },
  {
    id: 'F-006', activo: '10.0.1.25', herramienta: 'Trivy',
    nombre: 'Secreto hardcoded en imagen',
    severidad: 'CRITICAL',
    medida_ens: 'op.acc.6',
    descripcion: 'Se detectó una clave de API de AWS hardcodeada en la capa de la imagen Docker.',
    articulo_ens: 'op.acc.6 — Gestión de credenciales: credenciales en texto claro en artefactos de despliegue.',
    cvss: '9.1', port: null, cve: null,
  },
  {
    id: 'F-007', activo: '10.0.1.40', herramienta: 'Nuclei',
    nombre: 'Panel de administración sin autenticación',
    severidad: 'CRITICAL',
    medida_ens: 'op.acc.1',
    descripcion: 'El endpoint /admin es accesible sin credenciales desde la red interna.',
    articulo_ens: 'op.acc.1 — Control de acceso: recurso de administración sin mecanismo de autenticación.',
    cvss: '9.0', port: '8080/tcp', cve: null,
  },
  {
    id: 'F-008', activo: '10.0.1.50', herramienta: 'Nmap',
    nombre: 'Telnet habilitado',
    severidad: 'LOW',
    medida_ens: 'mp.com.1',
    descripcion: 'El puerto 23 está abierto. Telnet transmite credenciales en texto claro.',
    articulo_ens: 'mp.com.1 — Cifrado en tránsito: uso de protocolos sin cifrado para comunicaciones.',
    cvss: '3.1', port: '23/tcp', cve: null,
  },
];

/** Returns Tailwind classes for severity badge styling. */
function severityStyle(sev) {
  switch (sev) {
    case 'CRITICAL': return 'bg-red-500/15 text-red-400 border-red-500/30';
    case 'HIGH':     return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
    case 'MEDIUM':   return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    case 'LOW':      return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    default:         return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  }
}

const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

/** SortIcon — shows up/down chevron based on current sort state. */
function SortIcon({ field, sortField, sortDir }) {
  if (sortField !== field) return <ChevronUp className="w-3 h-3 text-[#4b5563]" />;
  return sortDir === 'asc'
    ? <ChevronUp className="w-3 h-3 text-[#00d4ff]" />
    : <ChevronDown className="w-3 h-3 text-[#00d4ff]" />;
}

/**
 * FindingDrawer — Sheet lateral con detalles de la vulnerabilidad seleccionada.
 */
function FindingDrawer({ finding, open, onClose }) {
  if (!finding) return null;
  return (
    <Sheet open={open} onOpenChange={onClose}>
      <SheetContent
        side="right"
        className="w-[480px] sm:w-[540px] bg-[#111318] border-l border-[#1e2530] p-0"
      >
        <ScrollArea className="h-full">
          <div className="p-6 space-y-6">
            <SheetHeader className="space-y-2">
              <div className="flex items-start justify-between gap-3">
                <SheetTitle className="text-white text-base leading-snug">
                  {finding.nombre}
                </SheetTitle>
                <Badge className={`shrink-0 mt-0.5 border ${severityStyle(finding.severidad)}`}>
                  {finding.severidad}
                </Badge>
              </div>
              <SheetDescription className="text-[#6b7280] text-xs font-mono">
                {finding.id} · {finding.herramienta} · {finding.activo}
              </SheetDescription>
            </SheetHeader>

            {/* Metadata grid */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Activo', value: finding.activo },
                { label: 'Herramienta', value: finding.herramienta },
                { label: 'CVSS', value: finding.cvss ?? '—' },
                { label: 'CVE', value: finding.cve ?? 'N/A' },
                { label: 'Puerto', value: finding.port ?? '—' },
                { label: 'Medida ENS', value: finding.medida_ens },
              ].map(({ label, value }) => (
                <div key={label} className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-3">
                  <div className="text-[#6b7280] text-xs mb-1">{label}</div>
                  <div className="text-white text-sm font-mono">{value}</div>
                </div>
              ))}
            </div>

            {/* Descripción */}
            <div>
              <h3 className="text-xs font-semibold text-[#9ca3af] uppercase tracking-wider mb-2">
                Descripción
              </h3>
              <p className="text-[#d1d5db] text-sm leading-relaxed">{finding.descripcion}</p>
            </div>

            {/* Contexto ENS (RAGEngine) */}
            <div className="bg-[#0f1117] border border-[#00d4ff]/20 rounded-lg p-4 space-y-2">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#00d4ff]" />
                <h3 className="text-xs font-semibold text-[#00d4ff] uppercase tracking-wider">
                  Contexto ENS (RAGEngine)
                </h3>
              </div>
              <p className="text-[#9ca3af] text-xs font-mono leading-relaxed">
                Artículo incumplido:
              </p>
              <p className="text-[#d1d5db] text-sm leading-relaxed">{finding.articulo_ens}</p>
            </div>
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}

/**
 * FindingsTable — tabla de hallazgos con ordenación, filtrado y drawer lateral.
 * Acepta `findings` del hook; si está vacío o ausente usa el mock.
 */
export function FindingsTable({ findings, initialQuery = '' }) {
  const rows = findings?.length ? findings : MOCK_FINDINGS;

  const [query, setQuery] = useState(initialQuery);
  const [sortField, setSortField] = useState('severidad');
  const [sortDir, setSortDir] = useState('desc');
  const [selected, setSelected] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const handleRowClick = (row) => {
    setSelected(row);
    setDrawerOpen(true);
  };

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return rows.filter(r =>
      !q ||
      r.nombre?.toLowerCase().includes(q) ||
      r.activo?.toLowerCase().includes(q) ||
      r.herramienta?.toLowerCase().includes(q) ||
      r.severidad?.toLowerCase().includes(q) ||
      r.medida_ens?.toLowerCase().includes(q)
    );
  }, [rows, query]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let av, bv;
      if (sortField === 'severidad') {
        av = SEVERITY_ORDER[a.severidad] ?? 0;
        bv = SEVERITY_ORDER[b.severidad] ?? 0;
      } else {
        av = (a[sortField] ?? '').toString().toLowerCase();
        bv = (b[sortField] ?? '').toString().toLowerCase();
      }
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }, [filtered, sortField, sortDir]);

  const COLS = [
    { key: 'id',         label: 'ID',        sortable: true,  width: 'w-20' },
    { key: 'activo',     label: 'Activo',     sortable: true,  width: 'w-28' },
    { key: 'herramienta',label: 'Herramienta',sortable: true,  width: 'w-28' },
    { key: 'nombre',     label: 'Hallazgo',   sortable: true,  width: '' },
    { key: 'severidad',  label: 'Severidad',  sortable: true,  width: 'w-28' },
    { key: 'medida_ens', label: 'ENS',        sortable: true,  width: 'w-24' },
  ];

  return (
    <>
      {/* Search bar */}
      <div className="flex items-center gap-2 mb-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#6b7280]" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Filtrar hallazgos…"
            className="w-full pl-8 pr-3 py-2 bg-[#1a1d27] border border-[#1e2530] rounded-lg text-sm text-white placeholder:text-[#4b5563] focus:outline-none focus:border-[#00d4ff]/50 transition-colors"
          />
        </div>
        <span className="text-xs text-[#6b7280] font-mono">{sorted.length} hallazgos</span>
      </div>

      {/* Table */}
      <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg overflow-hidden flex flex-col min-h-0">
        {/* Header */}
        <div className="grid grid-cols-[80px_112px_112px_minmax(0,_1fr)_112px_96px] border-b border-[#1e2530] bg-[#111318]">
          {COLS.map(col => (
            <button
              key={col.key}
              onClick={col.sortable ? () => handleSort(col.key) : undefined}
              className={`flex items-center gap-1 px-4 py-3 text-left text-xs font-semibold text-[#6b7280] uppercase tracking-wider transition-colors ${col.sortable ? 'hover:text-white cursor-pointer' : 'cursor-default'}`}
            >
              {col.label}
              {col.sortable && (
                <SortIcon field={col.key} sortField={sortField} sortDir={sortDir} />
              )}
            </button>
          ))}
        </div>

        {/* Rows */}
        <ScrollArea className="h-[calc(100vh-320px)] min-h-[300px]">
          {sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-[#4b5563]">
              <ShieldAlert className="w-8 h-8 mb-2" />
              <p className="text-sm">No se encontraron hallazgos</p>
            </div>
          ) : (
            sorted.map((row, i) => (
              <div
                key={row.id}
                onClick={() => handleRowClick(row)}
                className={`grid grid-cols-[80px_112px_112px_minmax(0,_1fr)_112px_96px] border-b border-[#1e2530]/50 cursor-pointer transition-colors hover:bg-[#1e2530] ${i % 2 === 0 ? 'bg-transparent' : 'bg-[#111318]/30'}`}
              >
                <div className="px-4 py-3 text-xs font-mono text-[#6b7280]">{row.id}</div>
                <div className="px-4 py-3 text-xs font-mono text-[#d1d5db]">{row.activo}</div>
                <div className="px-4 py-3 text-xs text-[#9ca3af]">{row.herramienta}</div>
                
                <div className="px-4 py-3 text-sm text-white min-w-0">
                  <div className="truncate text-left tracking-wide leading-relaxed" title={row.nombre}>
                    {row.nombre}
                  </div>
                </div>

                <div className="px-4 py-3">
                  <Badge className={`border text-xs ${severityStyle(row.severidad)}`}>
                    {row.severidad}
                  </Badge>
                </div>
                <div className="px-4 py-3 text-xs font-mono text-[#00d4ff]">{row.medida_ens}</div>
              </div>
            ))
          )}
        </ScrollArea>
      </div>

      <FindingDrawer
        finding={selected}
        open={drawerOpen}
        onClose={setDrawerOpen}
      />
    </>
  );
}
