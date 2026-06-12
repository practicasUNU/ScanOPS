import { useState, useEffect } from 'react';
import { useLocation } from 'react-router';
// [NUEVO] Importamos los iconos necesarios para identificar cada tipo de activo
import { 
  ScanLine, Radio, LayoutGrid, Map, RefreshCw, AlertCircle, 
  Search, Loader2, ShieldAlert, Server, Globe, Database, Code, Monitor, HelpCircle 
} from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/app/components/ui/tabs';
import { useScanData } from './hooks/useScanData';
import { LivePipelineTerminal } from './components/LivePipelineTerminal';
import { FindingsTable } from './components/FindingsTable';
import { SurfaceMap } from './components/SurfaceMap';
import { Sidebar } from '../../app/components/Sidebar';
import { TopBar } from '../../app/components/TopBar';

function getToken() { try { const r = sessionStorage.getItem('scanops_auth'); return r ? JSON.parse(r)?.access_token ?? null : null; } catch { return null; } }
function authH() { const t = getToken(); return t ? { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' }; }

function isIPAddress(target) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(target) || /^[0-9a-fA-F:]+$/.test(target);
}
function normalizeTarget(target) {
  return target.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].trim();
}
function getWebUrl(target) {
  if (target.startsWith('http://') || target.startsWith('https://')) return target;
  return `https://${target}`;
}

function StatPill({ label, value, accent }) {
  const accentClass =
    accent === 'red'   ? 'text-red-400 border-red-500/20 bg-red-500/5' :
    accent === 'amber' ? 'text-amber-400 border-amber-500/20 bg-amber-500/5' :
    accent === 'blue'  ? 'text-[#00d4ff] border-[#00d4ff]/20 bg-[#00d4ff]/5' :
                         'text-green-400 border-green-500/20 bg-green-500/5';

  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 border rounded-full text-xs font-mono ${accentClass}`}>
      <span className="font-bold">{value}</span>
      <span className="text-inherit opacity-70">{label}</span>
    </div>
  );
}

export function UnifiedScannerLayout() {
  const { data, loading, error, refetch } = useScanData();
  const findings = data?.findings ?? data?.items ?? [];

  const location = useLocation();
  const initialTab = location.state?.defaultTab || 'pipeline';
  const targetIp = location.state?.searchIp || '';

  // ─── Ad-hoc scanner state ───
  const [adhocTarget, setAdhocTarget] = useState('');
  const [adhocDomain, setAdhocDomain] = useState('');
  const [adhocScanning, setAdhocScanning] = useState(false);
  const [adhocPhase, setAdhocPhase] = useState('');
  const [adhocM2Result, setAdhocM2Result] = useState(null);
  const [adhocM3Result, setAdhocM3Result] = useState(null);
  const [adhocError, setAdhocError] = useState('');
  const [adhocLog, setAdhocLog] = useState([]);
  const [adhocWebResult, setAdhocWebResult] = useState(null);
  const [adhocScanMode, setAdhocScanMode] = useState('auto');

  const handleAdhocScan = async () => {
    if (!adhocTarget.trim()) return;
    setAdhocScanning(true);
    setAdhocError('');
    setAdhocM2Result(null);
    setAdhocM3Result(null);
    setAdhocWebResult(null);
    setAdhocLog([]);
    const log = (msg) => setAdhocLog(p => [...p, { ts: new Date().toLocaleTimeString('es-ES'), msg }]);

    const rawTarget = adhocTarget.trim();
    const cleanTarget = normalizeTarget(rawTarget);
    const webUrl = getWebUrl(rawTarget);
    const isIP = isIPAddress(cleanTarget);

    try {
      if (isIP) {
        // ── MODO IP: M2 reconocimiento + M3 vulnerabilidades ──
        setAdhocPhase('M2');
        log(`[M2] Iniciando reconocimiento Nmap sobre ${cleanTarget}...`);
        const m2Res = await fetch(
          `/api/m2/api/v1/scan?target=${encodeURIComponent(cleanTarget)}`,
          { method: 'POST', headers: authH(), signal: AbortSignal.timeout(120000) }
        );
        if (!m2Res.ok) throw new Error(`M2 HTTP ${m2Res.status}`);
        const m2Data = await m2Res.json();
        setAdhocM2Result(m2Data);
        const ports = m2Data.reconnaissance?.ports_discovered?.length ?? 0;
        log(`[M2] ✓ Completado — ${ports} puertos descubiertos en ${m2Data.summary?.scan_duration_seconds?.toFixed(1)}s`);
        if (m2Data.reconnaissance?.os_information?.detected_family)
          log(`[M2] OS detectado: ${m2Data.reconnaissance.os_information.detected_family}`);

        // Register asset in M1 (or reuse if already exists)
        setAdhocPhase('M1');
        log(`[M1] Registrando activo ${cleanTarget} en inventario...`);
        let assetId;
        const m1Register = await fetch('/api/m1/api/v1/assets', {
          method: 'POST', headers: authH(),
          body: JSON.stringify({ ip: cleanTarget, hostname: cleanTarget, tipo: 'OTRO', criticidad: 'PENDIENTE_CLASIFICAR', responsable: 'adhoc-scan' }),
          signal: AbortSignal.timeout(15000),
        });
        if (m1Register.ok) {
          const m1Asset = await m1Register.json();
          assetId = m1Asset.id;
          log(`[M1] ✓ Activo registrado — asset_id=${assetId}`);
        } else if (m1Register.status === 409) {
          // Asset already exists — buscar por IP exacta
          const m1Find = await fetch(
            `/api/m1/api/v1/assets?search=${encodeURIComponent(cleanTarget)}&page_size=50`,
            { headers: authH(), signal: AbortSignal.timeout(10000) }
          );
          if (!m1Find.ok) throw new Error(`M1 lookup HTTP ${m1Find.status}`);
          const m1List = await m1Find.json();
          const existing = (m1List.items ?? []).find(a => a.ip === cleanTarget);
          if (!existing) throw new Error(`M1: activo con IP ${cleanTarget} no encontrado`);
          assetId = existing.id;
          log(`[M1] Activo ya registrado — asset_id=${assetId} (IP: ${existing.ip})`);
        } else {
          throw new Error(`M1 HTTP ${m1Register.status}`);
        }

        setAdhocPhase('M3');
        log(`[M3] Lanzando Nmap + Nuclei + Nikto + ffuf + whatweb + testssl sobre ${cleanTarget}...`);
        const m3Launch = await fetch(`/api/m3/api/v1/scan/asset/${assetId}`, {
          method: 'POST', headers: authH(),
          body: JSON.stringify({ scan_types: ['nmap', 'nuclei', 'nikto', 'ffuf', 'whatweb', 'testssl'], description: `Ad-hoc IP: ${cleanTarget}` }),
          signal: AbortSignal.timeout(15000),
        });
        if (!m3Launch.ok) throw new Error(`M3 HTTP ${m3Launch.status}`);
        const { task_id } = await m3Launch.json();
        log(`[M3] Tarea creada — task_id=${task_id}`);
        await new Promise(r => setTimeout(r, 10000));

        let m3Done = false;
        // Polling dual: cada iteración consulta /results directamente.
        // No dependemos del status del task padre porque scan_asset_parallel
        // termina en <1s devolviendo "parallel_scans_initiated" — su status
        // es SUCCESS inmediatamente aunque el chord interno siga corriendo.
        for (let i = 0; i < 36; i++) {
          await new Promise(r => setTimeout(r, 8000));
          try {
            const resultsRes = await fetch(
              `/api/m3/api/v1/scan/results/${assetId}`,
              { headers: authH(), signal: AbortSignal.timeout(8000) }
            );
            if (resultsRes.ok) {
              const results = await resultsRes.json();
              const n = results.total_findings ?? 0;
              if (n > 0) {
                setAdhocM3Result(results);
                log(`[M3] ✓ Completado — ${n} vulnerabilidades encontradas`);
                m3Done = true;
                break;
              }
            }
          } catch (_e) {}
          if (i % 3 === 0) log(`[M3] Escaneando... ${10 + (i + 1) * 8}s`);
        }
        // Mostrar resultado final siempre — aunque sea 0 hallazgos
        if (!m3Done) {
          try {
            const resultsRes = await fetch(
              `/api/m3/api/v1/scan/results/${assetId}`,
              { headers: authH(), signal: AbortSignal.timeout(8000) }
            );
            if (resultsRes.ok) {
              const results = await resultsRes.json();
              setAdhocM3Result(results);
              const n = results.total_findings ?? 0;
              log(n > 0
                ? `[M3] ✓ Completado — ${n} vulnerabilidades`
                : `[M3] ✓ Completado — sin vulnerabilidades detectadas en este host`
              );
            }
          } catch {}
        }

      } else {
        // ── MODO WEB: Webcheck + M2 reconocimiento DNS ──
        setAdhocPhase('WEB');
        log(`[WEB] Iniciando análisis web de ${cleanTarget}...`);
        log(`[WEB] URL objetivo: ${webUrl}`);

        const webcheckEndpoints = ['ssl', 'headers', 'dns', 'tech-stack', 'cookies', 'mail-config'];
        log(`[WEB] Consultando: SSL, Headers, DNS, Tech Stack, Cookies, Mail Config...`);

        const wcResults = await Promise.allSettled(
          webcheckEndpoints.map(ep =>
            fetch(`/api/webcheck/api/${ep}?url=${encodeURIComponent(webUrl)}`,
              { signal: AbortSignal.timeout(30000) })
              .then(r => r.ok ? r.json() : null)
              .catch(() => null)
          )
        );

        const webData = {};
        webcheckEndpoints.forEach((ep, i) => {
          webData[ep] = wcResults[i].status === 'fulfilled' ? wcResults[i].value : null;
        });
        setAdhocWebResult(webData);

        const techCount = webData['tech-stack']?.technologies?.length ?? 0;
        const sslValid = webData['ssl']?.isValid;
        const headerGrade = webData['headers']?.grade ?? '?';
        log(`[WEB] ✓ Tech Stack: ${techCount} tecnologías detectadas`);
        log(`[WEB] ✓ SSL: ${sslValid ? 'Válido' : 'Inválido/Expirado'}`);
        log(`[WEB] ✓ Security Headers Grade: ${headerGrade}`);

        setAdhocPhase('M2');
        log(`[M2] Lanzando reconocimiento Nmap sobre ${cleanTarget}...`);
        try {
          const m2Res = await fetch(
            `/api/m2/api/v1/scan?target=${encodeURIComponent(cleanTarget)}`,
            { method: 'POST', headers: authH(), signal: AbortSignal.timeout(120000) }
          );
          if (m2Res.ok) {
            const m2Data = await m2Res.json();
            setAdhocM2Result(m2Data);
            const p = m2Data.reconnaissance?.ports_discovered?.length ?? 0;
            log(`[M2] ✓ ${p} puertos descubiertos`);
          }
        } catch { log(`[M2] Reconocimiento omitido (timeout)`); }
      }

      setAdhocPhase('done');
      log(`[✓] Análisis completo`);
    } catch (e) {
      setAdhocError(e.message ?? 'Error');
      setAdhocPhase('error');
      log(`[✗] Error: ${e.message}`);
    } finally {
      setAdhocScanning(false);
    }
  };

  const counts = findings.reduce((acc, f) => {
    const s = f.severidad ?? f.severity ?? 'INFO';
    acc[s] = (acc[s] ?? 0) + 1;
    return acc;
  }, {});

  // ─── [NUEVO] MOTOR DE CLASIFICACIÓN DE ACTIVOS (FINGERPRINTING) ───
  const determineAssetType = (m2Data) => {
    if (!m2Data) return { label: 'Desconocido', icon: HelpCircle, color: 'text-gray-400 bg-gray-500/5 border-gray-500/20' };

    const ports = m2Data.reconnaissance?.ports_discovered || [];
    const portIds = ports.map(p => p.port);
    const services = ports.map(p => (p.service || '').toLowerCase());
    const osFamily = (m2Data.reconnaissance?.os_information?.detected_family || '').toLowerCase();
    const webcheckRaw = m2Data.webcheck || {};
    const webcheckStr = JSON.stringify(webcheckRaw).toLowerCase();

    // 1. Detección de API / Endpoints REST
    const hasApiKeywords = webcheckStr.includes('api') || webcheckStr.includes('rest') || webcheckStr.includes('json') || services.includes('msrpc');
    const apiPorts = [8000, 8001, 8002, 8004, 8006, 8009, 5000, 8443];
    if (hasApiKeywords || portIds.some(p => apiPorts.includes(p))) {
      return { label: 'API Endpoint / Servicio Web RESTful', icon: Code, color: 'text-purple-400 bg-purple-500/10 border-purple-500/30' };
    }

    // 2. Detección de Servidores de Base de Datos
    const dbPorts = [3306, 5432, 27017, 1521, 1433];
    if (portIds.some(p => dbPorts.includes(p)) || services.some(s => ['mysql', 'postgresql', 'mongodb', 'oracle', 'ms-sql'].includes(s))) {
      return { label: 'Servidor de Base de Datos Relacional / NoSQL', icon: Database, color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30' };
    }

    // 3. Detección de Aplicaciones / Sitios Web Puros (Sin administración expuesta)
    if (portIds.includes(80) || portIds.includes(443) || portIds.includes(8080)) {
      const hasInfraPorts = portIds.some(p => [22, 23, 135, 445, 3389].includes(p));
      if (!hasInfraPorts) {
        return { label: 'Aplicación Web Activa / Servidor HTTP', icon: Globe, color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' };
      }
    }

    // 4. Detección de Servidores de Infraestructura de Red u Ordenadores
    if (osFamily.includes('linux') || osFamily.includes('windows') || portIds.includes(22) || portIds.includes(3389) || portIds.includes(445)) {
      const label = osFamily.includes('windows') ? 'Equipo / Servidor Corporativo Windows' : 'Servidor de Infraestructura Linux / UNIX';
      return { label, icon: Server, color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' };
    }

    // 5. Fallback: Host genérico
    return { label: 'Host de Red General / Nodo de Comunicaciones', icon: Monitor, color: 'text-orange-400 bg-orange-500/10 border-orange-500/30' };
  };

  const assetType = determineAssetType(adhocM2Result);

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />
        <main className="flex-1 overflow-auto p-6 space-y-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-[#00d4ff]/10 border border-[#00d4ff]/20 rounded-lg flex items-center justify-center shrink-0">
                <ScanLine className="w-5 h-5 text-[#00d4ff]" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-white leading-tight">Superficie y Riesgos</h1>
                <p className="text-sm text-[#6b7280] mt-0.5">M2 Reconocimiento · M3 Escaneo — hallazgos consolidados ENS Alto</p>
              </div>
            </div>

            <div className="flex items-center gap-2 flex-wrap justify-end">
              {!loading && !error && (
                <>
                  {counts.CRITICAL > 0 && <StatPill value={counts.CRITICAL} label="CRITICAL" accent="red" />}
                  {counts.HIGH     > 0 && <StatPill value={counts.HIGH}     label="HIGH"     accent="red" />}
                  {counts.MEDIUM   > 0 && <StatPill value={counts.MEDIUM}   label="MEDIUM"   accent="amber" />}
                  {counts.LOW      > 0 && <StatPill value={counts.LOW}      label="LOW"      accent="blue" />}
                  <StatPill value={findings.length} label="total" accent="green" />
                </>
              )}
              <button onClick={refetch} disabled={loading} className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1a1d27] border border-[#1e2530] rounded-lg text-xs text-[#9ca3af] hover:text-white hover:border-[#00d4ff]/40 transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer">
                <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
                {loading ? 'Cargando…' : 'Actualizar'}
              </button>
            </div>
          </div>

          {error && (
            <div className="flex items-center gap-2 px-4 py-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-sm text-amber-400 font-mono">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>
                {error.includes('Token expirado')
                  ? `⚠ Sesión caducada — ${error}`
                  : error.includes('no disponible') || error.includes('fetch')
                    ? `⚠ M2/M3 sin conexión — ${error}`
                    : `⚠ ${error}`
                }
              </span>
            </div>
          )}

          <Tabs defaultValue={initialTab} className="flex-1">
            <TabsList className="bg-[#1a1d27] border border-[#1e2530] h-10 w-full justify-start rounded-lg gap-1 p-1">
              <TabsTrigger value="pipeline" className="flex items-center gap-1.5 text-xs font-medium data-[state=active]:bg-[#00d4ff]/10 data-[state=active]:text-[#00d4ff] data-[state=active]:border-[#00d4ff]/30 rounded-md px-3 h-8"><Radio className="w-3.5 h-3.5" />Live Pipeline</TabsTrigger>
              <TabsTrigger value="findings" className="flex items-center gap-1.5 text-xs font-medium data-[state=active]:bg-[#00d4ff]/10 data-[state=active]:text-[#00d4ff] data-[state=active]:border-[#00d4ff]/30 rounded-md px-3 h-8">
                <LayoutGrid className="w-3.5 h-3.5" />Matriz de Hallazgos
                {findings.length > 0 && <span className="ml-1 px-1.5 py-0.5 bg-[#1e2530] rounded text-[10px] font-mono text-[#6b7280]">{findings.length}</span>}
              </TabsTrigger>
              <TabsTrigger value="surface" className="flex items-center gap-1.5 text-xs font-medium data-[state=active]:bg-[#00d4ff]/10 data-[state=active]:text-[#00d4ff] data-[state=active]:border-[#00d4ff]/30 rounded-md px-3 h-8"><Map className="w-3.5 h-3.5" />Mapa de Superficie</TabsTrigger>
              <TabsTrigger value="adhoc" className="flex items-center gap-1.5 text-xs font-medium data-[state=active]:bg-[#00d4ff]/10 data-[state=active]:text-[#00d4ff] data-[state=active]:border-[#00d4ff]/30 rounded-md px-3 h-8"><Search className="w-3.5 h-3.5" />Escaneo Ad-hoc</TabsTrigger>
            </TabsList>

            <TabsContent value="pipeline" className="mt-4"><LivePipelineTerminal /></TabsContent>
            <TabsContent value="findings" className="mt-4">
              <FindingsTable findings={findings} initialQuery={targetIp} />
            </TabsContent>
            <TabsContent value="surface" className="mt-4"><SurfaceMap data={data} /></TabsContent>
            <TabsContent value="adhoc" className="mt-4 space-y-4">
              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><Search className="w-4 h-4 text-[#00d4ff]" />Escaneo Ad-hoc — IP o Dominio externo</h3>
                <p className="text-xs text-[#6b7280] mb-4">Analiza cualquier IP o dominio sin necesidad de registrarlo en el inventario. Ejecuta M2 (reconocimiento Nmap) + M3 (Nuclei+Nikto) en secuencia.</p>
                <div className="mb-3">
                  <label className="text-xs text-[#6b7280] mb-1 block">IP, Dominio o URL *</label>
                  <input type="text" value={adhocTarget} onChange={e => setAdhocTarget(e.target.value)} placeholder="ej. 10.202.15.15, google.com o https://pruebas.unuware.com" disabled={adhocScanning} className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-sm text-white font-mono placeholder:text-[#374151] focus:outline-none focus:border-[#00d4ff] disabled:opacity-50" />
                  {adhocTarget.trim() && (
                    isIPAddress(normalizeTarget(adhocTarget))
                      ? <span className="text-xs text-[#00d4ff] flex items-center gap-1 mt-1"><Server className="w-3 h-3" />Modo IP — ejecutará M2 + M3</span>
                      : <span className="text-xs text-[#22c55e] flex items-center gap-1 mt-1"><Globe className="w-3 h-3" />Modo Web — ejecutará Webcheck + M2 DNS</span>
                  )}
                </div>
                <div className="flex items-center gap-3">
                  <button onClick={handleAdhocScan} disabled={adhocScanning || !adhocTarget.trim()} className="flex items-center gap-2 px-5 py-2 bg-[#00d4ff] hover:bg-[#00b8e6] text-[#0f1117] font-bold rounded-lg text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer">
                    {adhocScanning ? <><Loader2 className="w-4 h-4 animate-spin" />Escaneando...</> : <><Search className="w-4 h-4" />Iniciar Análisis Completo</>}
                  </button>
                  {adhocPhase === 'WEB' && <span className="text-xs text-[#22c55e] font-mono animate-pulse">Webcheck activo...</span>}
                  {adhocPhase === 'M2' && <span className="text-xs text-[#00d4ff] font-mono animate-pulse">M2 Reconocimiento activo...</span>}
                  {adhocPhase === 'M3' && <span className="text-xs text-[#f59e0b] font-mono animate-pulse">M3 Escaneo de vulnerabilidades...</span>}
                  {adhocPhase === 'done' && <span className="text-xs text-[#22c55e] font-mono">✓ Análisis completado</span>}
                </div>
                {adhocError && <p className="text-xs text-[#ff3b3b] flex items-center gap-1 mt-2"><AlertCircle className="w-3 h-3" />{adhocError}</p>}
              </div>

              {adhocLog.length > 0 && (
                <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-3 font-mono text-xs space-y-0.5 max-h-40 overflow-y-auto">
                  {adhocLog.map((l, i) => (
                    <div key={i} className="flex gap-2">
                      <span className="text-[#374151] shrink-0">{l.ts}</span>
                      <span className={l.msg.startsWith('[✗]') ? 'text-[#ff3b3b]' : l.msg.startsWith('[✓]') ? 'text-[#22c55e]' : l.msg.startsWith('[M2]') ? 'text-[#00d4ff]' : l.msg.startsWith('[M3]') ? 'text-[#f59e0b]' : l.msg.startsWith('[WEB]') ? 'text-[#22c55e]' : 'text-[#9ca3af]'}>{l.msg}</span>
                    </div>
                  ))}
                </div>
              )}

              {adhocWebResult && (
                <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-4 space-y-4">
                  <h4 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Globe className="w-4 h-4 text-[#22c55e]" />
                    Análisis Web — {normalizeTarget(adhocTarget)}
                  </h4>

                  {adhocWebResult.ssl && (
                    <div>
                      <p className="text-xs font-semibold text-[#6b7280] uppercase tracking-wider mb-2">SSL / TLS</p>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                        <div className="bg-[#0f1117] rounded p-2 text-center">
                          <div className={`text-sm font-bold ${adhocWebResult.ssl.isValid ? 'text-[#22c55e]' : 'text-[#ff3b3b]'}`}>{adhocWebResult.ssl.isValid ? '✓ Válido' : '✗ Inválido'}</div>
                          <div className="text-[10px] text-[#6b7280] mt-0.5">Estado</div>
                        </div>
                        <div className="bg-[#0f1117] rounded p-2 text-center">
                          <div className="text-sm font-bold text-white font-mono">{adhocWebResult.ssl.days_until_expiry ?? '?'}d</div>
                          <div className="text-[10px] text-[#6b7280] mt-0.5">Días hasta expirar</div>
                        </div>
                        <div className="bg-[#0f1117] rounded p-2 text-center col-span-2">
                          <div className="text-xs text-white font-mono truncate">{adhocWebResult.ssl.subject?.CN ?? adhocWebResult.ssl.subject ?? '—'}</div>
                          <div className="text-[10px] text-[#6b7280] mt-0.5">Common Name</div>
                        </div>
                      </div>
                    </div>
                  )}

                  {adhocWebResult.headers && (
                    <div>
                      <p className="text-xs font-semibold text-[#6b7280] uppercase tracking-wider mb-2">
                        Security Headers
                        {adhocWebResult.headers.grade && (
                          <span className={`ml-2 px-2 py-0.5 rounded font-bold text-xs ${
                            adhocWebResult.headers.grade === 'A' ? 'bg-[#22c55e]/20 text-[#22c55e]' :
                            adhocWebResult.headers.grade === 'B' ? 'bg-[#00d4ff]/20 text-[#00d4ff]' :
                            adhocWebResult.headers.grade === 'C' ? 'bg-[#f59e0b]/20 text-[#f59e0b]' :
                            'bg-[#ff3b3b]/20 text-[#ff3b3b]'
                          }`}>Grade {adhocWebResult.headers.grade}</span>
                        )}
                      </p>
                      {adhocWebResult.headers.missing?.length > 0 && (
                        <div className="space-y-1">
                          {adhocWebResult.headers.missing.map((h, i) => (
                            <div key={i} className="flex items-center gap-2 text-xs">
                              <span className="text-[#ff3b3b]">✗</span>
                              <span className="font-mono text-[#9ca3af]">{h}</span>
                              <span className="text-[#6b7280]">ausente</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {adhocWebResult['tech-stack']?.technologies?.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-[#6b7280] uppercase tracking-wider mb-2">Tech Stack</p>
                      <div className="flex flex-wrap gap-1.5">
                        {adhocWebResult['tech-stack'].technologies.map((t, i) => (
                          <span key={i} className="px-2 py-0.5 bg-[#1e2530] border border-[#374151] text-[#9ca3af] rounded text-xs font-mono">
                            {t.name}{t.version ? ` ${t.version}` : ''}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {adhocWebResult.dns && Object.values(adhocWebResult.dns).some(v => Array.isArray(v) && v.length > 0) && (
                    <div>
                      <p className="text-xs font-semibold text-[#6b7280] uppercase tracking-wider mb-2">DNS Records</p>
                      <div className="space-y-1">
                        {Object.entries(adhocWebResult.dns)
                          .filter(([, v]) => Array.isArray(v) && v.length > 0)
                          .map(([type, records]) => (
                            <div key={type} className="flex gap-2 text-xs">
                              <span className="font-mono text-[#00d4ff] w-12 shrink-0">{type}</span>
                              <span className="text-[#9ca3af] font-mono truncate">{records.slice(0, 3).join(', ')}</span>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {adhocWebResult['mail-config'] && (
                    <div>
                      <p className="text-xs font-semibold text-[#6b7280] uppercase tracking-wider mb-2">Mail Security</p>
                      <div className="flex gap-3">
                        {['spf', 'dkim', 'dmarc'].map(k => {
                          const val = adhocWebResult['mail-config'][k];
                          const ok = val && val !== 'none' && !String(val).includes('error');
                          return (
                            <div key={k} className={`px-2 py-1 rounded border text-xs font-mono ${ok ? 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]' : 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]'}`}>
                              {k.toUpperCase()} {ok ? '✓' : '✗'}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {adhocM2Result && (
                <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-4 space-y-4">
                  <h4 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
                    <Radio className="w-4 h-4 text-[#00d4ff]" />M2 — Reconocimiento
                  </h4>

                  {/* ─── [NUEVO CASILLERO] CLASIFICACIÓN DE PERFIL DEL ACTIVO EN VIVO ─── */}
                  <div className={`flex items-center gap-3.5 p-4 border rounded-xl shadow-md transition-all ${assetType.color}`}>
                    <assetType.icon className="w-6 h-6 shrink-0" />
                    <div>
                      <div className="text-[10px] uppercase font-bold tracking-widest opacity-60">Perfil de Activo Detectado</div>
                      <div className="text-sm font-mono font-bold text-white mt-0.5">{assetType.label}</div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
                    {[
                      { label: 'Puertos abiertos', value: adhocM2Result.summary?.total_ports_open ?? 0, color: '#00d4ff' },
                      { label: 'Servicios', value: adhocM2Result.summary?.total_services_detected ?? 0, color: '#00d4ff' },
                      { label: 'SSL activo', value: adhocM2Result.summary?.ssl_active ? 'Sí' : 'No', color: adhocM2Result.summary?.ssl_active ? '#22c55e' : '#6b7280' },
                      { label: 'Duración', value: `${adhocM2Result.summary?.scan_duration_seconds?.toFixed(1) ?? '?'}s`, color: '#9ca3af' },
                    ].map(({ label, value, color }) => (
                      <div key={label} className="bg-[#0f1117] rounded-lg p-3 text-center">
                        <div className="text-lg font-bold font-mono" style={{ color }}>{value}</div>
                        <div className="text-xs text-[#6b7280] mt-0.5">{label}</div>
                      </div>
                    ))}
                  </div>
                  {adhocM2Result.reconnaissance?.ports_discovered?.length > 0 && (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-[#6b7280] border-b border-[#1e2530]">
                            <th className="text-left py-2 font-medium">Puerto</th>
                            <th className="text-left py-2 font-medium">Servicio</th>
                            <th className="text-left py-2 font-medium">Versión</th>
                            <th className="text-left py-2 font-medium">Estado</th>
                          </tr>
                        </thead>
                        <tbody>
                          {adhocM2Result.reconnaissance.ports_discovered.map((p, i) => (
                            <tr key={i} className="border-b border-[#1e2530]/50 hover:bg-[#1e2530]/30">
                              <td className="py-2 font-mono text-[#00d4ff]">{p.port}/{p.protocol}</td>
                              <td className="py-2 text-white">{p.service}</td>
                              <td className="py-2 text-[#9ca3af] max-w-xs truncate">{p.version || '—'}</td>
                              <td className="py-2"><span className="px-2 py-0.5 bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] rounded">{p.state}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {adhocM3Result && (
                <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><ShieldAlert className="w-4 h-4 text-[#f59e0b]" />M3 — Vulnerabilidades ({adhocM3Result.total_findings} hallazgos)</h4>
                  {Object.entries(adhocM3Result.findings_by_scanner ?? {}).map(([scanner, findings]) => (
                    <div key={scanner} className="mb-4">
                      <p className="text-xs font-semibold text-[#6b7280] uppercase tracking-wider mb-2">{scanner}</p>
                      <div className="space-y-1.5">
                        {findings.map((f, i) => (
                          <div key={i} className="flex items-start gap-3 px-3 py-2 bg-[#0f1117] rounded-lg border border-[#1e2530]/50">
                            <span className={`shrink-0 px-2 py-0.5 rounded text-[10px] font-bold border ${f.severity === 'CRITICAL' ? 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]' : f.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30 text-orange-400' : f.severity === 'MEDIUM' ? 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]' : f.severity === 'LOW' ? 'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]' : 'bg-[#1e2530] border-[#374151] text-[#6b7280]'}`}>{f.severity}</span>
                            <div className="flex-1 min-w-0">
                              <p className="text-xs text-white">{f.title}</p>
                              {f.cve && <p className="text-[10px] font-mono text-[#00d4ff] mt-0.5">{f.cve} · CVSS {f.cvss}</p>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </TabsContent>
          </Tabs>
        </main>
      </div>
    </div>
  );
}