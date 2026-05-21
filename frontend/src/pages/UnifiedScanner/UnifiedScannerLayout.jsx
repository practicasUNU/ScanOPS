import { useState } from 'react';
import { ScanLine, Radio, LayoutGrid, Map, RefreshCw, AlertCircle, Search, Loader2, ShieldAlert } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/app/components/ui/tabs';
import { useScanData } from './hooks/useScanData';
import { LivePipelineTerminal } from './components/LivePipelineTerminal';
import { FindingsTable } from './components/FindingsTable';
import { SurfaceMap } from './components/SurfaceMap';

// IMPORTACIONES AÑADIDAS: Traemos la barra lateral y superior
import { Sidebar } from '../../app/components/Sidebar';
import { TopBar } from '../../app/components/TopBar';

function getToken() { try { const r = sessionStorage.getItem('scanops_auth'); return r ? JSON.parse(r)?.access_token ?? null : null; } catch { return null; } }
function authH() { const t = getToken(); return t ? { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' }; }

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

  // ── Ad-hoc scanner state ──
  const [adhocTarget, setAdhocTarget] = useState('');
  const [adhocDomain, setAdhocDomain] = useState('');
  const [adhocScanning, setAdhocScanning] = useState(false);
  const [adhocPhase, setAdhocPhase] = useState(''); // 'M2'|'M3'|'done'|'error'
  const [adhocM2Result, setAdhocM2Result] = useState(null);
  const [adhocM3Result, setAdhocM3Result] = useState(null);
  const [adhocError, setAdhocError] = useState('');
  const [adhocLog, setAdhocLog] = useState([]);

  const handleAdhocScan = async () => {
    if (!adhocTarget.trim()) return;
    setAdhocScanning(true);
    setAdhocError('');
    setAdhocM2Result(null);
    setAdhocM3Result(null);
    setAdhocLog([]);
    const log = (msg) => setAdhocLog(p => [...p, { ts: new Date().toLocaleTimeString('es-ES'), msg }]);

    try {
      // ── FASE M2: Reconocimiento ──
      setAdhocPhase('M2');
      const target = adhocDomain.trim() || adhocTarget.trim();
      log(`[M2] Iniciando reconocimiento Nmap sobre ${target}...`);
      const m2Res = await fetch(
        `http://localhost:8003/api/v1/scan?target=${encodeURIComponent(target)}`,
        { method: 'POST', headers: authH(), signal: AbortSignal.timeout(120000) }
      );
      if (!m2Res.ok) throw new Error(`M2 HTTP ${m2Res.status}`);
      const m2Data = await m2Res.json();
      setAdhocM2Result(m2Data);
      const ports = m2Data.reconnaissance?.ports_discovered?.length ?? 0;
      log(`[M2] ✓ Completado — ${ports} puertos descubiertos en ${m2Data.summary?.scan_duration_seconds?.toFixed(1)}s`);
      if (m2Data.reconnaissance?.os_information?.detected_family)
        log(`[M2] OS detectado: ${m2Data.reconnaissance.os_information.detected_family}`);
      if (m2Data.webcheck?.tech_stack?.technologies?.length > 0)
        log(`[M2] Stack: ${m2Data.webcheck['tech-stack']?.technologies?.slice(0, 3).map(t => t.name).join(', ')}`);

      // ── FASE M3: Escaneo de vulnerabilidades ──
      setAdhocPhase('M3');
      log(`[M3] Lanzando Nuclei + Nikto + Nmap sobre ${target}...`);
      const m3Launch = await fetch(
        `http://localhost:8002/api/v1/scan/asset/10`,
        {
          method: 'POST', headers: authH(),
          body: JSON.stringify({ scan_types: ['nmap', 'nuclei', 'nikto'], description: `Ad-hoc scan: ${target}` }),
          signal: AbortSignal.timeout(15000)
        }
      );
      if (!m3Launch.ok) throw new Error(`M3 HTTP ${m3Launch.status}`);
      const { task_id } = await m3Launch.json();
      log(`[M3] Tarea creada: ${task_id} — esperando resultados...`);

      // Polling M3
      for (let i = 0; i < 40; i++) {
        await new Promise(r => setTimeout(r, 4000));
        const statusRes = await fetch(
          `http://localhost:8002/api/v1/scan/status/${task_id}`,
          { headers: authH(), signal: AbortSignal.timeout(8000) }
        );
        if (!statusRes.ok) continue;
        const st = await statusRes.json();
        if (st.status === 'FAILED') throw new Error('M3 falló durante el escaneo');
        if (st.status === 'SUCCESS') {
          log(`[M3] ✓ Completado — ${st.findings_count ?? 0} hallazgos encontrados`);
          const resultsRes = await fetch(
            `http://localhost:8002/api/v1/scan/results/10`,
            { headers: authH(), signal: AbortSignal.timeout(8000) }
          );
          if (resultsRes.ok) {
            const results = await resultsRes.json();
            setAdhocM3Result(results);
            log(`[M3] ${results.total_findings ?? 0} vulnerabilidades totales procesadas`);
          }
          break;
        }
        if (i % 3 === 0) log(`[M3] Escaneando... (${(i + 1) * 4}s)`);
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

  return (
    // EL NUEVO LAYOUT ENVOLVENTE
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />

        <main className="flex-1 overflow-auto p-6 space-y-6">
          {/* ── Page header ── */}
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-[#00d4ff]/10 border border-[#00d4ff]/20 rounded-lg flex items-center justify-center shrink-0">
                <ScanLine className="w-5 h-5 text-[#00d4ff]" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-white leading-tight">
                  Superficie y Riesgos
                </h1>
                <p className="text-sm text-[#6b7280] mt-0.5">
                  M2 Reconocimiento · M3 Escaneo — hallazgos consolidados ENS Alto
                </p>
              </div>
            </div>

            {/* Right: KPI pills + refresh */}
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
              <button
                onClick={refetch}
                disabled={loading}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1a1d27] border border-[#1e2530] rounded-lg text-xs text-[#9ca3af] hover:text-white hover:border-[#00d4ff]/40 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
                {loading ? 'Cargando…' : 'Actualizar'}
              </button>
            </div>
          </div>

          {/* ── API error banner ── */}
          {error && (
            <div className="flex items-center gap-2 px-4 py-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-sm text-amber-400 font-mono">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>M3 no disponible — mostrando datos de demostración · {error}</span>
            </div>
          )}

          {/* ── Tabs ── */}
          <Tabs defaultValue="pipeline" className="flex-1">
            <TabsList className="bg-[#1a1d27] border border-[#1e2530] h-10 w-full justify-start rounded-lg gap-1 p-1">
              <TabsTrigger
                value="pipeline"
                className="flex items-center gap-1.5 text-xs font-medium data-[state=active]:bg-[#00d4ff]/10 data-[state=active]:text-[#00d4ff] data-[state=active]:border-[#00d4ff]/30 rounded-md px-3 h-8"
              >
                <Radio className="w-3.5 h-3.5" />
                Live Pipeline
              </TabsTrigger>

              <TabsTrigger
                value="findings"
                className="flex items-center gap-1.5 text-xs font-medium data-[state=active]:bg-[#00d4ff]/10 data-[state=active]:text-[#00d4ff] data-[state=active]:border-[#00d4ff]/30 rounded-md px-3 h-8"
              >
                <LayoutGrid className="w-3.5 h-3.5" />
                Matriz de Hallazgos
                {findings.length > 0 && (
                  <span className="ml-1 px-1.5 py-0.5 bg-[#1e2530] rounded text-[10px] font-mono text-[#6b7280]">
                    {findings.length}
                  </span>
                )}
              </TabsTrigger>

              <TabsTrigger
                value="surface"
                className="flex items-center gap-1.5 text-xs font-medium data-[state=active]:bg-[#00d4ff]/10 data-[state=active]:text-[#00d4ff] data-[state=active]:border-[#00d4ff]/30 rounded-md px-3 h-8"
              >
                <Map className="w-3.5 h-3.5" />
                Mapa de Superficie
              </TabsTrigger>

              <TabsTrigger
                value="adhoc"
                className="flex items-center gap-1.5 text-xs font-medium data-[state=active]:bg-[#00d4ff]/10 data-[state=active]:text-[#00d4ff] data-[state=active]:border-[#00d4ff]/30 rounded-md px-3 h-8"
              >
                <Search className="w-3.5 h-3.5" />
                Escaneo Ad-hoc
              </TabsTrigger>
            </TabsList>

            <TabsContent value="pipeline" className="mt-4">
              <LivePipelineTerminal />
            </TabsContent>

            <TabsContent value="findings" className="mt-4">
              <FindingsTable findings={findings} />
            </TabsContent>

            <TabsContent value="surface" className="mt-4">
              <SurfaceMap data={data} />
            </TabsContent>

            <TabsContent value="adhoc" className="mt-4 space-y-4">

              {/* Formulario de entrada */}
              <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                  <Search className="w-4 h-4 text-[#00d4ff]" />
                  Escaneo Ad-hoc — IP o Dominio externo
                </h3>
                <p className="text-xs text-[#6b7280] mb-4">
                  Analiza cualquier IP o dominio sin necesidad de registrarlo en el inventario.
                  Ejecuta M2 (reconocimiento Nmap) + M3 (Nuclei+Nikto) en secuencia.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
                  <div>
                    <label className="text-xs text-[#6b7280] mb-1 block">IP Address *</label>
                    <input
                      type="text" value={adhocTarget}
                      onChange={e => setAdhocTarget(e.target.value)}
                      placeholder="ej. 10.202.15.15 o 185.199.108.153"
                      disabled={adhocScanning}
                      className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2
                                 text-sm text-white font-mono placeholder:text-[#374151]
                                 focus:outline-none focus:border-[#00d4ff] disabled:opacity-50"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-[#6b7280] mb-1 block">Dominio (opcional)</label>
                    <input
                      type="text" value={adhocDomain}
                      onChange={e => setAdhocDomain(e.target.value)}
                      placeholder="ej. pruebas.unuware.com"
                      disabled={adhocScanning}
                      className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2
                                 text-sm text-white font-mono placeholder:text-[#374151]
                                 focus:outline-none focus:border-[#00d4ff] disabled:opacity-50"
                    />
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <button onClick={handleAdhocScan} disabled={adhocScanning || !adhocTarget.trim()}
                    className="flex items-center gap-2 px-5 py-2 bg-[#00d4ff] hover:bg-[#00b8e6]
                               text-[#0f1117] font-bold rounded-lg text-sm transition-colors
                               disabled:opacity-50 disabled:cursor-not-allowed">
                    {adhocScanning
                      ? <><Loader2 className="w-4 h-4 animate-spin" />Escaneando...</>
                      : <><Search className="w-4 h-4" />Iniciar Análisis Completo</>}
                  </button>
                  {adhocPhase === 'M2' && <span className="text-xs text-[#00d4ff] font-mono animate-pulse">M2 Reconocimiento activo...</span>}
                  {adhocPhase === 'M3' && <span className="text-xs text-[#f59e0b] font-mono animate-pulse">M3 Escaneo de vulnerabilidades...</span>}
                  {adhocPhase === 'done' && <span className="text-xs text-[#22c55e] font-mono">✓ Análisis completado</span>}
                </div>
                {adhocError && (
                  <p className="text-xs text-[#ff3b3b] flex items-center gap-1 mt-2">
                    <AlertCircle className="w-3 h-3" />{adhocError}
                  </p>
                )}
              </div>

              {/* Log en tiempo real */}
              {adhocLog.length > 0 && (
                <div className="bg-[#0f1117] border border-[#1e2530] rounded-lg p-3 font-mono text-xs space-y-0.5 max-h-40 overflow-y-auto">
                  {adhocLog.map((l, i) => (
                    <div key={i} className="flex gap-2">
                      <span className="text-[#374151] shrink-0">{l.ts}</span>
                      <span className={
                        l.msg.startsWith('[✗]') ? 'text-[#ff3b3b]' :
                        l.msg.startsWith('[✓]') ? 'text-[#22c55e]' :
                        l.msg.startsWith('[M2]') ? 'text-[#00d4ff]' :
                        l.msg.startsWith('[M3]') ? 'text-[#f59e0b]' :
                        'text-[#9ca3af]'
                      }>
                        {l.msg}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Resultados M2 */}
              {adhocM2Result && (
                <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                    <Radio className="w-4 h-4 text-[#00d4ff]" />M2 — Reconocimiento
                  </h4>
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
                  {adhocM2Result.reconnaissance?.ports_discovered?.some(p => p.tls_info) && (
                    <div className="mt-3 p-3 bg-[#0f1117] rounded-lg border border-[#1e2530]">
                      <p className="text-xs text-[#6b7280] font-semibold mb-1">Certificado TLS</p>
                      {adhocM2Result.reconnaissance.ports_discovered.filter(p => p.tls_info).map((p, i) => (
                        <div key={i} className="text-xs font-mono text-[#9ca3af]">
                          Puerto {p.port} · {p.tls_info.tls_version} · Expira: {p.tls_info.cert_expiry?.split('T')[0]} · {p.tls_info.days_until_expiry} días
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Resultados M3 */}
              {adhocM3Result && (
                <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-[#f59e0b]" />
                    M3 — Vulnerabilidades ({adhocM3Result.total_findings} hallazgos)
                  </h4>
                  {Object.entries(adhocM3Result.findings_by_scanner ?? {}).map(([scanner, findings]) => (
                    <div key={scanner} className="mb-4">
                      <p className="text-xs font-semibold text-[#6b7280] uppercase tracking-wider mb-2">{scanner}</p>
                      <div className="space-y-1.5">
                        {findings.map((f, i) => (
                          <div key={i} className="flex items-start gap-3 px-3 py-2 bg-[#0f1117] rounded-lg border border-[#1e2530]/50">
                            <span className={`shrink-0 px-2 py-0.5 rounded text-[10px] font-bold border ${
                              f.severity === 'CRITICAL' ? 'bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]' :
                              f.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30 text-orange-400' :
                              f.severity === 'MEDIUM' ? 'bg-[#f59e0b]/10 border-[#f59e0b]/30 text-[#f59e0b]' :
                              f.severity === 'LOW' ? 'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]' :
                              'bg-[#1e2530] border-[#374151] text-[#6b7280]'
                            }`}>{f.severity}</span>
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