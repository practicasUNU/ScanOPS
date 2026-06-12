import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { Search, Plus, Play, Activity, AlertCircle, CheckCircle2, RefreshCw, ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { useAssets, type Asset, type VulnResult } from '../../hooks/useAssets';

type WebCheckData = {
  ssl?: any;
  headers?: any;
  dns?: any;
  cookies?: any;
  'tech-stack'?: any;
  dnssec?: any;
  'mail-config'?: any; 
};

const SECURITY_HEADERS = [
  'X-Frame-Options',
  'Content-Security-Policy',
  'Strict-Transport-Security',
  'X-Content-Type-Options',
] as const;

export function ScannerPage() {
  const { assets, loading, error, refetch, createAsset, scanAsset, getScanStatus, getVulnResults } = useAssets();
  const [newIP, setNewIP] = useState('');
  const [scanning, setScanning] = useState<Record<number, boolean>>({});
  const [vulns, setVulns] = useState<Record<number, VulnResult[]>>({});
  const [expanded, setExpanded] = useState<number | null>(null);
  const [addError, setAddError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [scanTypes, setScanTypes] = useState<Record<number, string[]>>({});
  const [taskIds, setTaskIds] = useState<Record<number, string>>({});
  const [reconData, setReconData] = useState<Record<number, any>>({});

  // Ad-hoc scan state
  const [adhocTarget, setAdhocTarget] = useState('');
  const [adhocScanTypes, setAdhocScanTypes] = useState('nikto,nuclei,nmap,ffuf,whatweb,testssl');
  const [adhocScanning, setAdhocScanning] = useState(false);
  const [adhocError, setAdhocError] = useState<string | null>(null);
  const [adhocStatus, setAdhocStatus] = useState<string | null>(null);

  const handleAddAsset = async () => {
    if (!newIP.trim()) return;
    setAdding(true);
    setAddError(null);
    try {
      await createAsset({
        ip: newIP.trim(),
        hostname: newIP.trim(),
        tipo: 'SERVER',
        criticidad: 'MEDIA',
        responsable: 'admin',
      });
      setNewIP('');
    } catch (e) {
      setAddError(e instanceof Error ? e.message : 'Error al añadir activo');
    } finally {
      setAdding(false);
    }
  };

  const handleAdhocScan = async () => {
    const target = adhocTarget.trim();
    if (!target) return;
    setAdhocScanning(true);
    setAdhocError(null);
    setAdhocStatus('Registrando activo en M1...');
    try {
      // Reuse existing asset if already registered
      let asset = assets.find(a => a.ip === target || a.hostname === target);
      if (!asset) {
        asset = await createAsset({
          ip: target,
          hostname: target,
          tipo: 'OTRO',
          criticidad: 'PENDIENTE_CLASIFICAR',
          responsable: 'adhoc-scan',
        });
        await refetch();
      }
      setAdhocStatus('Lanzando escaneo en M3...');
      const types = adhocScanTypes.split(',').map(s => s.trim()).filter(Boolean);
      const task = await scanAsset(asset.id, types);
      setAdhocStatus(`Escaneo lanzado — task ${task.task_id.slice(0, 8)}… (puede tardar 2-3 min)`);
      setAdhocTarget('');
    } catch (e) {
      setAdhocError(e instanceof Error ? e.message : 'Error en escaneo ad-hoc');
      setAdhocStatus(null);
    } finally {
      setAdhocScanning(false);
    }
  };

  const handleScan = async (asset: Asset) => {
    const types = scanTypes[asset.id] ?? ['nikto'];
    setScanning(prev => ({ ...prev, [asset.id]: true }));
    try {
      const task = await scanAsset(asset.id, types);
      setTaskIds(prev => ({ ...prev, [asset.id]: task.task_id }));

      let attempts = 0;
      const poll = setInterval(async () => {
        attempts++;
        const statusRes = await getScanStatus(task.task_id);
        if (statusRes.status === 'SUCCESS' || statusRes.status === 'FAILURE' || attempts >= 12) {
          clearInterval(poll);
          const results = await getVulnResults(asset.id);
          setVulns(prev => ({ ...prev, [asset.id]: results }));
          setScanning(prev => ({ ...prev, [asset.id]: false }));
        }
      }, 10000);
    } catch {
      setScanning(prev => ({ ...prev, [asset.id]: false }));
    }
  };

  const handleExpand = async (asset: Asset) => {
    if (expanded === asset.id) { setExpanded(null); return; }
    setExpanded(asset.id);
    if (!vulns[asset.id]) {
      const results = await getVulnResults(asset.id);
      setVulns(prev => ({ ...prev, [asset.id]: results }));
    }
    if (!reconData[asset.id]) {
      try {
        const res = await fetch(
          `/api/m2/api/v1/snapshots/latest?target=${encodeURIComponent(asset.ip)}`,
          { headers: { Authorization: 'Bearer scanops_secret' } },
        );
        if (res.ok) {
          const data = await res.json();
          setReconData(prev => ({ ...prev, [asset.id]: data }));
        }
      } catch {
        // silencioso — M2 puede no estar disponible
      }
    }
  };

  const getSeverityColor = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL': return 'text-[#ff3b3b] bg-[#ff3b3b]/10 border-[#ff3b3b]/30';
      case 'HIGH': return 'text-[#f59e0b] bg-[#f59e0b]/10 border-[#f59e0b]/30';
      case 'MEDIUM': return 'text-[#00d4ff] bg-[#00d4ff]/10 border-[#00d4ff]/30';
      default: return 'text-[#9ca3af] bg-[#1a1d27] border-[#1e2530]';
    }
  };

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />
        <main className="flex-1 overflow-auto p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold text-white mb-1">Network Scanner</h1>
              <p className="text-[#9ca3af] text-sm">{assets.length} activos registrados en M1</p>
            </div>
            <button
              onClick={refetch}
              className="flex items-center gap-2 px-3 py-2 bg-[#1a1d27] border border-[#1e2530] rounded-lg text-sm text-[#9ca3af] hover:text-white transition-colors"
            >
              <RefreshCw className="w-4 h-4" /> Actualizar
            </button>
          </div>

          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#9ca3af]" />
              <input
                type="text"
                value={newIP}
                onChange={e => setNewIP(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleAddAsset()}
                placeholder="IP o hostname (ej: 10.202.15.15)"
                className="w-full bg-[#1a1d27] border border-[#1e2530] rounded-lg pl-10 pr-4 py-2.5 text-white text-sm placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] transition-colors font-mono"
              />
            </div>
            <button
              onClick={handleAddAsset}
              disabled={adding || !newIP.trim()}
              className="flex items-center gap-2 px-4 py-2.5 bg-[#00d4ff] hover:bg-[#00b8e6] disabled:opacity-50 text-[#0f1117] font-semibold rounded-lg transition-colors text-sm"
            >
              <Plus className="w-4 h-4" />
              {adding ? 'Añadiendo...' : 'Añadir'}
            </button>
          </div>

          {addError && (
            <div className="flex items-center gap-2 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 rounded-lg px-3 py-2 text-sm text-[#ff3b3b]">
              <AlertCircle className="w-4 h-4 shrink-0" />{addError}
            </div>
          )}

          {/* ── Escaneo Ad-hoc ── */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-4 space-y-3">
            <div className="text-xs font-semibold text-[#9ca3af] uppercase tracking-widest">
              Escaneo Ad-hoc — IP o Dominio externo
            </div>
            <div className="flex gap-3">
              <input
                type="text"
                value={adhocTarget}
                onChange={e => setAdhocTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleAdhocScan()}
                placeholder="82.223.9.162 o beta.unuware.com"
                disabled={adhocScanning}
                className="flex-1 bg-[#0f1117] border border-[#1e2530] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] transition-colors font-mono disabled:opacity-50"
              />
              <select
                value={adhocScanTypes}
                onChange={e => setAdhocScanTypes(e.target.value)}
                disabled={adhocScanning}
                className="text-xs bg-[#0f1117] border border-[#1e2530] text-[#9ca3af] rounded-lg px-2 py-2 focus:outline-none focus:border-[#00d4ff] disabled:opacity-50"
              >
                <option value="nikto,nuclei,nmap,ffuf,whatweb,testssl">Full Web Scan (all)</option>
                <option value="ffuf,whatweb,testssl">Web-only (ffuf+whatweb+testssl)</option>
                <option value="nikto,nuclei,nmap">Legacy (nikto+nuclei+nmap)</option>
                <option value="ffuf">ffuf — Endpoint Fuzzing</option>
                <option value="whatweb">whatweb — Tech Fingerprint</option>
                <option value="testssl">testssl — TLS/SSL Analysis</option>
              </select>
              <button
                onClick={handleAdhocScan}
                disabled={adhocScanning || !adhocTarget.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-[#00d4ff]/10 hover:bg-[#00d4ff]/20 border border-[#00d4ff]/30 text-[#00d4ff] text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
              >
                {adhocScanning ? <Activity className="w-4 h-4 animate-pulse" /> : <Play className="w-4 h-4" />}
                {adhocScanning ? 'Escaneando...' : 'Iniciar Análisis'}
              </button>
            </div>
            {adhocError && (
              <div className="flex items-center gap-2 text-xs text-[#ff3b3b]">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />{adhocError}
              </div>
            )}
            {adhocStatus && !adhocError && (
              <div className="text-xs text-[#22c55e] font-mono">{adhocStatus}</div>
            )}
          </div>

          {error && (
            <div className="flex items-center gap-2 bg-[#f59e0b]/10 border border-[#f59e0b]/30 rounded-lg px-3 py-2 text-sm text-[#f59e0b]">
              <AlertCircle className="w-4 h-4 shrink-0" />M1 no disponible — {error}
            </div>
          )}

          {loading ? (
            <div className="text-center py-12 text-[#9ca3af] font-mono text-sm">Cargando activos de M1...</div>
          ) : assets.length === 0 ? (
            <div className="text-center py-12 text-[#9ca3af] font-mono text-sm">No hay activos registrados — añade una IP para empezar</div>
          ) : (
            <div className="space-y-3">
              {assets.map(asset => (
                <div key={asset.id} className="bg-[#1a1d27] border border-[#1e2530] rounded-lg overflow-hidden">
                  <div className="flex items-center gap-4 px-4 py-3">
                    <div className="flex-1 grid grid-cols-4 gap-4">
                      <div>
                        <div className="text-xs text-[#9ca3af] mb-0.5">IP</div>
                        <div className="text-sm text-white font-mono">{asset.ip}</div>
                      </div>
                      <div>
                        <div className="text-xs text-[#9ca3af] mb-0.5">Hostname</div>
                        <div className="text-sm text-[#d1d5db] font-mono">{asset.hostname ?? '—'}</div>
                      </div>
                      <div>
                        <div className="text-xs text-[#9ca3af] mb-0.5">Criticidad</div>
                        <span className={`text-xs px-2 py-0.5 rounded border font-medium ${
                          asset.criticidad === 'CRITICA' ? 'text-[#ff3b3b] bg-[#ff3b3b]/10 border-[#ff3b3b]/30' :
                          asset.criticidad === 'ALTA' ? 'text-[#f59e0b] bg-[#f59e0b]/10 border-[#f59e0b]/30' :
                          'text-[#9ca3af] bg-[#1e2530] border-[#1e2530]'
                        }`}>{asset.criticidad}</span>
                      </div>
                      <div>
                        <div className="text-xs text-[#9ca3af] mb-0.5">Vulns</div>
                        <div className="text-sm font-mono">
                          {vulns[asset.id]
                            ? <span className={vulns[asset.id].length > 0 ? 'text-[#f59e0b]' : 'text-[#22c55e]'}>{vulns[asset.id].length}</span>
                            : <span className="text-[#6b7280]">—</span>
                          }
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {scanning[asset.id] && taskIds[asset.id] && (
                        <span className="text-xs text-[#9ca3af] font-mono">
                          task: {taskIds[asset.id].slice(0, 8)}…
                        </span>
                      )}
                      <select
                        value={(scanTypes[asset.id] ?? ['nikto']).join(',')}
                        onChange={e => setScanTypes(prev => ({ ...prev, [asset.id]: e.target.value.split(',') }))}
                        disabled={scanning[asset.id]}
                        className="text-xs bg-[#0f1117] border border-[#1e2530] text-[#9ca3af] rounded px-2 py-1.5 focus:outline-none focus:border-[#00d4ff] disabled:opacity-50"
                      >
                        <option value="nikto">Nikto</option>
                        <option value="nuclei">Nuclei</option>
                        <option value="nmap">Nmap</option>
                        <option value="ffuf">ffuf — Endpoint Fuzzing</option>
                        <option value="whatweb">whatweb — Tech Fingerprint</option>
                        <option value="testssl">testssl — TLS/SSL Analysis</option>
                        <option value="nikto,nuclei">Nikto + Nuclei</option>
                        <option value="nikto,nmap">Nikto + Nmap</option>
                        <option value="nikto,nuclei,nmap">Todo (legacy)</option>
                        <option value="nuclei,nikto,nmap,ffuf,whatweb,testssl">Full Web Scan (all)</option>
                      </select>
                      <button
                        onClick={() => handleScan(asset)}
                        disabled={scanning[asset.id]}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-[#00d4ff]/10 hover:bg-[#00d4ff]/20 border border-[#00d4ff]/30 text-[#00d4ff] text-xs font-medium rounded-lg transition-colors disabled:opacity-50"
                      >
                        {scanning[asset.id] ? <Activity className="w-3.5 h-3.5 animate-pulse" /> : <Play className="w-3.5 h-3.5" />}
                        {scanning[asset.id] ? 'Escaneando...' : 'Scan'}
                      </button>
                      <button
                        onClick={() => handleExpand(asset)}
                        className="flex items-center gap-1 px-2 py-1.5 text-[#9ca3af] hover:text-white text-xs rounded-lg transition-colors"
                      >
                        <ChevronDown className={`w-4 h-4 transition-transform ${expanded === asset.id ? 'rotate-180' : ''}`} />
                      </button>
                    </div>
                  </div>

                  {expanded === asset.id && (
                    <div className="border-t border-[#1e2530] px-4 py-3 space-y-3">
                      {!vulns[asset.id] ? (
                        <div className="text-xs text-[#9ca3af] font-mono">Cargando resultados...</div>
                      ) : vulns[asset.id].length === 0 ? (
                        <div className="flex items-center gap-2 text-xs text-[#22c55e]">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Sin vulnerabilidades registradas
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {vulns[asset.id].map(v => (
                            <div key={v.id} className="flex items-start gap-3 text-xs">
                              <span className={`px-1.5 py-0.5 rounded border font-medium shrink-0 ${getSeverityColor(v.severity)}`}>{v.severity}</span>
                              <div className="flex-1">
                                <div className="text-white">{v.title}</div>
                                {v.cve_id && <div className="text-[#00d4ff] font-mono mt-0.5">{v.cve_id}</div>}
                              </div>
                              <div className="text-[#6b7280] shrink-0 font-mono">{v.tool_source}</div>
                            </div>
                          ))}
                        </div>
                      )}

                      {(() => {
                        const wc: WebCheckData | undefined = reconData[asset.id]?.webcheck;
                        if (!wc) return null;
                        const ssl = wc.ssl;
                        const headersRaw = wc.headers;
                        const techStack = wc['tech-stack'];
                        const mailConfig = wc['mail-config'];

                        const sslValid: boolean = ssl?.valid ?? ssl?.isValid ?? false;
                        const sslDays: number | null = ssl?.daysUntilExpiry ?? ssl?.days_remaining ?? null;
                        const sslIssuer: string | null = ssl?.issuer?.O ?? ssl?.issuer ?? null;

                        const presentHeaders = new Set<string>(
                          Array.isArray(headersRaw)
                            ? headersRaw.map((h: any) => h?.name ?? h)
                            : Object.keys(headersRaw ?? {}),
                        );

                        const techRaw = techStack?.technologies ?? techStack;
                        const techList: string[] = Array.isArray(techRaw)
                          ? techRaw.map((t: any) => t?.name ?? t).filter(Boolean)
                          : typeof techRaw === 'object' && techRaw
                          ? Object.keys(techRaw)
                          : []

                        const spfOk: boolean = mailConfig?.spf?.valid ?? mailConfig?.spf ?? false;
                        const dmarcOk: boolean = mailConfig?.dmarc?.valid ?? mailConfig?.dmarc ?? false;

                        return (
                          <div className="pt-2 border-t border-[#1e2530]">
                            <div className="text-xs text-[#9ca3af] mb-2 font-medium">🌐 Web-Check</div>
                            <div className="grid grid-cols-2 gap-2">

                              {ssl && (
                                <div className="bg-[#1e2530] rounded-lg p-3">
                                  <div className="text-xs text-[#9ca3af] mb-1.5">SSL</div>
                                  <div className={`text-xs font-medium ${sslValid ? 'text-[#22c55e]' : 'text-[#ff3b3b]'}`}>
                                    {sslValid ? 'Válido' : 'Expirado'}
                                  </div>
                                  {sslDays != null && (
                                    <div className="text-xs text-[#9ca3af] font-mono mt-0.5">{sslDays}d restantes</div>
                                  )}
                                  {sslIssuer && (
                                    <div className="text-xs text-[#6b7280] font-mono mt-0.5 truncate">{sslIssuer}</div>
                                  )}
                                </div>
                              )}

                              {headersRaw && (
                                <div className="bg-[#1e2530] rounded-lg p-3">
                                  <div className="text-xs text-[#9ca3af] mb-1.5">Headers</div>
                                  <div className="space-y-0.5">
                                    {SECURITY_HEADERS.map(h => (
                                      <div key={h} className="flex items-center gap-1.5">
                                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${presentHeaders.has(h) ? 'bg-[#22c55e]' : 'bg-[#ff3b3b]'}`} />
                                        <span className={`text-xs font-mono ${presentHeaders.has(h) ? 'text-[#22c55e]' : 'text-[#ff3b3b]'}`}>{h}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {techList.length > 0 && (
                                <div className="bg-[#1e2530] rounded-lg p-3">
                                  <div className="text-xs text-[#9ca3af] mb-1.5">Tech Stack</div>
                                  <div className="flex flex-wrap gap-1">
                                    {techList.map(t => (
                                      <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/20 font-mono">
                                        {t}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {mailConfig && (
                                <div className="bg-[#1e2530] rounded-lg p-3">
                                  <div className="text-xs text-[#9ca3af] mb-1.5">Mail</div>
                                  <div className="space-y-0.5">
                                    {([['SPF', spfOk], ['DMARC', dmarcOk]] as const).map(([label, ok]) => (
                                      <div key={label} className="flex items-center gap-1.5">
                                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${ok ? 'bg-[#22c55e]' : 'bg-[#ff3b3b]'}`} />
                                        <span className={`text-xs font-mono ${ok ? 'text-[#22c55e]' : 'text-[#ff3b3b]'}`}>{label}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                            </div>
                          </div>
                        );
                      })()}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
