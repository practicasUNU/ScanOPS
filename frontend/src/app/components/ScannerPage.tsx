import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { Search, Plus, Play, Activity, AlertCircle, CheckCircle2, RefreshCw, ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { useAssets, type Asset, type VulnResult } from '../../hooks/useAssets';

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
                        <option value="nikto,nuclei">Nikto + Nuclei</option>
                        <option value="nikto,nmap">Nikto + Nmap</option>
                        <option value="nikto,nuclei,nmap">Todo</option>
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
                    <div className="border-t border-[#1e2530] px-4 py-3">
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
