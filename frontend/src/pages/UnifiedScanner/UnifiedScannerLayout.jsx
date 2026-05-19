import { ScanLine, Radio, LayoutGrid, Map, RefreshCw, AlertCircle } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/app/components/ui/tabs';
import { useScanData } from './hooks/useScanData';
import { LivePipelineTerminal } from './components/LivePipelineTerminal';
import { FindingsTable } from './components/FindingsTable';
import { SurfaceMap } from './components/SurfaceMap';

// IMPORTACIONES AÑADIDAS: Traemos la barra lateral y superior
import { Sidebar } from '../../app/components/Sidebar';
import { TopBar } from '../../app/components/TopBar';

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
          </Tabs>

        </main>
      </div>
    </div>
  );
}