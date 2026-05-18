import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { Server, ShieldAlert, KeyRound, Plus, RefreshCw, AlertCircle } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Badge } from './ui/badge';
import { useAssets } from '../../hooks/useAssets';
import { useState } from 'react';

export function AssetManagerPage() {
  const { assets, loading, error, refetch } = useAssets();
  const [activeTab, setActiveTab] = useState('cmdb');

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />

        <main className="flex-1 overflow-auto p-6 space-y-6">
          {/* Cabecera */}
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
              <button className="flex items-center gap-2 px-4 py-2 bg-[#00d4ff] hover:bg-[#00b8e6] text-[#0f1117] font-semibold rounded-lg transition-colors text-sm">
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

          {/* Navegación por Pestañas */}
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
            <TabsContent value="cmdb" className="mt-4">
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
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2530]">
                    {loading ? (
                      <tr><td colSpan={6} className="px-6 py-8 text-center text-[#6b7280] font-mono">Cargando inventario...</td></tr>
                    ) : assets.length === 0 ? (
                      <tr><td colSpan={6} className="px-6 py-8 text-center text-[#6b7280] font-mono">No hay activos registrados.</td></tr>
                    ) : (
                      assets.map((asset) => (
                        <tr key={asset.id} className="hover:bg-[#1e2530]/50 transition-colors">
                          <td className="px-6 py-4 font-mono text-[#6b7280]">{asset.id}</td>
                          <td className="px-6 py-4">
                            <div className="text-white font-mono">{asset.ip}</div>
                            <div className="text-xs text-[#9ca3af] mt-0.5">{asset.hostname || 'Sin hostname'}</div>
                          </td>
                          <td className="px-6 py-4">
                            <Badge variant="outline" className={`border ${
                              asset.criticidad === 'CRITICA' ? 'text-[#ff3b3b] border-[#ff3b3b]/30 bg-[#ff3b3b]/10' :
                              asset.criticidad === 'ALTA' ? 'text-[#f59e0b] border-[#f59e0b]/30 bg-[#f59e0b]/10' :
                              'text-[#00d4ff] border-[#00d4ff]/30 bg-[#00d4ff]/10'
                            }`}>
                              {asset.criticidad}
                            </Badge>
                          </td>
                          <td className="px-6 py-4 text-[#9ca3af]">{asset.tipo}</td>
                          <td className="px-6 py-4 text-white">{asset.responsable}</td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-1.5">
                              <div className={`w-1.5 h-1.5 rounded-full ${asset.status === 'ACTIVO' ? 'bg-[#22c55e]' : 'bg-[#6b7280]'}`}></div>
                              <span className="text-xs text-[#9ca3af]">{asset.status}</span>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </TabsContent>

            {/* TAB 2 y 3 (Placeholders por ahora) */}
            <TabsContent value="shadow" className="mt-4">
              <div className="p-8 border border-dashed border-[#1e2530] rounded-lg text-center">
                <ShieldAlert className="w-8 h-8 text-[#f59e0b] mx-auto mb-3 opacity-50" />
                <p className="text-[#9ca3af] font-mono text-sm">Vista de dispositivos descubiertos por Nmap pendiente de clasificar.</p>
              </div>
            </TabsContent>
            <TabsContent value="vault" className="mt-4">
              <div className="p-8 border border-dashed border-[#1e2530] rounded-lg text-center">
                <KeyRound className="w-8 h-8 text-[#22c55e] mx-auto mb-3 opacity-50" />
                <p className="text-[#9ca3af] font-mono text-sm">Gestor de secretos cifrados en HashiCorp Vault.</p>
              </div>
            </TabsContent>
          </Tabs>

        </main>
      </div>
    </div>
  );
}