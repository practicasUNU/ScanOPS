// frontend/src/app/components/SettingsPage.tsx
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

export function SettingsPage() {
  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />

        <main className="flex-1 overflow-auto p-6 space-y-6">
          <div>
            <h1 className="text-2xl font-semibold text-white mb-1">Configuración</h1>
            <p className="text-[#9ca3af] text-sm">Gestión de parámetros del entorno ScanOps</p>
          </div>

          <div className="flex-1 flex items-center justify-center mt-20">
            <div className="text-center space-y-2">
              <p className="text-[#9ca3af] font-mono text-sm">Vista de configuración en construcción</p>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}