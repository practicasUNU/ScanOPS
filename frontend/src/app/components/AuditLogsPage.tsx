import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

export function AuditLogsPage() {
  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="Auditor" />

        <main className="flex-1 flex items-center justify-center">
          <div className="text-center space-y-2">
            <p className="text-[#9ca3af] font-mono text-sm">Vista en construcción · HITO 8 en progreso</p>
          </div>
        </main>
      </div>
    </div>
  );
}
