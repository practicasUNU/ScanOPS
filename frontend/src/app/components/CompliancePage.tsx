import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { CheckCircle2, AlertTriangle, XCircle, Download, FileText } from 'lucide-react';
import { useState } from 'react';

const cycleHistory = [
  {
    week: 'Semana 19 · 2026',
    inicio: '2026-05-04 02:00',
    fin: '2026-05-10 23:59',
    modules: ['M1', 'M2', 'M3', 'M8', 'M4', 'M7'],
    incidencias: 0,
  },
  {
    week: 'Semana 18 · 2026',
    inicio: '2026-04-27 02:00',
    fin: '2026-05-03 23:59',
    modules: ['M1', 'M2', 'M3', 'M8', 'M4', 'M7'],
    incidencias: 2,
  },
  {
    week: 'Semana 17 · 2026',
    inicio: '2026-04-20 02:00',
    fin: '2026-04-26 23:59',
    modules: ['M1', 'M2', 'M3', 'M8', 'M4'],
    incidencias: 1,
  },
  {
    week: 'Semana 16 · 2026',
    inicio: '2026-04-13 02:00',
    fin: '2026-04-19 23:59',
    modules: ['M1', 'M2', 'M3', 'M8', 'M4', 'M7'],
    incidencias: 0,
  },
];

const generateMeasures = () => {
  const statuses = ['compliant', 'compliant', 'compliant', 'compliant', 'compliant', 'partial', 'non-compliant'];
  const categories = [
    { prefix: 'op.exp', count: 11, name: 'Operational' },
    { prefix: 'mp.per', count: 8, name: 'Personnel' },
    { prefix: 'mp.eq', count: 7, name: 'Equipment' },
    { prefix: 'mp.si', count: 9, name: 'Systems' },
    { prefix: 'mp.sw', count: 6, name: 'Software' },
    { prefix: 'mp.com', count: 8, name: 'Communications' },
    { prefix: 'org', count: 6, name: 'Organizational' },
    { prefix: 'op.pl', count: 7, name: 'Planning' },
    { prefix: 'op.acc', count: 11, name: 'Access' },
  ];

  const measures = [];
  categories.forEach(cat => {
    for (let i = 1; i <= cat.count; i++) {
      measures.push({
        id: `${cat.prefix}.${i}`,
        status: statuses[Math.floor(Math.random() * statuses.length)],
        category: cat.name,
      });
    }
  });
  return measures;
};

const ensMeasures = generateMeasures();

const reports = [
  { name: 'Informe Técnico', date: '2026-05-10', size: '2.4 MB' },
  { name: 'Informe Ejecutivo', date: '2026-05-10', size: '847 KB' },
  { name: 'Statement of Applicability (SoA)', date: '2026-05-10', size: '1.2 MB' },
  { name: 'Plan de Remediación', date: '2026-05-10', size: '1.8 MB' },
];

export function CompliancePage() {
  const [selectedMeasure, setSelectedMeasure] = useState<string | null>(null);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'bg-[#22c55e] border-[#22c55e]';
      case 'partial':
        return 'bg-[#f59e0b] border-[#f59e0b]';
      case 'non-compliant':
        return 'bg-[#ff3b3b] border-[#ff3b3b]';
      default:
        return 'bg-[#374151] border-[#4b5563]';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant':
        return <CheckCircle2 className="w-4 h-4" />;
      case 'partial':
        return <AlertTriangle className="w-4 h-4" />;
      case 'non-compliant':
        return <XCircle className="w-4 h-4" />;
      default:
        return null;
    }
  };

  const compliantCount = ensMeasures.filter(m => m.status === 'compliant').length;
  const partialCount = ensMeasures.filter(m => m.status === 'partial').length;
  const nonCompliantCount = ensMeasures.filter(m => m.status === 'non-compliant').length;

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="Auditor" />

        <main className="flex-1 overflow-auto p-6 space-y-6">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-semibold text-white mb-2">ENS Compliance Overview</h1>
              <p className="text-[#9ca3af]">73 measures assessed for ENS Alto certification</p>
            </div>

            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-[#22c55e] rounded"></div>
                <span className="text-sm text-[#9ca3af]">{compliantCount} Compliant</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-[#f59e0b] rounded"></div>
                <span className="text-sm text-[#9ca3af]">{partialCount} Partial</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-[#ff3b3b] rounded"></div>
                <span className="text-sm text-[#9ca3af]">{nonCompliantCount} Non-Compliant</span>
              </div>
            </div>
          </div>

          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Compliance Matrix</h2>

            <div className="grid grid-cols-10 gap-2">
              {ensMeasures.map((measure) => (
                <button
                  key={measure.id}
                  onClick={() => setSelectedMeasure(measure.id)}
                  className={`aspect-square rounded border-2 transition-all hover:scale-105 hover:shadow-lg flex items-center justify-center ${getStatusColor(measure.status)} ${
                    selectedMeasure === measure.id ? 'ring-2 ring-[#00d4ff] ring-offset-2 ring-offset-[#1a1d27]' : ''
                  }`}
                  title={measure.id}
                >
                  <span className="text-xs font-mono font-semibold text-white opacity-0 hover:opacity-100 transition-opacity">
                    {measure.id.split('.').pop()}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {selectedMeasure && (
            <div className="bg-[#1a1d27] border border-[#00d4ff]/30 rounded-lg p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h2 className="text-lg font-semibold text-white mb-1 font-mono">{selectedMeasure}</h2>
                  <p className="text-[#9ca3af]">
                    {ensMeasures.find(m => m.id === selectedMeasure)?.category}
                  </p>
                </div>
                <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border ${
                  ensMeasures.find(m => m.id === selectedMeasure)?.status === 'compliant'
                    ? 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30'
                    : ensMeasures.find(m => m.id === selectedMeasure)?.status === 'partial'
                    ? 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30'
                    : 'bg-[#ff3b3b]/10 text-[#ff3b3b] border-[#ff3b3b]/30'
                }`}>
                  {getStatusIcon(ensMeasures.find(m => m.id === selectedMeasure)?.status || '')}
                  <span className="text-sm font-semibold capitalize">
                    {ensMeasures.find(m => m.id === selectedMeasure)?.status.replace('-', ' ')}
                  </span>
                </div>
              </div>

              <div className="space-y-3">
                <div>
                  <div className="text-xs text-[#9ca3af] mb-1">Evidence</div>
                  <div className="text-sm text-white">Configuration audit logs, access control policies, and encryption certificates verified.</div>
                </div>
                <div>
                  <div className="text-xs text-[#9ca3af] mb-1">Last Assessment</div>
                  <div className="text-sm text-white">2026-05-10 14:32:18</div>
                </div>
              </div>
            </div>
          )}

          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Compliance Reports</h2>

            <div className="space-y-3">
              {reports.map((report) => (
                <div key={report.name} className="flex items-center justify-between p-4 bg-[#0f1117] border border-[#1e2530] rounded-lg hover:border-[#00d4ff]/30 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-[#ff3b3b]/10 rounded-lg flex items-center justify-center">
                      <FileText className="w-5 h-5 text-[#ff3b3b]" />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-white">{report.name}</div>
                      <div className="text-xs text-[#9ca3af]">{report.date} • {report.size}</div>
                    </div>
                  </div>
                  <button className="px-4 py-2 bg-[#00d4ff]/10 hover:bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/30 font-semibold rounded-lg transition-colors flex items-center gap-2">
                    <Download className="w-4 h-4" />
                    Download PDF
                  </button>
                </div>
              ))}
            </div>
          </div>
          {/* Historial de Ciclos */}
          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Historial de Ciclos</h2>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-[#9ca3af] border-b border-[#1e2530]">
                    <th className="pb-3 pr-4 font-medium">Semana</th>
                    <th className="pb-3 pr-4 font-medium">Inicio</th>
                    <th className="pb-3 pr-4 font-medium">Fin</th>
                    <th className="pb-3 pr-4 font-medium">Módulos</th>
                    <th className="pb-3 pr-4 font-medium">Incidencias</th>
                    <th className="pb-3 font-medium">Informe</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2530]">
                  {cycleHistory.map((row) => (
                    <tr
                      key={row.week}
                      className="group bg-[#0f1117] border border-[#1e2530] hover:border-[#00d4ff]/30 transition-colors"
                    >
                      <td className="py-3 pr-4 pl-0 font-mono text-xs text-white">{row.week}</td>
                      <td className="py-3 pr-4 font-mono text-xs text-[#9ca3af]">{row.inicio}</td>
                      <td className="py-3 pr-4 font-mono text-xs text-[#9ca3af]">{row.fin}</td>
                      <td className="py-3 pr-4">
                        <div className="flex flex-wrap gap-1">
                          {row.modules.map((m) => (
                            <span
                              key={m}
                              className="px-1.5 py-0.5 bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/20 rounded text-xs font-mono"
                            >
                              {m}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 pr-4">
                        <span className={`font-mono text-sm font-semibold ${row.incidencias > 0 ? 'text-[#ff3b3b]' : 'text-[#22c55e]'}`}>
                          {row.incidencias}
                        </span>
                      </td>
                      <td className="py-3">
                        <button className="px-3 py-1.5 bg-[#00d4ff]/10 hover:bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/30 rounded-lg transition-colors flex items-center gap-1.5 text-xs font-semibold">
                          <Download className="w-3 h-3" />
                          Descargar PDF
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
