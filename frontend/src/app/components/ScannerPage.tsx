import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { Search, Plus, Trash2, Play, Activity, AlertCircle, CheckCircle2, Clock } from 'lucide-react';
import { useState } from 'react';

interface ScanTarget {
  id: string;
  target: string;
  type: 'ip' | 'domain';
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  vulnerabilities: number;
  lastScan: string;
  ports?: string;
}

const initialTargets: ScanTarget[] = [
  {
    id: '1',
    target: '192.168.1.45',
    type: 'ip',
    status: 'completed',
    vulnerabilities: 3,
    lastScan: '2026-05-13 12:45:18',
    ports: '22,80,443,3389',
  },
  {
    id: '2',
    target: 'web-server-03.internal',
    type: 'domain',
    status: 'scanning',
    vulnerabilities: 0,
    lastScan: '2026-05-13 14:30:02',
    ports: '80,443,8080',
  },
  {
    id: '3',
    target: '10.0.0.127',
    type: 'ip',
    status: 'completed',
    vulnerabilities: 7,
    lastScan: '2026-05-13 11:22:35',
    ports: '21,22,23,80,443,445,3306',
  },
  {
    id: '4',
    target: 'db-server-01.internal',
    type: 'domain',
    status: 'completed',
    vulnerabilities: 2,
    lastScan: '2026-05-13 10:15:47',
    ports: '3306,5432',
  },
  {
    id: '5',
    target: '172.16.0.89',
    type: 'ip',
    status: 'failed',
    vulnerabilities: 0,
    lastScan: '2026-05-13 09:08:12',
    ports: '',
  },
  {
    id: '6',
    target: 'mail-server-02.internal',
    type: 'domain',
    status: 'pending',
    vulnerabilities: 0,
    lastScan: '-',
    ports: '',
  },
];

export function ScannerPage() {
  const [targets, setTargets] = useState<ScanTarget[]>(initialTargets);
  const [newTarget, setNewTarget] = useState('');
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());

  const handleAddTarget = () => {
    if (!newTarget.trim()) return;

    const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(newTarget);
    const newEntry: ScanTarget = {
      id: Date.now().toString(),
      target: newTarget.trim(),
      type: isIP ? 'ip' : 'domain',
      status: 'pending',
      vulnerabilities: 0,
      lastScan: '-',
      ports: '',
    };

    setTargets([...targets, newEntry]);
    setNewTarget('');
  };

  const handleDeleteSelected = () => {
    setTargets(targets.filter(t => !selectedTargets.has(t.id)));
    setSelectedTargets(new Set());
  };

  const handleScanSelected = () => {
    setTargets(targets.map(t => {
      if (selectedTargets.has(t.id) && t.status !== 'scanning') {
        return { ...t, status: 'scanning' };
      }
      return t;
    }));
  };

  const toggleSelect = (id: string) => {
    const newSelected = new Set(selectedTargets);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedTargets(newSelected);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'text-[#22c55e] bg-[#22c55e]/10 border-[#22c55e]/30';
      case 'scanning':
        return 'text-[#00d4ff] bg-[#00d4ff]/10 border-[#00d4ff]/30';
      case 'failed':
        return 'text-[#ff3b3b] bg-[#ff3b3b]/10 border-[#ff3b3b]/30';
      case 'pending':
        return 'text-[#9ca3af] bg-[#374151]/10 border-[#4b5563]/30';
      default:
        return 'text-[#9ca3af] bg-[#374151]/10 border-[#4b5563]/30';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="w-4 h-4" />;
      case 'scanning':
        return <Activity className="w-4 h-4 animate-pulse" />;
      case 'failed':
        return <AlertCircle className="w-4 h-4" />;
      case 'pending':
        return <Clock className="w-4 h-4" />;
      default:
        return null;
    }
  };

  const getVulnerabilityColor = (count: number) => {
    if (count === 0) return 'text-[#22c55e]';
    if (count <= 3) return 'text-[#f59e0b]';
    return 'text-[#ff3b3b]';
  };

  const completedScans = targets.filter(t => t.status === 'completed').length;
  const activeScans = targets.filter(t => t.status === 'scanning').length;
  const totalVulns = targets.reduce((sum, t) => sum + t.vulnerabilities, 0);

  return (
    <div className="flex h-screen bg-[#0f1117]">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar role="System Manager" />

        <main className="flex-1 overflow-auto p-6 space-y-6">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-semibold text-white mb-2">Network Scanner</h1>
              <p className="text-[#9ca3af]">Escaneo de IPs y dominios - Módulo 2</p>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#00d4ff]/10 rounded-lg flex items-center justify-center">
                  <Search className="w-5 h-5 text-[#00d4ff]" />
                </div>
              </div>
              <div className="text-3xl font-semibold text-white mb-1">{targets.length}</div>
              <div className="text-sm text-[#9ca3af]">Total Targets</div>
            </div>

            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#22c55e]/10 rounded-lg flex items-center justify-center">
                  <CheckCircle2 className="w-5 h-5 text-[#22c55e]" />
                </div>
              </div>
              <div className="text-3xl font-semibold text-white mb-1">{completedScans}</div>
              <div className="text-sm text-[#9ca3af]">Completed Scans</div>
            </div>

            <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 bg-[#ff3b3b]/10 rounded-lg flex items-center justify-center">
                  <AlertCircle className="w-5 h-5 text-[#ff3b3b]" />
                </div>
              </div>
              <div className="text-3xl font-semibold text-white mb-1">{totalVulns}</div>
              <div className="text-sm text-[#9ca3af]">Total Vulnerabilities</div>
            </div>
          </div>

          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Add Target</h2>

            <div className="flex gap-3">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#9ca3af]" />
                <input
                  type="text"
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAddTarget()}
                  className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-10 pr-4 py-2.5 text-white placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] focus:ring-1 focus:ring-[#00d4ff] transition-colors font-mono"
                  placeholder="192.168.1.100 o ejemplo.com"
                />
              </div>
              <button
                onClick={handleAddTarget}
                className="px-6 py-2.5 bg-[#00d4ff] hover:bg-[#00b8e6] text-[#0f1117] font-semibold rounded-lg transition-colors flex items-center gap-2"
              >
                <Plus className="w-4 h-4" />
                Add Target
              </button>
            </div>
          </div>

          <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-[#1e2530]">
              <h2 className="text-lg font-semibold text-white">Scan Targets</h2>
              <div className="flex items-center gap-3">
                {selectedTargets.size > 0 && (
                  <>
                    <button
                      onClick={handleScanSelected}
                      className="px-4 py-2 bg-[#22c55e] hover:bg-[#16a34a] text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
                    >
                      <Play className="w-4 h-4" />
                      Scan ({selectedTargets.size})
                    </button>
                    <button
                      onClick={handleDeleteSelected}
                      className="px-4 py-2 bg-[#ff3b3b] hover:bg-[#dc2626] text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
                    >
                      <Trash2 className="w-4 h-4" />
                      Delete
                    </button>
                  </>
                )}
                {activeScans > 0 && (
                  <div className="flex items-center gap-2 text-xs text-[#00d4ff]">
                    <div className="w-2 h-2 bg-[#00d4ff] rounded-full animate-pulse"></div>
                    {activeScans} scanning
                  </div>
                )}
              </div>
            </div>

            <div className="overflow-auto">
              <table className="w-full">
                <thead className="bg-[#0f1117] border-b border-[#1e2530]">
                  <tr>
                    <th className="px-4 py-3 text-left">
                      <input
                        type="checkbox"
                        checked={selectedTargets.size === targets.length && targets.length > 0}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedTargets(new Set(targets.map(t => t.id)));
                          } else {
                            setSelectedTargets(new Set());
                          }
                        }}
                        className="w-4 h-4 rounded border-[#1e2530] bg-[#0f1117] text-[#00d4ff] focus:ring-[#00d4ff] focus:ring-offset-0"
                      />
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Target</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Type</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Vulnerabilities</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Open Ports</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-[#9ca3af] uppercase tracking-wider">Last Scan</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2530]">
                  {targets.map((target) => (
                    <tr key={target.id} className="hover:bg-[#0f1117]/50 transition-colors">
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={selectedTargets.has(target.id)}
                          onChange={() => toggleSelect(target.id)}
                          className="w-4 h-4 rounded border-[#1e2530] bg-[#0f1117] text-[#00d4ff] focus:ring-[#00d4ff] focus:ring-offset-0"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-sm text-white">{target.target}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-[#374151] text-[#e5e7eb]">
                          {target.type.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border text-xs font-semibold ${getStatusColor(target.status)}`}>
                          {getStatusIcon(target.status)}
                          <span className="capitalize">{target.status}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-sm font-semibold ${getVulnerabilityColor(target.vulnerabilities)}`}>
                          {target.vulnerabilities}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-[#9ca3af]">
                          {target.ports || '-'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-[#9ca3af]">
                          {target.lastScan}
                        </span>
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
