import { useMemo } from 'react';
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';

// ─── Palettes ───────────────────────────────────────────────────────────────
const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#f59e0b',
  LOW:      '#3b82f6',
  INFO:     '#475569',
};

const PORT_COLORS = ['#8B5CF6', '#22c55e', '#f59e0b', '#a78bfa', '#f87171'];

// ─── Fallback data ───────────────────────────────────────────────────────────
const DEFAULT_SEVERITY_DATA = [
  { name: 'CRITICAL', value: 3 },
  { name: 'HIGH',     value: 5 },
  { name: 'MEDIUM',   value: 8 },
  { name: 'LOW',      value: 4 },
];

const DEFAULT_PORT_DATA = [
  { name: '443/tcp', value: 12 },
  { name: '80/tcp',  value: 9 },
  { name: '22/tcp',  value: 7 },
  { name: '3389/tcp',value: 4 },
  { name: '8080/tcp',value: 3 },
];

const DEFAULT_TOOL_DATA = [
  { name: 'Nuclei', CRITICAL: 2, HIGH: 3, MEDIUM: 4 },
  { name: 'Nmap',   CRITICAL: 0, HIGH: 2, MEDIUM: 3 },
  { name: 'Trivy',  CRITICAL: 1, HIGH: 0, MEDIUM: 1 },
];

// ─── Custom tooltip ──────────────────────────────────────────────────────────
function DarkTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-[#111318] border border-[#1C2030] rounded-lg px-3 py-2 shadow-lg text-xs font-mono">
      {payload.map((p, i) => (
        <div key={i} className="flex items-center gap-2">
          <span style={{ color: p.fill ?? p.color }} className="font-semibold">{p.name}</span>
          <span className="text-white">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

/** Renders the label in the center of the donut. */
function DonutLabel({ cx, cy, total }) {
  return (
    <>
      <text x={cx} y={cy - 6} textAnchor="middle" className="fill-white" fontSize={22} fontWeight={600}>
        {total}
      </text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="#475569" fontSize={11}>
        hallazgos
      </text>
    </>
  );
}

// ─── Section wrapper ─────────────────────────────────────────────────────────
function ChartCard({ title, children }) {
  return (
    <div className="bg-[#111318] border border-[#1C2030] rounded-lg p-5 flex flex-col gap-4">
      <h3 className="text-sm font-semibold text-[#64748B] uppercase tracking-wider">{title}</h3>
      {children}
    </div>
  );
}

/**
 * SurfaceMap — resumen visual de la superficie de ataque.
 * Acepta `data` del hook (opcional); usa fallback si no hay datos.
 */
export function SurfaceMap({ data }) {
  // Derive chart data from API payload or fall back to defaults
  const severityData = useMemo(() => {
    if (!data?.severity_counts) return DEFAULT_SEVERITY_DATA;
    return Object.entries(data.severity_counts).map(([name, value]) => ({ name, value }));
  }, [data]);

  const portData = useMemo(() => {
    if (!data?.top_ports) return DEFAULT_PORT_DATA;
    return data.top_ports.slice(0, 5).map(p => ({ name: p.port, value: p.count }));
  }, [data]);

  const toolData = useMemo(() => {
    if (!data?.tool_breakdown) return DEFAULT_TOOL_DATA;
    return data.tool_breakdown;
  }, [data]);

  const total = useMemo(() => severityData.reduce((s, d) => s + d.value, 0), [severityData]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Donut — Distribución de severidad */}
      <ChartCard title="Distribución de Severidad">
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie
              data={severityData}
              cx="50%"
              cy="50%"
              innerRadius={70}
              outerRadius={100}
              paddingAngle={3}
              dataKey="value"
              label={false}
            >
              {severityData.map((entry, i) => (
                <Cell key={i} fill={SEVERITY_COLORS[entry.name] ?? '#475569'} stroke="transparent" />
              ))}
            </Pie>
            <DonutLabel cx="50%" cy="50%" total={total} />
            <Tooltip content={<DarkTooltip />} />
            <Legend
              iconType="circle"
              iconSize={8}
              formatter={(value) => (
                <span className="text-xs text-[#64748B] font-mono">{value}</span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </ChartCard>

      {/* Donut — Top 5 Puertos */}
      <ChartCard title="Top 5 Puertos Expuestos">
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie
              data={portData}
              cx="50%"
              cy="50%"
              innerRadius={70}
              outerRadius={100}
              paddingAngle={3}
              dataKey="value"
              label={false}
            >
              {portData.map((_, i) => (
                <Cell key={i} fill={PORT_COLORS[i % PORT_COLORS.length]} stroke="transparent" />
              ))}
            </Pie>
            <Tooltip content={<DarkTooltip />} />
            <Legend
              iconType="circle"
              iconSize={8}
              formatter={(value) => (
                <span className="text-xs text-[#64748B] font-mono">{value}</span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </ChartCard>

      {/* Bar — Hallazgos por herramienta */}
      <ChartCard title="Hallazgos por Herramienta">
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={toolData} barCategoryGap="30%">
            <CartesianGrid strokeDasharray="3 3" stroke="#1C2030" vertical={false} />
            <XAxis
              dataKey="name"
              tick={{ fill: '#475569', fontSize: 11, fontFamily: 'monospace' }}
              axisLine={{ stroke: '#1C2030' }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: '#475569', fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip content={<DarkTooltip />} cursor={{ fill: '#1C2030' }} />
            <Bar dataKey="CRITICAL" stackId="a" fill={SEVERITY_COLORS.CRITICAL} radius={[0, 0, 0, 0]} />
            <Bar dataKey="HIGH"     stackId="a" fill={SEVERITY_COLORS.HIGH} />
            <Bar dataKey="MEDIUM"   stackId="a" fill={SEVERITY_COLORS.MEDIUM} radius={[4, 4, 0, 0]} />
            <Legend
              iconType="square"
              iconSize={8}
              formatter={(value) => (
                <span className="text-xs text-[#64748B] font-mono">{value}</span>
              )}
            />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      {/* Bar — Activos con más hallazgos */}
      <ChartCard title="Top Activos por Hallazgos">
        <ResponsiveContainer width="100%" height={220}>
          <BarChart
            data={data?.top_assets ?? [
              { name: '10.0.1.10', value: 6 },
              { name: '10.0.1.25', value: 4 },
              { name: '10.0.1.15', value: 3 },
              { name: '10.0.1.20', value: 2 },
              { name: '10.0.1.40', value: 1 },
            ]}
            layout="vertical"
            barCategoryGap="25%"
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#1C2030" horizontal={false} />
            <XAxis
              type="number"
              tick={{ fill: '#475569', fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              tick={{ fill: '#475569', fontSize: 11, fontFamily: 'monospace' }}
              axisLine={{ stroke: '#1C2030' }}
              tickLine={false}
              width={80}
            />
            <Tooltip content={<DarkTooltip />} cursor={{ fill: '#1C2030' }} />
            <Bar dataKey="value" fill="#8B5CF6" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>
    </div>
  );
}
