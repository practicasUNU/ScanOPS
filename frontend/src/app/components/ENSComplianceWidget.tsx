import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Legend } from 'recharts';
import { Shield } from 'lucide-react';

const overallComplianceData = [
  { name: 'Compliant', value: 85, color: '#22c55e' },
  { name: 'Pending', value: 15, color: '#374151' },
];

const domainComplianceData = [
  {
    domain: 'Organizational Framework',
    compliant: 18,
    notCompliant: 2,
    notApplicable: 1,
  },
  {
    domain: 'Operational Framework',
    compliant: 22,
    notCompliant: 4,
    notApplicable: 2,
  },
  {
    domain: 'Protection Measures',
    compliant: 20,
    notCompliant: 3,
    notApplicable: 1,
  },
];

const COLORS = {
  compliant: '#22c55e',
  notCompliant: '#ff3b3b',
  notApplicable: '#6b7280',
};

export function ENSComplianceWidget() {
  const renderCustomLabel = () => {
    return (
      <text
        x="50%"
        y="50%"
        textAnchor="middle"
        dominantBaseline="middle"
        className="fill-white"
      >
        <tspan x="50%" dy="-0.2em" fontSize="48" fontWeight="700">
          85%
        </tspan>
        <tspan x="50%" dy="1.5em" fontSize="14" className="fill-[#9ca3af]">
          Compliant
        </tspan>
      </text>
    );
  };

  const CustomLegend = () => (
    <div className="flex items-center justify-center gap-6 mt-4">
      <div className="flex items-center gap-2">
        <div className="w-3 h-3 rounded-sm bg-[#22c55e]"></div>
        <span className="text-xs text-[#e5e7eb]">Compliant</span>
      </div>
      <div className="flex items-center gap-2">
        <div className="w-3 h-3 rounded-sm bg-[#ff3b3b]"></div>
        <span className="text-xs text-[#e5e7eb]">Not Compliant</span>
      </div>
      <div className="flex items-center gap-2">
        <div className="w-3 h-3 rounded-sm bg-[#6b7280]"></div>
        <span className="text-xs text-[#e5e7eb]">Not Applicable</span>
      </div>
    </div>
  );

  return (
    <div className="bg-gradient-to-br from-[#1a1d27]/95 via-[#1a1d27]/90 to-[#1a1d27]/95 backdrop-blur-xl border border-[#1e2530] rounded-lg p-6">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 bg-[#00d4ff]/10 rounded-lg flex items-center justify-center">
          <Shield className="w-5 h-5 text-[#00d4ff]" />
        </div>
        <div>
          <h2 className="text-lg font-semibold text-white">ENS Compliance Status</h2>
          <p className="text-sm text-[#9ca3af]">Esquema Nacional de Seguridad</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Overall Compliance Score - Donut Chart */}
        <div className="bg-[#0f1117]/50 border border-[#1e2530] rounded-lg p-6">
          <h3 className="text-sm font-semibold text-[#e5e7eb] mb-4 text-center">
            Overall Compliance Score
          </h3>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={overallComplianceData}
                cx="50%"
                cy="50%"
                innerRadius={80}
                outerRadius={110}
                paddingAngle={2}
                dataKey="value"
                startAngle={90}
                endAngle={-270}
              >
                {overallComplianceData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.color}
                    stroke={entry.color}
                    strokeWidth={index === 0 ? 2 : 0}
                    style={{
                      filter: index === 0 ? 'drop-shadow(0 0 8px rgba(34, 197, 94, 0.4))' : 'none',
                    }}
                  />
                ))}
              </Pie>
              {renderCustomLabel()}
            </PieChart>
          </ResponsiveContainer>
          <div className="text-center mt-4">
            <p className="text-xs text-[#9ca3af]">
              <span className="text-[#22c55e] font-semibold">62 of 73</span> measures compliant
            </p>
          </div>
        </div>

        {/* Compliance by Domain - Horizontal Stacked Bar Chart */}
        <div className="bg-[#0f1117]/50 border border-[#1e2530] rounded-lg p-6">
          <h3 className="text-sm font-semibold text-[#e5e7eb] mb-4 text-center">
            Compliance by Domain
          </h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart
              data={domainComplianceData}
              layout="vertical"
              margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
            >
              <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 12 }} stroke="#374151" />
              <YAxis
                type="category"
                dataKey="domain"
                tick={{ fill: '#e5e7eb', fontSize: 12 }}
                stroke="#374151"
                width={160}
              />
              <Bar dataKey="compliant" stackId="a" fill={COLORS.compliant} radius={[0, 0, 0, 0]} />
              <Bar dataKey="notCompliant" stackId="a" fill={COLORS.notCompliant} radius={[0, 0, 0, 0]} />
              <Bar dataKey="notApplicable" stackId="a" fill={COLORS.notApplicable} radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
          <CustomLegend />
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-3 gap-4 mt-6 pt-6 border-t border-[#1e2530]">
        <div className="text-center">
          <div className="text-2xl font-semibold text-[#22c55e]">62</div>
          <div className="text-xs text-[#9ca3af] mt-1">Compliant</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-semibold text-[#ff3b3b]">9</div>
          <div className="text-xs text-[#9ca3af] mt-1">Not Compliant</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-semibold text-[#6b7280]">4</div>
          <div className="text-xs text-[#9ca3af] mt-1">Not Applicable</div>
        </div>
      </div>
    </div>
  );
}
