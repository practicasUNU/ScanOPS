const SEVERITY = {
  CRITICAL: { color: '#EF4444', bg: 'rgba(239,68,68,0.10)', border: 'rgba(239,68,68,0.28)' },
  HIGH:     { color: '#F97316', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.28)' },
  MEDIUM:   { color: '#A78BFA', bg: 'rgba(167,139,250,0.10)', border: 'rgba(167,139,250,0.28)' },
  LOW:      { color: '#22C55E', bg: 'rgba(34,197,94,0.10)',  border: 'rgba(34,197,94,0.28)' },
  INFO:     { color: '#64748B', bg: 'rgba(100,116,139,0.10)', border: 'rgba(100,116,139,0.28)' },
} as const;

type SeverityKey = keyof typeof SEVERITY;

interface SeverityBadgeProps {
  severity: string | undefined | null;
  size?: 'xs' | 'sm';
}

export function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const raw = (severity ?? 'INFO').toUpperCase();
  const key: SeverityKey = (raw in SEVERITY ? raw : 'INFO') as SeverityKey;
  const cfg = SEVERITY[key];
  const label = raw.charAt(0) + raw.slice(1).toLowerCase();

  const dotSize  = size === 'xs' ? 5  : 6;
  const fontSize = size === 'xs' ? 9  : 11;
  const px       = size === 'xs' ? 6  : 8;
  const py       = size === 'xs' ? 1  : 2;

  return (
    <span
      className="inline-flex items-center gap-1.5 font-semibold rounded-full whitespace-nowrap"
      style={{
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        color: cfg.color,
        fontSize,
        padding: `${py}px ${px}px`,
        lineHeight: 1,
      }}
    >
      <span
        className="rounded-full shrink-0"
        style={{ width: dotSize, height: dotSize, background: cfg.color }}
      />
      {label}
    </span>
  );
}
