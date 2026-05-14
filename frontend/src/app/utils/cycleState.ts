export type DotColor = 'green' | 'amber' | 'gray';

export interface CycleState {
  label: string;
  phase: string;
  dotColor: DotColor;
  dot: '●' | '⏸' | '◌';
  activeBlock: 0 | 1 | 2 | -1;
  timeRemaining: string;
  weekLabel: string;
}

function getISOWeek(date: Date): number {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  return Math.ceil((((d.getTime() - yearStart.getTime()) / 86400000) + 1) / 7);
}

function hoursUntil(now: Date, targetDay: number, targetHour: number): string {
  const target = new Date(now);
  let daysUntil = (targetDay - now.getDay() + 7) % 7;
  if (daysUntil === 0) daysUntil = 7;
  target.setDate(target.getDate() + daysUntil);
  target.setHours(targetHour, 0, 0, 0);
  const diff = target.getTime() - now.getTime();
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  return `Faltan ${h}h ${m}m`;
}

export function getCycleState(): CycleState {
  const now = new Date();
  const day = now.getDay(); // 0=Sun 1=Mon 2=Tue 3=Wed 4=Thu 5=Fri 6=Sat
  const week = getISOWeek(now);
  const year = now.getFullYear();
  const weekLabel = `Semana ${week} · ${year}`;

  switch (day) {
    case 1:
      return {
        label: 'Ciclo activo · Lunes · Fase 1 — M1 + M2 en curso',
        phase: 'Fase 1 — Inventario',
        dotColor: 'green',
        dot: '●',
        activeBlock: 0,
        timeRemaining: hoursUntil(now, 2, 0),
        weekLabel,
      };
    case 2:
      return {
        label: 'Ciclo activo · Martes · Fase 2 — M3 + M8-IA en curso',
        phase: 'Fase 2 — Análisis',
        dotColor: 'green',
        dot: '●',
        activeBlock: 1,
        timeRemaining: hoursUntil(now, 4, 0),
        weekLabel,
      };
    case 3:
      return {
        label: 'Ciclo activo · Miércoles · Fase 2 — M3 + M8-IA en curso',
        phase: 'Fase 2 — Análisis',
        dotColor: 'green',
        dot: '●',
        activeBlock: 1,
        timeRemaining: hoursUntil(now, 4, 0),
        weekLabel,
      };
    case 4:
      return {
        label: 'Fase 3 — Revisión humana · Pendiente de firma',
        phase: 'Fase 3 — Revisión',
        dotColor: 'amber',
        dot: '⏸',
        activeBlock: 1,
        timeRemaining: hoursUntil(now, 6, 1),
        weekLabel,
      };
    case 6:
      return {
        label: 'Ciclo activo · Sábado · Fase 4 — M4 Explotación en curso',
        phase: 'Fase 4 — Explotación',
        dotColor: 'green',
        dot: '●',
        activeBlock: 2,
        timeRemaining: hoursUntil(now, 0, 7),
        weekLabel,
      };
    case 0:
      return {
        label: 'Ciclo activo · Domingo · Fase 5 — M7 Reporting',
        phase: 'Fase 5 — Reporting',
        dotColor: 'green',
        dot: '●',
        activeBlock: 2,
        timeRemaining: hoursUntil(now, 1, 2),
        weekLabel,
      };
    default: // Friday (5)
      return {
        label: 'Ciclo en espera · Próximo inicio: Lunes 02:00',
        phase: 'En espera',
        dotColor: 'gray',
        dot: '◌',
        activeBlock: -1,
        timeRemaining: hoursUntil(now, 1, 2),
        weekLabel,
      };
  }
}
