UPDATE THIS PROJECT with the following changes. Keep all existing code, colors, and components — only add or modify what is specified below.

1. TOPBAR — Add cycle status indicator (center)
In TopBar.tsx, add a centered status pill between the left logo area and the right user info. The pill shows the current weekly cycle state dynamically based on the current day of the week:

Monday: ● Ciclo activo · Lunes · Fase 1 — M1 + M2 en curso
Tuesday/Wednesday: ● Ciclo activo · Martes · Fase 2 — M3 + M8-IA en curso
Thursday: ⏸ Fase 3 — Revisión humana · Pendiente de firma
Saturday: ● Ciclo activo · Sábado · Fase 4 — M4 Explotación en curso
Sunday: ● Ciclo activo · Domingo · Fase 5 — M7 Reporting
Friday or idle: ◌ Ciclo en espera · Próximo inicio: Lunes 02:00

Color: green dot for active, amber for Thursday (awaiting approval), gray for idle. Font: monospace, text-xs. This pill is visible on all pages for all roles.

2. DASHBOARD — Replace "Next Scan" KPI card
Replace the 4th KPI card ("Monday 02:00 / Next Scan") with a dynamic "Ciclo Semanal" card that shows:

Top: Current week label — Semana 20 · 2026
Middle large: Current phase name — Fase 2 — Análisis
Bottom: Time remaining in this phase window — Faltan 6h 14m

Use amber (#f59e0b) icon (a calendar or repeat icon from lucide-react).

3. DASHBOARD — Redesign the Pipeline section with temporal grouping
Replace the current flat horizontal pipeline bar with a 3-block temporal layout. Each block represents a time window of the weekly cycle:
┌─────────────────┐   ┌──────────────────────┐   ┌─────────────────┐
│  LUNES 02:00    │   │  MAR/MIÉ 00:00        │   │  SAB/DOM 01:00  │
│  Fase 1         │   │  Fase 2 + Fase 3       │   │  Fase 4 + 5     │
│  [M1] [M2]     │   │  [M3] [M8-IA] [👤]    │   │  [M4] [M7]     │
└─────────────────┘   └──────────────────────┘   └─────────────────┘
Each block:

Header: day/time label in text-xs text-[#9ca3af]
Phase label: "Fase 1 — Inventario" in text-sm text-white
Module badges: same color logic as current (green=completed, cyan pulse=in-progress, gray=pending)
Add a special badge for the human approval gate on Thursday: 👤 Revisión in amber
Blocks connected by → arrows between them
Active block has a cyan border glow: border border-[#00d4ff]/40 shadow-[0_0_12px_rgba(0,212,255,0.15)]


4. DASHBOARD — Add pause state banner
Add a conditional banner that appears between TopBar and the main content when the cycle is manually paused. Implement a isPausedManually state (default false). The banner:

Background: bg-[#f59e0b]/10 border border-[#f59e0b]/30
Icon: ⏸ in amber
Text: Ciclo pausado manualmente · Reanudación automática: Viernes 18:00
Right side: two buttons — Reanudar ahora (amber) and Ver motivo (ghost)

Important: This is different from the Kill Switch. Add a comment in the code: // PAUSA: responsable puede reanudar · KILL SWITCH: requiere reactivación manual
Wire the existing "Pause" button to toggle isPausedManually.

5. DASHBOARD — Add Kill Switch confirmation modal
The Kill Switch button currently has no confirmation. Add a Radix Dialog modal that opens on click:

Title: ⚠ Activar Kill Switch in red
Body text: Esta acción detiene completamente el ciclo semanal. No se reanudará automáticamente. Requiere reactivación manual por el Responsable de Sistemas.
Input field: TOTP 6-digit code (same style as LoginPage)
Two buttons: Confirmar Kill Switch (bg-[#ff3b3b], full width) and Cancelar (ghost)
After confirmation: show a persistent red banner at the top: 🔴 Kill Switch activo · Ciclo detenido · Reactivación manual requerida


6. EXPLOITATION PAGE — Add temporal context to each request card
In ExploitationPage.tsx, add two fields to each exploit request card, below the existing target/module grid:

Ventana programada: Sábado 01:00 — Domingo 07:00 (text-xs text-[#9ca3af] label + text-sm text-white value in monospace)
Tiempo hasta ejecución: En 6h 14m (amber text if <12h, white if more)

Also add a auto-proceed notice at the top of the page, below the title:
ℹ Si no se toma acción antes de Sábado 01:00, el sistema procederá automáticamente según el plan de ataque aprobado por M8-IA.
Style: bg-[#00d4ff]/5 border border-[#00d4ff]/20 rounded-lg px-4 py-3 text-sm text-[#9ca3af]

7. COMPLIANCE PAGE — Add "Historial de Ciclos" table
In CompliancePage.tsx, add a new section below the compliance reports section. Title: Historial de Ciclos. A table with columns:
| Semana | Inicio | Fin | Módulos | Incidencias | Informe |
Add 4 mock rows of data (recent weeks going backward from May 2026). Each row:

"Módulos" column: small green badges for each completed module (M1 M2 M3 M8 M4 M7)
"Incidencias" column: a number, red if >0, green "0" if none
"Informe" column: a Descargar PDF button (same style as existing download buttons but smaller, text-xs)

Table styles: same as existing report rows (bg-[#0f1117] border border-[#1e2530]), with hover hover:border-[#00d4ff]/30.

8. SIDEBAR — Add missing navigation items
In Sidebar.tsx, add two new nav items after "Explotación":

Bell icon → label Alertas → path /alerts
ScrollText icon → label Logs Auditoría → path /audit-logs

Create two placeholder page components (AlertsPage.tsx and AuditLogsPage.tsx) with the same layout shell (Sidebar + TopBar) and a centered message: Vista en construcción · HITO 8 en progreso in text-[#9ca3af]. Register both routes in App.tsx.

Design constraints (do not change)

Background: #0f1117 · Cards: #1a1d27 · Borders: #1e2530
Accent cyan: #00d4ff · Critical red: #ff3b3b · Warning amber: #f59e0b · Success green: #22c55e
All new components follow the same card pattern: bg-[#1a1d27] border border-[#1e2530] rounded-lg
Font mono for: CVEs, IPs, module IDs, log entries, TOTP fields, time remaining
Do not add new dependencies beyond what is already in package.json