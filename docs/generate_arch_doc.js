const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat, HeadingLevel,
  BorderStyle, WidthType, ShadingType, PageNumber, PageBreak,
  TableOfContents, UnderlineType
} = require('docx');
const fs = require('fs');
const path = require('path');

// ─── Color palette ───────────────────────────────────────────────
const NAVY   = '1A2B4A';  // dark navy for header rows
const BLUE   = '2563EB';  // accent blue for headings
const SLATE  = '334155';  // secondary text
const WHITE  = 'FFFFFF';
const LIGHT  = 'F1F5F9';  // alternate row
const BORDER_COLOR = 'CBD5E1';

const PAGE_W  = 11906; // A4 width DXA
const PAGE_H  = 16838;
const MARGIN  = 1200;
const CONTENT = PAGE_W - MARGIN * 2; // 9506 DXA

// ─── Helpers ─────────────────────────────────────────────────────
function pt(n) { return n * 2; } // half-points

function cellBorder(color = BORDER_COLOR) {
  const b = { style: BorderStyle.SINGLE, size: 1, color };
  return { top: b, bottom: b, left: b, right: b };
}

function hCell(text, colW, isFirst = false) {
  return new TableCell({
    width: { size: colW, type: WidthType.DXA },
    borders: cellBorder(NAVY),
    shading: { fill: NAVY, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 140, right: 140 },
    children: [new Paragraph({
      children: [new TextRun({ text, bold: true, color: WHITE, size: pt(9), font: 'Arial' })],
    })],
  });
}

function dCell(text, colW, shade = false) {
  return new TableCell({
    width: { size: colW, type: WidthType.DXA },
    borders: cellBorder(),
    shading: shade ? { fill: LIGHT, type: ShadingType.CLEAR } : undefined,
    margins: { top: 70, bottom: 70, left: 140, right: 140 },
    children: [new Paragraph({
      children: [new TextRun({ text, size: pt(9), font: 'Arial' })],
    })],
  });
}

function monoCell(text, colW, shade = false) {
  return new TableCell({
    width: { size: colW, type: WidthType.DXA },
    borders: cellBorder(),
    shading: shade ? { fill: LIGHT, type: ShadingType.CLEAR } : undefined,
    margins: { top: 70, bottom: 70, left: 140, right: 140 },
    children: [new Paragraph({
      children: [new TextRun({ text, size: pt(9), font: 'Courier New' })],
    })],
  });
}

function tableRow(cells, shade) {
  return new TableRow({ children: cells });
}

function twoColTable(headers, rows, widths) {
  const [w1, w2] = widths || [Math.round(CONTENT * 0.38), Math.round(CONTENT * 0.62)];
  const total = w1 + w2;
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: [w1, w2],
    rows: [
      new TableRow({ children: [hCell(headers[0], w1), hCell(headers[1], w2)], tableHeader: true }),
      ...rows.map(([a, b], i) => tableRow([dCell(a, w1, i % 2 === 0), dCell(b, w2, i % 2 === 0)])),
    ],
  });
}

function threeColTable(headers, rows, widths) {
  const [w1, w2, w3] = widths || [Math.round(CONTENT * 0.3), Math.round(CONTENT * 0.3), Math.round(CONTENT * 0.4)];
  const total = w1 + w2 + w3;
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: [w1, w2, w3],
    rows: [
      new TableRow({ children: [hCell(headers[0], w1), hCell(headers[1], w2), hCell(headers[2], w3)], tableHeader: true }),
      ...rows.map(([a, b, c], i) => tableRow([
        dCell(a, w1, i % 2 === 0),
        dCell(b, w2, i % 2 === 0),
        dCell(c, w3, i % 2 === 0),
      ])),
    ],
  });
}

function fiveColTable(headers, rows, widths) {
  const total = widths.reduce((s, v) => s + v, 0);
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    rows: [
      new TableRow({
        children: headers.map((h, i) => hCell(h, widths[i])),
        tableHeader: true,
      }),
      ...rows.map((cols, ri) => new TableRow({
        children: cols.map((c, ci) => dCell(c, widths[ci], ri % 2 === 0)),
      })),
    ],
  });
}

function h1(text, id) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    pageBreakBefore: true,
    children: [new TextRun({ text, bold: true, size: pt(16), font: 'Arial', color: NAVY })],
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 120 },
    children: [new TextRun({ text, bold: true, size: pt(12), font: 'Arial', color: BLUE })],
  });
}

function h3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 200, after: 100 },
    children: [new TextRun({ text, bold: true, size: pt(10), font: 'Arial', color: SLATE })],
  });
}

function body(text, opts = {}) {
  return new Paragraph({
    spacing: { before: 80, after: 80 },
    children: [new TextRun({ text, size: pt(10), font: 'Arial', ...opts })],
  });
}

function bullet(text) {
  return new Paragraph({
    numbering: { reference: 'bullets', level: 0 },
    spacing: { before: 60, after: 60 },
    children: [new TextRun({ text, size: pt(10), font: 'Arial' })],
  });
}

function numItem(text) {
  return new Paragraph({
    numbering: { reference: 'numbers', level: 0 },
    spacing: { before: 60, after: 60 },
    children: [new TextRun({ text, size: pt(10), font: 'Arial' })],
  });
}

function spacer() {
  return new Paragraph({ spacing: { before: 60, after: 60 }, children: [new TextRun('')] });
}

function codeBlock(lines) {
  return new Paragraph({
    spacing: { before: 120, after: 120 },
    shading: { fill: 'EFF4FB', type: ShadingType.CLEAR },
    border: {
      top: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR },
      bottom: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR },
      left: { style: BorderStyle.THICK, size: 6, color: BLUE },
      right: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR },
    },
    indent: { left: 200, right: 200 },
    children: lines.map((l, i) => new TextRun({
      text: l,
      font: 'Courier New',
      size: pt(8),
      break: i === 0 ? 0 : 1,
    })),
  });
}

function labelValue(label, value) {
  return new Paragraph({
    spacing: { before: 60, after: 60 },
    children: [
      new TextRun({ text: label + ': ', bold: true, size: pt(10), font: 'Arial' }),
      new TextRun({ text: value, size: pt(10), font: 'Arial' }),
    ],
  });
}

function infoBox(lines) {
  return new Table({
    width: { size: CONTENT, type: WidthType.DXA },
    columnWidths: [CONTENT],
    rows: [new TableRow({
      children: [new TableCell({
        width: { size: CONTENT, type: WidthType.DXA },
        shading: { fill: 'EFF6FF', type: ShadingType.CLEAR },
        borders: {
          top: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR },
          bottom: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR },
          left: { style: BorderStyle.THICK, size: 8, color: BLUE },
          right: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR },
        },
        margins: { top: 120, bottom: 120, left: 200, right: 200 },
        children: lines.map(l => new Paragraph({
          children: [new TextRun({ text: l, size: pt(9), font: 'Arial' })],
        })),
      })],
    })],
  });
}

// ─── COVER PAGE section ──────────────────────────────────────────
function makeCoverSection() {
  return {
    properties: {
      page: {
        size: { width: PAGE_W, height: PAGE_H },
        margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN },
      },
    },
    children: [
      // Top accent bar
      new Paragraph({
        border: { top: { style: BorderStyle.THICK, size: 12, color: NAVY, space: 0 } },
        spacing: { before: 0, after: 400 },
        children: [],
      }),
      // Organization
      new Paragraph({
        alignment: AlignmentType.RIGHT,
        spacing: { before: 0, after: 200 },
        children: [new TextRun({ text: 'UNUWARE', bold: true, size: pt(20), font: 'Arial', color: BLUE })],
      }),
      new Paragraph({
        alignment: AlignmentType.RIGHT,
        spacing: { before: 0, after: 2000 },
        children: [new TextRun({ text: 'Ciberseguridad Empresarial', size: pt(11), font: 'Arial', color: SLATE })],
      }),
      // Main title
      new Paragraph({
        alignment: AlignmentType.LEFT,
        spacing: { before: 0, after: 300 },
        border: { left: { style: BorderStyle.THICK, size: 16, color: BLUE, space: 300 } },
        indent: { left: 400 },
        children: [new TextRun({ text: 'ScanOPS', bold: true, size: pt(36), font: 'Arial', color: NAVY })],
      }),
      new Paragraph({
        alignment: AlignmentType.LEFT,
        spacing: { before: 0, after: 200 },
        indent: { left: 400 },
        children: [new TextRun({ text: 'Documento de Arquitectura del Sistema', bold: true, size: pt(18), font: 'Arial', color: NAVY })],
      }),
      new Paragraph({
        alignment: AlignmentType.LEFT,
        spacing: { before: 0, after: 2000 },
        indent: { left: 400 },
        children: [new TextRun({ text: 'Plataforma de Operaciones de Seguridad Automatizada — ENS Alto', size: pt(12), font: 'Arial', color: SLATE })],
      }),
      // Metadata table
      new Table({
        width: { size: CONTENT, type: WidthType.DXA },
        columnWidths: [Math.round(CONTENT * 0.35), Math.round(CONTENT * 0.65)],
        rows: [
          ['Versión',          'v2.4.1'],
          ['Fecha',            'Junio 2026'],
          ['Autores',          'Equipo de Desarrollo UNUWARE'],
          ['Clasificación',    'CONFIDENCIAL — Uso Interno'],
          ['Cumplimiento',     'ENS Alto (RD 311/2022)'],
        ].map(([label, value], i) => new TableRow({
          children: [
            new TableCell({
              width: { size: Math.round(CONTENT * 0.35), type: WidthType.DXA },
              borders: cellBorder(),
              shading: { fill: NAVY, type: ShadingType.CLEAR },
              margins: { top: 80, bottom: 80, left: 140, right: 140 },
              children: [new Paragraph({ children: [new TextRun({ text: label, bold: true, color: WHITE, size: pt(9), font: 'Arial' })] })],
            }),
            new TableCell({
              width: { size: Math.round(CONTENT * 0.65), type: WidthType.DXA },
              borders: cellBorder(),
              shading: i % 2 === 0 ? { fill: LIGHT, type: ShadingType.CLEAR } : undefined,
              margins: { top: 80, bottom: 80, left: 140, right: 140 },
              children: [new Paragraph({ children: [new TextRun({ text: value, size: pt(9), font: 'Arial' })] })],
            }),
          ],
        })),
      }),
      spacer(),
      spacer(),
      // Bottom bar
      new Paragraph({
        border: { bottom: { style: BorderStyle.THICK, size: 12, color: NAVY, space: 0 } },
        spacing: { before: 800, after: 0 },
        children: [],
      }),
    ],
  };
}

// ─── TOC section ─────────────────────────────────────────────────
function makeTOCSection() {
  return {
    properties: {
      page: {
        size: { width: PAGE_W, height: PAGE_H },
        margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN },
      },
    },
    headers: makeHeader(),
    footers: makeFooter(),
    children: [
      new Paragraph({
        spacing: { before: 0, after: 400 },
        children: [new TextRun({ text: 'ÍNDICE DE CONTENIDOS', bold: true, size: pt(16), font: 'Arial', color: NAVY })],
      }),
      new TableOfContents('Tabla de Contenidos', { hyperlink: true, headingStyleRange: '1-2' }),
      new Paragraph({ children: [new PageBreak()] }),
    ],
  };
}

function makeHeader() {
  return {
    default: new Header({
      children: [new Paragraph({
        border: { bottom: { style: BorderStyle.SINGLE, size: 3, color: BORDER_COLOR, space: 1 } },
        spacing: { before: 0, after: 100 },
        children: [
          new TextRun({ text: 'ScanOPS — Documento de Arquitectura', size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ text: '\t\tv2.4.1 | CONFIDENCIAL', size: pt(8), font: 'Arial', color: SLATE }),
        ],
        tabStops: [{ type: 'right', position: 9506 }],
      })],
    }),
  };
}

function makeFooter() {
  return {
    default: new Footer({
      children: [new Paragraph({
        border: { top: { style: BorderStyle.SINGLE, size: 3, color: BORDER_COLOR, space: 1 } },
        spacing: { before: 100, after: 0 },
        children: [
          new TextRun({ text: 'UNUWARE | Plataforma ScanOPS', size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ text: '\tPágina ', size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ children: [PageNumber.CURRENT], size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ text: ' de ', size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ children: [PageNumber.TOTAL_PAGES], size: pt(8), font: 'Arial', color: SLATE }),
        ],
        tabStops: [{ type: 'right', position: 9506 }],
      })],
    }),
  };
}

// ─── Main body section ───────────────────────────────────────────
function makeBodySection() {
  const children = [];

  // ── 1. RESUMEN EJECUTIVO ────────────────────────────────────────
  children.push(h1('1. Resumen Ejecutivo'));
  children.push(body('ScanOPS es una plataforma de seguridad ofensiva y defensiva diseñada para automatizar el ciclo completo de operaciones de seguridad en organizaciones bajo el Esquema Nacional de Seguridad (ENS) categoría Alto. Integra descubrimiento de activos, reconocimiento, análisis de vulnerabilidades, razonamiento con inteligencia artificial, validación de exploits, monitorización SIEM y generación de reportes en un único sistema orquestado de ocho módulos especializados.'));
  children.push(spacer());
  children.push(body('La plataforma opera en ciclos semanales automatizados (Lunes–Domingo) con una fase de aprobación humana obligatoria antes de cualquier acción de explotación, garantizando el control de operador exigido por las medidas ENS Alto op.exp.2 y op.acc.5.'));
  children.push(spacer());
  children.push(body('Capacidades clave:', { bold: true }));
  [
    'Inventario continuo de activos y Shadow IT discovery (M1/M2)',
    'Escaneo de vulnerabilidades con Nikto, Nuclei, Nmap y análisis de comportamiento EDR (M3)',
    'Razonamiento IA sobre vectores de ataque con modelos Ollama / Qwen2.5:14b (M8)',
    'Validación de exploits SSH/HTTP/SQLi con aprobación TOTP obligatoria (M4)',
    'SIEM correlacionado con Suricata, Wazuh, Cowrie, Beelzebub, Graylog y MISP (M5)',
    'Generacion de reportes ejecutivos, tecnicos, SoA ENS y auditorias firmadas (M7)',
    'Kill switch de emergencia con autenticacion TOTP y trazabilidad completa',
  ].forEach(t => children.push(bullet(t)));

  // ── 2. GLOSARIO ─────────────────────────────────────────────────
  children.push(h1('2. Glosario y Acronimos'));
  children.push(twoColTable(['Termino', 'Definicion'], [
    ['ENS',          'Esquema Nacional de Seguridad (RD 311/2022)'],
    ['SOC',          'Security Operations Center'],
    ['SIEM',         'Security Information and Event Management'],
    ['EDR',          'Endpoint Detection and Response'],
    ['TOTP',         'Time-based One-Time Password (RFC 6238)'],
    ['CVE',          'Common Vulnerabilities and Exposures'],
    ['IOC',          'Indicator of Compromise'],
    ['MITRE ATT&CK', 'Framework de tacticas y tecnicas de ataque'],
    ['OSINT',        'Open Source Intelligence'],
    ['M0-M8',        'Modulos funcionales de ScanOPS (Orchestrator y M1-M8)'],
    ['Shadow IT',    'Infraestructura TI no registrada oficialmente'],
    ['JWT',          'JSON Web Token (RFC 7519)'],
    ['RBAC',         'Role-Based Access Control'],
    ['SSE',          'Server-Sent Events'],
    ['TLS',          'Transport Layer Security'],
  ], [Math.round(CONTENT * 0.25), Math.round(CONTENT * 0.75)]));

  // ── 3. VISION GENERAL ───────────────────────────────────────────
  children.push(h1('3. Vision General de la Arquitectura'));
  children.push(h2('3.1 Modelo de Capas'));
  children.push(body('ScanOPS se organiza en seis capas funcionales superpuestas que separan responsabilidades desde la presentacion hasta la inteligencia de amenazas:'));
  children.push(spacer());

  // Layers table
  const LCOLW = [Math.round(CONTENT * 0.28), Math.round(CONTENT * 0.72)];
  children.push(new Table({
    width: { size: CONTENT, type: WidthType.DXA },
    columnWidths: LCOLW,
    rows: [
      new TableRow({ children: [hCell('Capa', LCOLW[0]), hCell('Componentes', LCOLW[1])], tableHeader: true }),
      ...[
        ['Presentacion',          'React 18 SPA → Nginx Reverse Proxy (TLS 1.3) → Puerto 443'],
        ['Orquestacion (M0)',      'Orchestrator (8009): ciclo semanal, health checks, SSE log stream, kill switch, rate limiting'],
        ['Modulos FastAPI (M1-M8)', 'M1 Asset Manager (8001) | M2 Recon Engine (8003) | M3 Scanner (8002) | M4 Exploit (8004) | M5 SIEM (8006) | M7 Reporting (8007) | M8 AI (8005)'],
        ['Datos',                  'PostgreSQL 16 (operacional) | Redis 7 (cache/colas) | MongoDB 5.0 (Graylog) | OpenSearch 2.11 (indices SIEM) | HashiCorp Vault (secretos)'],
        ['Seguridad Perimetral',   'Suricata IDS (host) | Wazuh Manager 4.7.2 | CrowdSec | Cowrie SSH Honeypot (2222/2223) | Beelzebub HTTP (8880)'],
        ['Inteligencia',           'MISP Threat Intelligence | Graylog 5.2 | Trivy CVE Scanner | Web-Check OSINT'],
      ].map(([a, b], i) => new TableRow({
        children: [
          new TableCell({
            width: { size: LCOLW[0], type: WidthType.DXA },
            borders: cellBorder(),
            shading: { fill: i % 2 === 0 ? LIGHT : WHITE, type: ShadingType.CLEAR },
            margins: { top: 80, bottom: 80, left: 140, right: 140 },
            children: [new Paragraph({ children: [new TextRun({ text: a, bold: true, size: pt(9), font: 'Arial' })] })],
          }),
          new TableCell({
            width: { size: LCOLW[1], type: WidthType.DXA },
            borders: cellBorder(),
            shading: { fill: i % 2 === 0 ? LIGHT : WHITE, type: ShadingType.CLEAR },
            margins: { top: 80, bottom: 80, left: 140, right: 140 },
            children: [new Paragraph({ children: [new TextRun({ text: b, size: pt(9), font: 'Arial' })] })],
          }),
        ],
      })),
    ],
  }));
  children.push(spacer());
  children.push(h2('3.2 Principios de Diseno'));
  [
    'Modularidad: Cada modulo es un microservicio FastAPI independiente con su propio Dockerfile, healthcheck y esquema PostgreSQL separado.',
    'Ciclo semanal automatizado: La orquestacion sigue un calendario fijo (Lunes→Domingo) con transiciones automaticas de fase. La fase de explotacion requiere aprobacion humana explicita con TOTP.',
    'Defense in Depth: Multiples capas de seguridad perimetral (IDS, HIDS, honeypots, WAF, rate limiting) generan alertas correlacionadas en el SIEM.',
    'Trazabilidad completa (ENS op.acc.5 / op.exp.5): Todas las acciones destructivas (kill switch, aprobar exploit, ejecutar ataque) se registran con timestamp, IP de origen y operador.',
    'Separacion de redes: La red de honeypots (scanops_honeypot_net) esta aislada de la red principal (scanops) para evitar pivoting.',
  ].forEach(t => children.push(numItem(t)));

  // ── 4. STACK TECNOLOGICO ─────────────────────────────────────────
  children.push(h1('4. Stack Tecnologico'));
  children.push(h2('4.1 Frontend'));
  children.push(threeColTable(['Tecnologia', 'Version', 'Funcion'], [
    ['React', '18.3.1', 'Framework UI principal'],
    ['TypeScript', '6.0', 'Tipado estatico'],
    ['Vite', '6.3.5', 'Build tool y dev server'],
    ['Tailwind CSS', '4.1.12', 'Utility-first CSS'],
    ['shadcn/ui + Radix UI', 'latest', 'Componentes accesibles'],
    ['Recharts', '2.15.2', 'Graficas y sparklines KPI'],
    ['React Router', '7.13', 'Enrutamiento SPA'],
    ['Lucide React', '0.487', 'Iconografia'],
    ['Motion', '12.23', 'Animaciones'],
    ['Sonner', '2.0', 'Notificaciones toast'],
    ['OTPAuth', '9.5', 'Generacion TOTP cliente'],
  ], [Math.round(CONTENT * 0.28), Math.round(CONTENT * 0.18), Math.round(CONTENT * 0.54)]));
  children.push(spacer());
  children.push(h2('4.2 Backend'));
  children.push(threeColTable(['Tecnologia', 'Version', 'Funcion'], [
    ['Python', '3.11', 'Lenguaje principal de todos los modulos'],
    ['FastAPI', '0.104.1', 'Framework REST API (ASGI)'],
    ['Uvicorn', '0.24.0', 'ASGI server'],
    ['SQLAlchemy', '2.0+', 'ORM y gestion de esquemas'],
    ['Alembic', '1.12+', 'Migraciones de base de datos'],
    ['Pydantic', '2.0+', 'Validacion de datos'],
    ['Celery', '5.3+', 'Cola de tareas distribuidas'],
    ['python-jose', '3.3+', 'JWT HS256'],
    ['PyOTP / qrcode', '2.9 / 7.4', 'TOTP MFA'],
    ['httpx', '0.24+', 'HTTP client asincrono'],
    ['Paramiko', '3.1+', 'SSH client (M3 telemetria agentless)'],
    ['ReportLab', '4.4+', 'Generacion de PDFs (M7)'],
    ['Jinja2', '3.1+', 'Plantillas de reportes'],
  ], [Math.round(CONTENT * 0.28), Math.round(CONTENT * 0.18), Math.round(CONTENT * 0.54)]));
  children.push(spacer());
  children.push(h2('4.3 Infraestructura'));
  children.push(threeColTable(['Componente', 'Tecnologia', 'Funcion'], [
    ['Reverse Proxy', 'Nginx', 'TLS termination, routing, rate limiting, SPA serving'],
    ['Base de datos', 'PostgreSQL 16', 'Datos operacionales de todos los modulos'],
    ['Cache / Colas', 'Redis 7 Alpine', 'Session cache, Celery broker, kill switch state'],
    ['Gestor de secretos', 'HashiCorp Vault', 'Credenciales de activos, rotacion automatica'],
    ['Orquestacion', 'Docker Compose', 'Despliegue multi-contenedor (19 servicios)'],
    ['IDS/IPS', 'Suricata (host)', 'Deteccion de intrusiones en red'],
    ['HIDS', 'Wazuh Manager 4.7.2', 'Deteccion en endpoints'],
    ['Threat Intelligence', 'MISP', 'Feeds de IOCs y correlacion'],
    ['Log Management', 'Graylog 5.2 + OpenSearch', 'Centralizacion y busqueda de logs'],
    ['Honeypot SSH', 'Cowrie', 'Captura de ataques SSH/Telnet'],
    ['Honeypot HTTP', 'Beelzebub + Ollama', 'Honeypot LLM-driven'],
    ['IA / LLM', 'Ollama (qwen2.5:14b)', 'Razonamiento sobre vectores de ataque'],
    ['Bot de alertas', 'Telegram Bot API', 'Notificaciones criticas en tiempo real'],
  ]));

  // ── 5. MODULOS DEL SISTEMA ───────────────────────────────────────
  children.push(h1('5. Modulos del Sistema'));

  // M0
  children.push(h2('5.1 M0 — Orchestrator (Puerto 8009)'));
  children.push(body('Responsabilidad: Punto central de coordinacion. Gestiona el ciclo semanal, expone el estado de salud de todos los modulos, provee el stream SSE de logs en tiempo real, controla el kill switch de emergencia y aplica rate limiting.'));
  children.push(spacer());
  children.push(body('Funcionalidades principales:', { bold: true }));
  [
    'Estado del ciclo semanal en tiempo real (polling 30s desde el frontend)',
    'Health checks concurrentes de M1-M8 (timeout 2s por modulo)',
    'SSE endpoint /orchestrator/logs/stream para el Live Execution Log del Dashboard',
    'Kill switch con autenticacion TOTP y registro de auditoria (ENS op.acc.5)',
    'Pausa/reanudacion del ciclo con IP de origen registrada',
    'Metricas del dashboard agregadas desde M1 y M3',
    'Gestion de usuarios activos y sesiones',
    'Rate limiting: 120 req/min general, 10 req/min en endpoints de autenticacion',
  ].forEach(t => children.push(bullet(t)));
  children.push(spacer());
  children.push(body('Middleware stack: RateLimitMiddleware → CORSMiddleware → AuthRouter → UserRouter', { italics: true }));

  // M1
  children.push(h2('5.2 M1 — Asset Manager (Puerto 8001)'));
  children.push(body('Responsabilidad: Registro canonico (CMDB) de todos los activos de la organizacion. Soporta descubrimiento de Shadow IT, integracion con HashiCorp Vault para credenciales y audit trail inmutable.'));
  children.push(spacer());
  children.push(body('Funcionalidades principales:', { bold: true }));
  [
    'CRUD completo de activos (SERVER, ENDPOINT, RED, APLICACION, IOT)',
    'Descubrimiento de Shadow IT via Nmap (rangos CIDR configurables)',
    'Metadatos ENS por activo (ID ENS, criticidad, responsable, dominio, ubicacion)',
    'Integracion con HashiCorp Vault para referencias de credenciales SSH',
    'Audit log inmutable por activo (CREATE/UPDATE/DELETE/RESTORE/CREDENTIAL_ACCESS)',
    'Gestion de blacklist de IPs descubiertas',
  ].forEach(t => children.push(bullet(t)));
  children.push(spacer());
  children.push(body('Entidades principales: Asset, AssetAuditLog, ShadowITHost, VaultCredential', { italics: true }));
  children.push(body('Fase del ciclo: Fase 1 — Lunes 02:00 (Asset Discovery)', { italics: true }));

  // M2
  children.push(h2('5.3 M2 — Recon Engine (Puerto 8003)'));
  children.push(body('Responsabilidad: Reconocimiento pasivo y activo de la superficie de ataque de cada activo registrado.'));
  children.push(spacer());
  [
    'Banner grabbing (servicios y versiones)',
    'DNS/WHOIS lookup y analisis de dominios',
    'Analisis de hardening de configuracion de red',
    'Virtual host fuzzing (descubrimiento de vhosts)',
    'Surface diff: comparacion con snapshot anterior para detectar cambios',
    'Integracion con OSINT (Web-Check)',
  ].forEach(t => children.push(bullet(t)));
  children.push(body('Fase del ciclo: Fase 1 — Lunes 02:00 (junto con M1)', { italics: true }));

  // M3
  children.push(h2('5.4 M3 — Scanner Engine / EDR (Puerto 8002)'));
  children.push(body('Responsabilidad: Analisis de vulnerabilidades tecnicas sobre activos y deteccion de comportamiento anomalo mediante capacidades EDR agentless.'));
  children.push(spacer());
  [
    'Escaneo con Nikto (web), Nuclei (plantillas CVE), Nmap (puertos/servicios)',
    'Integracion con OpenVAS para analisis de vulnerabilidades autenticado',
    'TestSSL para auditoria TLS/SSL y WhatWeb para fingerprinting',
    'FFUF para fuzzing de directorios, CORS checker y JS source analyzer',
    'Analisis YARA sobre archivos sospechosos',
    'Threat intelligence lookup (VirusTotal, MISP)',
    'Telemetria agentless SSH: recopilacion de logs de sistema sin agente instalado',
    'Analisis de comportamiento EDR: deteccion de anomalias (brute force, privilege escalation)',
    'MITRE ATT&CK mapping automatico de hallazgos',
    'Integracion con ZAP (DAST) para aplicaciones web',
  ].forEach(t => children.push(bullet(t)));
  children.push(body('Fase del ciclo: Fase 2 — Martes 00:00 (Vulnerability Scanning)', { italics: true }));

  // M4
  children.push(h2('5.5 M4 — Exploit Engine (Puerto 8004)'));
  children.push(body('Responsabilidad: Validacion controlada de vulnerabilidades mediante ataques reales sobre activos pre-autorizados, con doble factor de autenticacion obligatorio antes de cualquier ejecucion.'));
  children.push(spacer());
  [
    'Fuerza bruta SSH/FTP/HTTP con Hydra (wordlists configurables)',
    'Enumeracion de directorios y subdominios con Gobuster',
    'SQL Injection testing con SQLMap',
    'Network exploitation con NetExec (NXC)',
    'Sistema de aprobacion TOTP+PIN en dos pasos (request-approval → approve → execute)',
    'Cola de aprobaciones pendientes con expiracion automatica',
    'Kill switch de emergencia integrado con Redis (cancela ejecuciones en curso)',
    'Audit log estructurado para cada accion (APPROVAL_REQUESTED, APPROVAL_GRANTED/DENIED, EXPLOIT_EXECUTE_LAUNCHED)',
    'Notificacion Telegram en tiempo real al explotar credenciales',
  ].forEach(t => children.push(bullet(t)));
  children.push(spacer());
  children.push(infoBox([
    'NOTA DE SEGURIDAD (ENS Alto op.exp.2):',
    'Ningun ataque puede ejecutarse sin que un operador autorizado haya validado el codigo TOTP en tiempo real.',
    'El secreto TOTP se genera por solicitud y no es reutilizable.',
  ]));
  children.push(body('Fase del ciclo: Fase 4 — Sabado 01:00 (Exploit Validation)', { italics: true }));

  // M5
  children.push(h2('5.6 M5 — SIEM Engine (Puerto 8006)'));
  children.push(body('Responsabilidad: Correlacion y enriquecimiento de eventos de seguridad provenientes de multiples fuentes con capacidades de threat intelligence.'));
  children.push(spacer());
  children.push(body('Fuentes de datos integradas:', { bold: true }));
  ['Suricata IDS: alertas de red (eve.json)', 'Wazuh Manager: eventos de endpoints (HIDS)', 'Cowrie SSH Honeypot: sesiones e intentos de intrusion', 'Beelzebub HTTP Honeypot: interacciones web maliciosas', 'M4 Pipeline: eventos de explotacion interna', 'Graylog: logs centralizados de todos los contenedores'].forEach(t => children.push(bullet(t)));
  children.push(spacer());
  children.push(body('Funcionalidades:', { bold: true }));
  ['Pipeline de eventos en tiempo real (polling 5s en el frontend)', 'Correlacion de IP atacante entre fuentes', 'Deteccion de ataques de fuerza bruta (>= 5 fallos misma IP)', 'Integracion MISP: enriquecimiento de IOCs y lookup de reputacion', 'Bloqueo activo con CrowdSec', 'KPIs: ataques bloqueados Suricata, fallos Wazuh, interacciones honeypot, sensores online'].forEach(t => children.push(bullet(t)));
  children.push(body('Fase del ciclo: Permanente (monitorizacion continua)', { italics: true }));

  // M7
  children.push(h2('5.7 M7 — Reporting Engine (Puerto 8007)'));
  children.push(body('Responsabilidad: Generacion automatizada de reportes tecnicos, ejecutivos y de cumplimiento ENS en formato PDF con cadena de evidencias.'));
  children.push(spacer());
  children.push(twoColTable(['Tipo de Reporte', 'Contenido'], [
    ['Reporte Ejecutivo', 'Metricas globales, ENS score, ROI de seguridad, top vulnerabilidades'],
    ['Reporte Tecnico', 'Evidencias completas M1+M2+M3+M4, plan de remediacion priorizado'],
    ['Declaracion de Aplicabilidad (SoA)', '73 medidas ENS Alto (RD 311/2022), estado de implantacion'],
    ['Auditoria Completa (ZIP)', 'Paquete con 4 PDFs firmados + evidencias tecnicas'],
    ['Reporte por activo', 'Analisis individual con datos de M1, M2, M3, M8, M4 y M5'],
  ]));
  children.push(body('Fase del ciclo: Fase 5 — Domingo 08:00 (Reporting)', { italics: true }));

  // M8
  children.push(h2('5.8 M8 — AI Reasoning (Puerto 8005)'));
  children.push(body('Responsabilidad: Razonamiento autonomo sobre vectores de ataque y priorizacion de vulnerabilidades utilizando LLMs locales (Ollama qwen2.5:14b).'));
  children.push(spacer());
  [
    'Analisis de vectores de ataque sobre hallazgos de M3 (Attack Vector API)',
    'Kill chain detection: mapeo automatico a MITRE ATT&CK kill chain',
    'False positive filter: reduce falsos positivos de escaneres',
    'RAG Engine: recuperacion de informacion de base de conocimientos local',
    'Prioritizer: ranking de vulnerabilidades por impacto real (EPSS + contexto)',
    'Post-exploit agent: analisis de resultados M4 con recomendaciones',
    'Validacion humana: interfaz para que el operador revise razonamientos antes de la Fase 3',
    'Generacion de secciones de reporte con lenguaje natural',
  ].forEach(t => children.push(bullet(t)));
  children.push(spacer());
  children.push(body('Modelo LLM: Ollama qwen2.5:14b ejecutado en host, accedido via host.docker.internal:11434', { italics: true }));
  children.push(body('Fase del ciclo: Fase 2 (analisis) y Fase 3 (gate de aprobacion humana)', { italics: true }));

  // ── 6. FLUJO DE DATOS Y CICLO OPERATIVO ─────────────────────────
  children.push(h1('6. Flujo de Datos y Ciclo Operativo'));
  children.push(h2('6.1 Ciclo Semanal Automatizado'));
  const W_FASE = [1400, 1600, 1600, 2806, 1800];
  children.push(fiveColTable(
    ['Fase', 'Dia / Hora', 'Modulos', 'Descripcion', 'Aprobacion Humana'],
    [
      ['Fase 1', 'Lunes 02:00',    'M1, M2', 'Asset Discovery y Reconocimiento',                         'No'],
      ['Fase 2', 'Martes 00:00',   'M3, M8', 'Vulnerability Scanning y Analisis IA',                    'No'],
      ['Fase 3', 'Jueves 09:00',   'M8',     'Human Approval Gate: revision de vectores IA',             'SI (obligatorio)'],
      ['Fase 4', 'Sabado 01:00',   'M4',     'Exploit Validation (requiere aprobacion TOTP de Fase 3)',  'SI (TOTP+PIN)'],
      ['Fase 5', 'Domingo 08:00',  'M7',     'Generacion de Reportes y cadena de evidencias',            'No'],
      ['Idle',   'Viernes',        '—',      'Sin operaciones activas',                                  '—'],
    ],
    W_FASE
  ));

  children.push(spacer());
  children.push(h2('6.2 Flujo de una Vulnerabilidad Critica (End-to-End)'));
  [
    'M1 registra activo 10.202.15.10 en la CMDB con criticidad ALTA',
    'M2 realiza reconocimiento: banner grabbing, DNS, surface snapshot',
    'M3 ejecuta Nuclei + Nikto: detecta CVE-2024-XXXX (CVSS 9.8)',
    'M8 analiza el vector de ataque con qwen2.5:14b: confirma explotabilidad real',
    'El operador revisa el razonamiento IA en /ai-reasoning (Fase 3 gate)',
    'El operador crea solicitud en M4: POST /api/m4/request-approval con {cve, ip, user_email, pin}',
    'M4 genera secreto TOTP y QR; el operador configura su autenticador',
    'El operador valida en tiempo real: POST /api/m4/approve con {approval_id, totp_code, pin}',
    'Audit log registra: APPROVAL_GRANTED ip=X approval_id=42',
    'El operador ejecuta: POST /api/m4/execute/42',
    'Hydra lanza fuerza bruta SSH en background; M4 actualiza estado en PostgreSQL',
    'Si exito: Telegram notifica credenciales; M5 recibe evento SIEM tipo EXPLOIT_EXECUTED',
    'M7 incluye evidencia en el Reporte Tecnico del domingo',
  ].forEach(t => children.push(numItem(t)));

  children.push(spacer());
  children.push(h2('6.3 Flujo de Alerta en Tiempo Real'));
  [
    'Kali Linux lanza nmap -sS contra 10.202.15.0/24',
    'Suricata (network_mode: host) detecta ET SCAN Nmap y escribe en eve.json',
    'M5 lee eve.json y publica evento con severidad HIGH via pipeline',
    'Frontend (AlertsPage) muestra alerta en tiempo real (polling 5s)',
    'useCriticalAlerts hook detecta severidad CRITICAL y genera toast de notificacion',
    'M5 consulta MISP: enriquece IP atacante con reputacion conocida',
    'CrowdSec agrega IP a lista de bloqueo automaticamente',
  ].forEach(t => children.push(numItem(t)));

  // ── 7. ARQUITECTURA DE SEGURIDAD ─────────────────────────────────
  children.push(h1('7. Arquitectura de Seguridad'));
  children.push(h2('7.1 Autenticacion y Autorizacion'));
  children.push(h3('JWT Bearer Tokens'));
  children.push(twoColTable(['Parametro', 'Valor'], [
    ['Algoritmo', 'HS256'],
    ['Expiracion access token', '8 horas'],
    ['Expiracion refresh token', '7 dias'],
    ['Almacenamiento cliente', 'sessionStorage (no localStorage)'],
    ['Validacion', 'En cada peticion a modulos protegidos'],
  ], [Math.round(CONTENT * 0.38), Math.round(CONTENT * 0.62)]));
  children.push(spacer());
  children.push(h3('Roles RBAC (4 niveles)'));
  children.push(threeColTable(['Rol', 'Descripcion', 'Permisos clave'], [
    ['system_manager', 'Administrador del sistema', 'Acceso completo. Kill switch, gestion de usuarios, configuracion'],
    ['security_officer', 'Responsable de Seguridad', 'Scanner, EDR, Alertas, Explotacion, Bastionado'],
    ['auditor', 'Auditor', 'Solo lectura. Assets, Logs de Auditoria, Cumplimiento, Reportes'],
    ['service', 'Cuenta de servicio', 'API programatica entre modulos'],
  ]));
  children.push(spacer());
  children.push(h3('MFA TOTP para acciones destructivas (M4)'));
  ['RFC 6238 (TOTP, intervalo 30s, HMAC-SHA1)', 'Secreto generado por solicitud de aprobacion — no reutilizable', 'QR code entregado al operador para configuracion en autenticador', 'Validacion server-side en el momento de aprobacion'].forEach(t => children.push(bullet(t)));

  children.push(h2('7.2 Seguridad en Transporte'));
  ['TLS 1.2 / TLS 1.3 en el reverse proxy Nginx', 'Certificados mkcert en desarrollo (localhost+2.pem)', 'HSTS: max-age=31536000, X-Frame-Options: SAMEORIGIN, X-Content-Type-Options: nosniff, Referrer-Policy'].forEach(t => children.push(bullet(t)));

  children.push(h2('7.3 Rate Limiting (dos capas)'));
  children.push(h3('Capa Nginx'));
  children.push(threeColTable(['Zona', 'Limite', 'Endpoints'], [
    ['general', '10 req/s', 'Frontend / SPA'],
    ['api', '30 req/s', 'Todos los /api/*'],
    ['upload', '5 req/min', '/api/(m1|m4)/upload'],
  ]));
  children.push(spacer());
  children.push(h3('Capa Orchestrator (ENS op.acc.6)'));
  children.push(threeColTable(['Tipo', 'Limite', 'Endpoints'], [
    ['General', '120 req/min por IP', 'Todos los endpoints'],
    ['Autenticacion', '10 req/min por IP', '/auth/token, /auth/login'],
  ]));

  children.push(h2('7.4 Audit Trail (ENS op.exp.5 / op.acc.5)'));
  children.push(threeColTable(['Evento', 'Modulo', 'Datos registrados'], [
    ['Asset CRUD', 'M1', 'accion, usuario, IP, timestamp, antes/despues (JSON)'],
    ['Login success/failure', 'Orchestrator', 'usuario, rol, IP, user-agent, razon del fallo'],
    ['Ciclo pause/resume', 'Orchestrator', 'estado nuevo, IP del operador'],
    ['Kill switch ON/OFF', 'Orchestrator', 'estado, IP del operador, timestamp'],
    ['Approval requested', 'M4', 'approval_id, CVE, IP objetivo, solicitante'],
    ['Approval granted/denied', 'M4', 'approval_id, razon, IP del operador'],
    ['Exploit launched', 'M4', 'approval_id, CVE, IP objetivo, IP del operador'],
    ['Manual attack', 'M4', 'tipo de ataque, IP objetivo, operador, resultado'],
  ]));

  children.push(h2('7.5 Aislamiento de Red'));
  children.push(twoColTable(['Red Docker', 'Contenidos'], [
    ['scanops (principal)', 'M1-M8, Orchestrator, PostgreSQL, Redis, Wazuh, Graylog, OpenSearch, Vault'],
    ['scanops_honeypot_net (aislada)', 'Solo Cowrie y Beelzebub. Sin acceso a la red principal. Previene pivoting.'],
  ]));
  children.push(spacer());
  children.push(body('Suricata opera en network_mode: host para captura real de trafico perimetral, fuera de ambas redes Docker.', { italics: true }));

  // ── 8. ARQUITECTURA DEL FRONTEND ────────────────────────────────
  children.push(h1('8. Arquitectura del Frontend'));
  children.push(h2('8.1 Estructura de Carpetas'));
  children.push(codeBlock([
    'frontend/src/',
    '  app/',
    '    components/          Paginas y componentes principales',
    '      ui/                shadcn/ui components + SeverityBadge',
    '      DashboardPage.tsx',
    '      AlertsPage.tsx',
    '      AssetManagerPage.tsx',
    '      AssetDetailPage.tsx',
    '      ExploitationPage.tsx',
    '      EDRDashboardPage.tsx',
    '      AIReasoningPage.tsx',
    '      ReportingPage.tsx',
    '      ... (16 paginas total)',
    '    utils/               Helpers (cycleState, etc.)',
    '    App.tsx              Router principal',
    '  config/',
    '    api.ts               Registro centralizado de endpoints M1-M8',
    '  hooks/                 Custom hooks',
    '    useCriticalAlerts.ts Polling de alertas criticas (SIEM + auth)',
    '    useDashboardMetrics.ts',
    '    useLogStream.ts      SSE consumer para live logs',
    '    useCycleStatus.ts',
    '    useAssets.ts',
    '  pages/',
    '    UnifiedScanner/      Scanner page (JSX legacy)',
    '    BastionadoPage.tsx',
    '  styles/',
    '    theme.css            CSS variables - paleta enterprise purple',
  ]));

  children.push(h2('8.2 Gestion de Estado y Datos'));
  children.push(twoColTable(['Mecanismo', 'Uso'], [
    ['Estado local (useState)', 'Datos de pagina, filtros, formularios'],
    ['Polling 60s (useDashboardMetrics)', 'Metricas del dashboard agregadas'],
    ['Polling 30s (useCycleStatus)', 'Estado del ciclo semanal'],
    ['Polling 60s (useCriticalAlerts)', 'Alertas criticas de SIEM y auth events'],
    ['SSE (useLogStream)', 'Live Execution Log en tiempo real desde Orchestrator'],
    ['Auth context (useAuth)', 'JWT en sessionStorage, logout automatico'],
    ['RouteErrorBoundary', 'Error boundary en todas las 13 rutas protegidas'],
  ]));

  children.push(h2('8.3 Diseno Visual'));
  children.push(twoColTable(['Elemento', 'Valor'], [
    ['Fondo principal', '#0A0C10 (deep near-black)'],
    ['Color primario', '#8B5CF6 (purple)'],
    ['Acento', '#06B6D4 (cyan)'],
    ['Estilo', 'Enterprise dark theme inspirado en SentinelOne Singularity'],
    ['Componentes clave', 'SeverityBadge (filled circle + label), KPI cards con sparklines Recharts, skeleton loaders animate-pulse'],
    ['Navegacion', 'Sidebar colapsable con 3 secciones + indicadores de salud de modulos'],
  ]));

  children.push(h2('8.4 Routing y Proteccion'));
  children.push(threeColTable(['Ruta', 'Pagina', 'Roles requeridos'], [
    ['/dashboard', 'DashboardPage', 'Autenticado'],
    ['/assets', 'AssetManagerPage', 'Autenticado'],
    ['/assets/:id', 'AssetDetailPage', 'system_manager, auditor'],
    ['/surface', 'UnifiedScannerLayout', 'Autenticado'],
    ['/edr', 'EDRDashboardPage', 'system_manager, security_officer'],
    ['/incident-response', 'IncidentResponsePage', 'system_manager, security_officer'],
    ['/ai-reasoning', 'AIReasoningPage', 'Autenticado'],
    ['/exploitation', 'ExploitationPage', 'system_manager, security_officer'],
    ['/alerts', 'AlertsPage', 'system_manager, security_officer'],
    ['/bastionado', 'BastionadoPage', 'system_manager, security_officer'],
    ['/reporting', 'ReportingPage', 'system_manager, auditor'],
    ['/compliance', 'CompliancePage', 'system_manager, auditor'],
    ['/audit-logs', 'AuditLogsPage', 'system_manager, auditor'],
    ['/settings', 'SettingsPage', 'system_manager, security_officer'],
  ]));

  // ── 9. ARQUITECTURA DE DATOS ────────────────────────────────────
  children.push(h1('9. Arquitectura de Datos'));
  children.push(h2('9.1 PostgreSQL — Esquemas por Modulo'));
  children.push(twoColTable(['Modulo', 'Tablas principales'], [
    ['M1 Asset Manager', 'assets, asset_audit_logs, shadow_it_hosts, vault_credentials'],
    ['M3 Scanner', 'scan_results, vulnerabilities, behavioral_findings, edr_events'],
    ['M4 Exploit', 'm4_approvals, exploit_results, cancel_tokens'],
    ['M5 SIEM', 'pipeline_events, honeypot_sessions, auth_events, wazuh_alerts'],
    ['M7 Reporting', 'report_history'],
    ['M8 AI', 'attack_vectors, ai_analysis_results, rag_documents'],
    ['Shared Auth', 'users (sincronizados en memoria al arrancar)'],
  ]));

  children.push(h2('9.2 Redis — Uso por Modulo'));
  children.push(threeColTable(['Uso', 'TTL', 'Descripcion'], [
    ['Kill switch state', 'Sin expiracion', 'Flag global accesible por todos los modulos'],
    ['Celery broker', '—', 'Cola de tareas: discovery, vulnerabilities, heavy_scans, scanner_tasks, ai_reasoning, exploitation, reporting'],
    ['Session cache', '8h', 'Token JWT server-side para invalidacion anticipada'],
    ['Rate limit buckets', '60s', 'Sliding window en Orchestrator'],
  ]));

  children.push(h2('9.3 Celery — Colas de Tareas'));
  children.push(threeColTable(['Cola', 'Modulo consumidor', 'Tipos de tarea'], [
    ['discovery', 'M2', 'Reconocimiento de activos, surface scans'],
    ['vulnerabilities', 'M3', 'Escaneos Nikto, Nuclei, analisis de CVEs'],
    ['heavy_scans', 'M3', 'OpenVAS, ZAP DAST (larga duracion)'],
    ['scanner_tasks', 'M3', 'Tareas EDR, behavioral analysis'],
    ['scanner_orchestrator', 'M3', 'Coordinacion de escaneos en paralelo'],
    ['ai_reasoning', 'M8', 'Analisis LLM de vectores de ataque'],
    ['exploitation', 'M4', 'Ataques en background (Hydra, SQLMap)'],
    ['reporting', 'M7', 'Generacion asincrona de PDFs'],
  ]));

  // ── 10. DESPLIEGUE E INFRAESTRUCTURA ─────────────────────────────
  children.push(h1('10. Despliegue e Infraestructura'));
  children.push(h2('10.1 Requisitos de Hardware'));
  children.push(threeColTable(['Componente', 'Minimo', 'Recomendado'], [
    ['CPU', '8 cores', '16 cores'],
    ['RAM', '16 GB', '32 GB (+10 GB si Ollama en CPU)'],
    ['Almacenamiento', '100 GB SSD', '500 GB SSD NVMe'],
    ['Red', '1 Gbps', '10 Gbps'],
    ['GPU (opcional)', '-', 'NVIDIA 8 GB VRAM para aceleracion Ollama'],
  ]));

  children.push(h2('10.2 Comandos de Despliegue'));
  children.push(body('Arranque completo:', { bold: true }));
  children.push(codeBlock([
    '# Servicios core (Orchestrator, M1-M8, PostgreSQL, Redis, Vault)',
    'docker compose -f docker-compose.yml up -d',
    '',
    '# Servicios SIEM adicionales (Suricata, Cowrie, Beelzebub, MISP)',
    'docker compose -f docker-compose.siem.yml up -d',
    '',
    '# Rebuild del frontend',
    'docker compose -f docker-compose.yml build frontend',
    'docker compose -f docker-compose.yml up -d frontend',
    '',
    '# Verificar estado de modulos',
    'docker compose ps',
    'curl http://localhost:8009/orchestrator/modules/health',
  ]));

  children.push(h2('10.3 Variables de Entorno Criticas'));
  children.push(threeColTable(['Variable', 'Descripcion', 'Default (no produccion)'], [
    ['JWT_SECRET_KEY', 'Clave de firma JWT', 'CHANGE_ME_IN_PRODUCTION'],
    ['DATABASE_URL', 'Conexion PostgreSQL', 'postgresql://scanops:scanops@postgres:5432/scanops'],
    ['REDIS_URL', 'Conexion Redis', 'redis://scanops-main-redis:6379/0'],
    ['TELEGRAM_BOT_TOKEN', 'Bot de alertas', '(vacio — deshabilita alertas Telegram)'],
    ['OLLAMA_BASE_URL', 'URL del servidor LLM', 'http://host.docker.internal:11434'],
    ['VAULT_ADDR', 'HashiCorp Vault URL', 'http://vault:8200'],
    ['M1_URL / M2_URL / ...', 'URLs inter-modulo', 'http://m1:8001, http://m2:8003, ...'],
  ]));

  children.push(h2('10.4 Puertos Expuestos'));
  children.push(threeColTable(['Puerto', 'Servicio', 'Acceso'], [
    ['80 / 443', 'Nginx — Frontend React (HTTPS redirect)', 'Publico'],
    ['2222 / 2223', 'Cowrie SSH/Telnet Honeypot', 'Publico (intencionalmente expuesto)'],
    ['8880', 'Beelzebub HTTP Honeypot', 'Publico'],
    ['9000', 'Graylog Web UI', 'Interno'],
    ['3000', 'Web-Check OSINT', 'Interno'],
    ['8090', 'Trivy Server', 'Interno'],
    ['55000', 'Wazuh Manager API', 'Interno'],
    ['6379', 'Redis (sin exposicion externa)', 'Red Docker unicamente'],
    ['5432', 'PostgreSQL (sin exposicion externa)', 'Red Docker unicamente'],
  ]));

  // ── 11. MONITORIZACION Y OBSERVABILIDAD ──────────────────────────
  children.push(h1('11. Monitorizacion y Observabilidad'));
  children.push(h2('11.1 Health Checks'));
  children.push(body('Cada modulo FastAPI expone GET /health devolviendo JSON con estado y timestamp. El Orchestrator realiza polling concurrente cada 30 segundos con timeout de 2s por modulo y expone el resultado agregado en /orchestrator/modules/health. El Sidebar del frontend muestra indicadores de color (verde/rojo) por modulo en tiempo real.'));

  children.push(h2('11.2 Logs en Tiempo Real'));
  children.push(body('El Dashboard incluye un Live Execution Log conectado via SSE al endpoint /orchestrator/logs/stream. Los logs muestran todas las acciones del ciclo con color coding por nivel (INFO/SUCCESS/WARN/ERROR) y auto-scroll.'));

  children.push(h2('11.3 Stack de Observabilidad'));
  children.push(threeColTable(['Herramienta', 'Funcion', 'Puerto'], [
    ['Graylog 5.2', 'Centralizacion y busqueda de logs de todos los contenedores', '9000'],
    ['OpenSearch 2.11', 'Backend de indices para Graylog', 'Interno'],
    ['Wazuh Manager', 'HIDS — eventos de seguridad de endpoints', '55000 API'],
    ['Suricata eve.json', 'IDS — alertas de red en tiempo real', '/var/log/suricata/'],
    ['CrowdSec', 'Deteccion colaborativa y bloqueo de IPs maliciosas', 'Interno'],
  ]));

  // ── 12. CUMPLIMIENTO ENS ALTO ────────────────────────────────────
  children.push(h1('12. Cumplimiento ENS Alto'));
  children.push(h2('12.1 Controles Implementados'));
  children.push(threeColTable(['Medida ENS', 'Descripcion', 'Implementacion en ScanOPS'], [
    ['op.exp.2', 'Control de acceso privilegiado', 'Aprobacion TOTP+PIN obligatoria en M4 antes de cualquier ataque'],
    ['op.exp.3', 'Gestion de vulnerabilidades', 'Ciclo semanal automatizado M1→M8 con evidencias trazables'],
    ['op.exp.4', 'Gestion de configuracion', 'M3 Scanner hardening checks + BastionadoPage'],
    ['op.exp.5', 'Registro de auditoria', 'Audit log inmutable en M1; structured logging M4; kill switch log'],
    ['op.acc.4', 'Control de acceso RBAC', '4 roles con permisos granulares por ruta y endpoint'],
    ['op.acc.5', 'Autenticacion fuerte', 'JWT HS256 8h + TOTP para operaciones criticas'],
    ['op.acc.6', 'Limitacion de intentos', 'Rate limiting 10 req/min auth; CrowdSec bloqueo automatico'],
    ['op.mon.3', 'Monitorizacion continua', 'SIEM M5 + Suricata + Wazuh + honeypots en tiempo real'],
    ['mp.info.3', 'Gestion de secretos', 'HashiCorp Vault para credenciales de activos'],
    ['op.ext.1', 'Gestion de proveedores', 'MISP threat intelligence feeds integrados'],
  ]));

  // ── 13. ADR ──────────────────────────────────────────────────────
  children.push(h1('13. Decisiones de Arquitectura (ADR)'));

  const adrs = [
    {
      id: 'ADR-001', title: 'Microservicios vs Monolito',
      decision: 'Arquitectura de microservicios (M1-M8 + Orchestrator)',
      rationale: 'Permite escalar modulos computacionalmente intensivos (M3, M4) independientemente; facilita actualizacion de herramientas de seguridad sin afectar al resto; aisla fallos (un modulo offline no detiene el sistema).',
    },
    {
      id: 'ADR-002', title: 'FastAPI vs Django/Flask',
      decision: 'FastAPI para todos los modulos backend',
      rationale: 'Rendimiento asincrono nativo (ASGI), auto-documentacion OpenAPI, validacion Pydantic, ideal para APIs internas entre modulos.',
    },
    {
      id: 'ADR-003', title: 'LLM Local vs API Cloud',
      decision: 'Ollama con qwen2.5:14b ejecutado en host',
      rationale: 'Los datos de vulnerabilidades son altamente sensibles; enviarlos a una API cloud violaria los requisitos de confidencialidad ENS; la inferencia local garantiza air-gap de datos.',
    },
    {
      id: 'ADR-004', title: 'Polling vs WebSocket para el frontend',
      decision: 'SSE para log stream (unidireccional), polling periodico para metricas',
      rationale: 'SSE es mas simple que WebSocket para flujos unidireccionales servidor→cliente; no requiere negociacion bidireccional; reconexion automatica del navegador.',
    },
    {
      id: 'ADR-005', title: 'Honeypots aislados en red propia',
      decision: 'Red scanops_honeypot_net separada de la red scanops',
      rationale: 'Si un atacante compromete el honeypot, no puede pivotar a la infraestructura interna; cumple el principio de aislamiento de componentes de riesgo.',
    },
  ];

  adrs.forEach(adr => {
    children.push(h2(`${adr.id}: ${adr.title}`));
    children.push(labelValue('Decision', adr.decision));
    children.push(labelValue('Razon', adr.rationale));
    children.push(spacer());
  });

  // ── 14. LIMITACIONES Y TRABAJO FUTURO ────────────────────────────
  children.push(h1('14. Limitaciones Conocidas y Trabajo Futuro'));
  children.push(h2('14.1 Limitaciones Actuales'));
  [
    'El sistema de login events del Orchestrator usa un deque en memoria (maxlen=500); los eventos se pierden al reiniciar el contenedor. Pendiente: persistir en PostgreSQL (tabla auth_audit_log).',
    'Los modelos Ollama requieren hardware dedicado; en maquinas sin GPU la inferencia puede superar 2 minutos por analisis.',
    'La configuracion multi-host (migracion a 10.202.15.100) esta pendiente de validacion en servidor dedicado.',
    'Cowrie y Suricata requieren verificacion funcional con trafico real desde entorno Kali.',
    'El bundle JavaScript frontend (~1.3 MB) supera la recomendacion de 500 KB; pendiente code splitting con React.lazy().',
  ].forEach(t => children.push(numItem(t)));

  children.push(h2('14.2 Mejoras Planificadas'));
  [
    'Migracion a servidor dedicado 10.202.15.100 con configuracion de produccion y certificados TLS validos.',
    'Code splitting del frontend con React.lazy() para reducir bundle size y mejorar tiempo de carga inicial.',
    'Persistencia de login events en PostgreSQL para cumplimiento ENS op.mon.3.',
    'Dashboard de cumplimiento ENS con progreso por medida y evidencias linkadas.',
    'Integracion con fuentes OSINT adicionales (Shodan, Censys, VirusTotal Enterprise).',
    'Soporte para escaneos programados por activo independientes del ciclo semanal.',
  ].forEach(t => children.push(numItem(t)));

  // ── APENDICE A ────────────────────────────────────────────────────
  children.push(h1('Apendice A — Referencias'));
  children.push(twoColTable(['Referencia', 'Fuente'], [
    ['ENS Alto RD 311/2022', 'Real Decreto 311/2022 — Esquema Nacional de Seguridad (BOE)'],
    ['MITRE ATT&CK v14', 'https://attack.mitre.org/'],
    ['OWASP Top 10 2023', 'https://owasp.org/Top10/'],
    ['FastAPI Documentation', 'https://fastapi.tiangolo.com/'],
    ['Docker Compose Spec', 'https://docs.docker.com/compose/'],
    ['Suricata Documentation', 'https://docs.suricata.io/'],
    ['Wazuh Documentation', 'https://documentation.wazuh.com/'],
    ['MISP Project', 'https://www.misp-project.org/'],
    ['Ollama Documentation', 'https://ollama.com/'],
    ['HashiCorp Vault', 'https://developer.hashicorp.com/vault/docs'],
  ]));

  return {
    properties: {
      page: {
        size: { width: PAGE_W, height: PAGE_H },
        margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN },
      },
    },
    headers: makeHeader(),
    footers: makeFooter(),
    children,
  };
}

// ─── Build & write document ──────────────────────────────────────
async function main() {
  const doc = new Document({
    numbering: {
      config: [
        {
          reference: 'bullets',
          levels: [{
            level: 0, format: LevelFormat.BULLET, text: '•',
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 560, hanging: 280 } } },
          }],
        },
        {
          reference: 'numbers',
          levels: [{
            level: 0, format: LevelFormat.DECIMAL, text: '%1.',
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 560, hanging: 280 } } },
          }],
        },
      ],
    },
    styles: {
      default: {
        document: { run: { font: 'Arial', size: pt(10) } },
      },
      paragraphStyles: [
        {
          id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: pt(16), bold: true, font: 'Arial', color: NAVY },
          paragraph: { spacing: { before: 480, after: 240 }, outlineLevel: 0 },
        },
        {
          id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: pt(12), bold: true, font: 'Arial', color: BLUE },
          paragraph: { spacing: { before: 320, after: 160 }, outlineLevel: 1 },
        },
        {
          id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: pt(10), bold: true, font: 'Arial', color: SLATE },
          paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 2 },
        },
      ],
    },
    settings: {
      updateFields: true,
    },
    sections: [
      makeCoverSection(),
      makeTOCSection(),
      makeBodySection(),
    ],
  });

  const buffer = await Packer.toBuffer(doc);
  const outPath = path.join(__dirname, 'ScanOPS_Arquitectura_v2.4.1.docx');
  fs.writeFileSync(outPath, buffer);
  console.log('Document written to:', outPath);
  console.log('Size:', Math.round(buffer.length / 1024), 'KB');
}

main().catch(err => { console.error(err); process.exit(1); });
