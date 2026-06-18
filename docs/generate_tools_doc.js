const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat, HeadingLevel,
  BorderStyle, WidthType, ShadingType, PageNumber, PageBreak,
  TableOfContents, ExternalHyperlink
} = require('docx');
const fs = require('fs');
const path = require('path');

const NAVY  = '1A2B4A';
const BLUE  = '2563EB';
const GREEN = '16A34A';
const AMBER = 'D97706';
const RED   = 'DC2626';
const SLATE = '334155';
const WHITE = 'FFFFFF';
const LIGHT = 'F1F5F9';
const BORDER_COLOR = 'CBD5E1';

const PAGE_W  = 11906;
const PAGE_H  = 16838;
const MARGIN  = 1100;
const CONTENT = PAGE_W - MARGIN * 2;

function pt(n) { return n * 2; }

function border(color = BORDER_COLOR) {
  const b = { style: BorderStyle.SINGLE, size: 1, color };
  return { top: b, bottom: b, left: b, right: b };
}

function hCell(text, w, bg = NAVY) {
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    borders: border(bg),
    shading: { fill: bg, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 130, right: 130 },
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, color: WHITE, size: pt(8.5), font: 'Arial' })] })],
  });
}

function dCell(text, w, shade = false, mono = false, color = '1E293B') {
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    borders: border(),
    shading: shade ? { fill: LIGHT, type: ShadingType.CLEAR } : undefined,
    margins: { top: 70, bottom: 70, left: 130, right: 130 },
    children: [new Paragraph({ children: [new TextRun({ text, size: pt(8.5), font: mono ? 'Courier New' : 'Arial', color })] })],
  });
}

function linkCell(text, url, w, shade = false) {
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    borders: border(),
    shading: shade ? { fill: LIGHT, type: ShadingType.CLEAR } : undefined,
    margins: { top: 70, bottom: 70, left: 130, right: 130 },
    children: [new Paragraph({
      children: [new ExternalHyperlink({
        link: url,
        children: [new TextRun({ text, size: pt(8.5), font: 'Arial', color: '2563EB', underline: { type: 'single' } })],
      })],
    })],
  });
}

function makeTable(headers, rows, widths) {
  const total = widths.reduce((s, v) => s + v, 0);
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    rows: [
      new TableRow({ children: headers.map((h, i) => hCell(h, widths[i])), tableHeader: true }),
      ...rows.map((cols, ri) => new TableRow({
        children: cols.map((c, ci) => {
          if (typeof c === 'object' && c.url) return linkCell(c.text, c.url, widths[ci], ri % 2 === 0);
          if (typeof c === 'object' && c.mono) return dCell(c.text, widths[ci], ri % 2 === 0, true);
          return dCell(c, widths[ci], ri % 2 === 0);
        }),
      })),
    ],
  });
}

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    pageBreakBefore: true,
    children: [new TextRun({ text, bold: true, size: pt(15), font: 'Arial', color: NAVY })],
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 280, after: 140 },
    children: [new TextRun({ text, bold: true, size: pt(11), font: 'Arial', color: BLUE })],
  });
}

function h3(text, color = SLATE) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 200, after: 100 },
    children: [new TextRun({ text, bold: true, size: pt(10), font: 'Arial', color })],
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
    spacing: { before: 50, after: 50 },
    children: [new TextRun({ text, size: pt(9.5), font: 'Arial' })],
  });
}

function spacer() {
  return new Paragraph({ spacing: { before: 80, after: 80 }, children: [new TextRun('')] });
}

function colorBadge(text, bgColor, w) {
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    borders: border(),
    shading: { fill: bgColor, type: ShadingType.CLEAR },
    margins: { top: 70, bottom: 70, left: 130, right: 130 },
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, size: pt(8.5), font: 'Arial', color: WHITE })] })],
  });
}

function makeHeader() {
  return {
    default: new Header({
      children: [new Paragraph({
        border: { bottom: { style: BorderStyle.SINGLE, size: 3, color: BORDER_COLOR, space: 1 } },
        spacing: { before: 0, after: 100 },
        children: [
          new TextRun({ text: 'ScanOPS — Referencia de APIs y Herramientas', size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ text: '\tv2.4.1 | CONFIDENCIAL', size: pt(8), font: 'Arial', color: SLATE }),
        ],
        tabStops: [{ type: 'right', position: CONTENT }],
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
          new TextRun({ text: 'UNUWARE | ScanOPS', size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ text: '\tPagina ', size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ children: [PageNumber.CURRENT], size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ text: ' de ', size: pt(8), font: 'Arial', color: SLATE }),
          new TextRun({ children: [PageNumber.TOTAL_PAGES], size: pt(8), font: 'Arial', color: SLATE }),
        ],
        tabStops: [{ type: 'right', position: CONTENT }],
      })],
    }),
  };
}

function makeCover() {
  return {
    properties: {
      page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } },
    },
    children: [
      new Paragraph({ border: { top: { style: BorderStyle.THICK, size: 12, color: NAVY } }, spacing: { before: 0, after: 400 }, children: [] }),
      new Paragraph({ alignment: AlignmentType.RIGHT, spacing: { before: 0, after: 200 }, children: [new TextRun({ text: 'UNUWARE', bold: true, size: pt(20), font: 'Arial', color: BLUE })] }),
      new Paragraph({ alignment: AlignmentType.RIGHT, spacing: { before: 0, after: 2400 }, children: [new TextRun({ text: 'Ciberseguridad Empresarial', size: pt(11), font: 'Arial', color: SLATE })] }),
      new Paragraph({ alignment: AlignmentType.LEFT, spacing: { before: 0, after: 300 }, indent: { left: 400 }, border: { left: { style: BorderStyle.THICK, size: 16, color: BLUE, space: 300 } }, children: [new TextRun({ text: 'ScanOPS', bold: true, size: pt(32), font: 'Arial', color: NAVY })] }),
      new Paragraph({ alignment: AlignmentType.LEFT, spacing: { before: 0, after: 200 }, indent: { left: 400 }, children: [new TextRun({ text: 'Referencia Completa de APIs y Herramientas', bold: true, size: pt(16), font: 'Arial', color: NAVY })] }),
      new Paragraph({ alignment: AlignmentType.LEFT, spacing: { before: 0, after: 2400 }, indent: { left: 400 }, children: [new TextRun({ text: 'Inventario de dependencias, servicios, herramientas de seguridad e integraciones externas', size: pt(11), font: 'Arial', color: SLATE })] }),
      makeTable(['Campo', 'Valor'], [
        ['Version', 'v2.4.1'],
        ['Fecha', 'Junio 2026'],
        ['Clasificacion', 'CONFIDENCIAL — Uso Interno'],
        ['Documento relacionado', 'ScanOPS_Arquitectura_v2.4.1.docx'],
      ], [Math.round(CONTENT * 0.3), Math.round(CONTENT * 0.7)]),
      spacer(), spacer(),
      new Paragraph({ border: { bottom: { style: BorderStyle.THICK, size: 12, color: NAVY } }, spacing: { before: 800, after: 0 }, children: [] }),
    ],
  };
}

function makeTOC() {
  return {
    properties: {
      page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } },
    },
    headers: makeHeader(),
    footers: makeFooter(),
    children: [
      new Paragraph({ spacing: { before: 0, after: 400 }, children: [new TextRun({ text: 'INDICE DE CONTENIDOS', bold: true, size: pt(16), font: 'Arial', color: NAVY })] }),
      new TableOfContents('Tabla de Contenidos', { hyperlink: true, headingStyleRange: '1-2' }),
      new Paragraph({ children: [new PageBreak()] }),
    ],
  };
}

function makeBody() {
  const children = [];

  // ── 1. CONTENEDORES DOCKER ─────────────────────────────────────
  children.push(h1('1. Contenedores Docker (Imagenes)'));
  children.push(body('Todos los servicios de ScanOPS se ejecutan en contenedores Docker. Las imagenes a continuacion deben estar disponibles en el host antes del despliegue.'));
  children.push(spacer());
  children.push(h2('1.1 Core (docker-compose.yml)'));
  children.push(makeTable(
    ['Nombre servicio', 'Imagen Docker', 'Puerto(s)', 'Descripcion'],
    [
      ['postgres', 'postgres:16', '5432 (interno)', 'Base de datos relacional principal'],
      ['redis', 'redis:7-alpine', '6379 (interno)', 'Cache, colas Celery y kill switch'],
      ['m1 (Asset Manager)', 'Build local (Dockerfile.asset)', '8001', 'CMDB y Shadow IT discovery'],
      ['celery-worker', 'Build local', 'interno', 'Trabajadores de colas distribuidas'],
      ['celery-beat', 'Build local', 'interno', 'Scheduler del ciclo semanal'],
      ['m2 (Recon Engine)', 'Build local (Dockerfile.m2)', '8003', 'Reconocimiento y superficie de ataque'],
      ['scanops-webcheck', 'lissy93/web-check:latest', '3000', 'OSINT y analisis web externo'],
      ['scanner-engine (M3)', 'Build local (Dockerfile.scanner)', '8002', 'Scanner CVE y EDR agentless'],
      ['trivy', 'aquasec/trivy:latest', '8090', 'Escaneo de vulnerabilidades en imagenes Docker'],
      ['m4 (Exploit Engine)', 'Build local (Dockerfile.m4)', '8004', 'Motor de explotacion controlada'],
      ['m8 (AI Reasoning)', 'Build local (Dockerfile.m8)', '8005', 'Razonamiento IA con Ollama'],
      ['mongodb', 'mongo:5.0', '27017 (interno)', 'Backend de logs para Graylog'],
      ['opensearch', 'opensearchproject/opensearch:2.11.0', '9200 (interno)', 'Indices SIEM y busqueda de logs'],
      ['graylog', 'graylog/graylog:5.2', '9000, 12201/udp', 'Centralizacion y gestion de logs'],
      ['wazuh-manager', 'wazuh/wazuh-manager:4.7.2', '1514/udp, 1515, 55000', 'HIDS — deteccion en endpoints'],
      ['m5 (SIEM Engine)', 'Build local (Dockerfile.m5)', '8006', 'Correlacion de eventos de seguridad'],
      ['crowdsec', 'crowdsecurity/crowdsec:latest', '8080 (interno)', 'Deteccion colaborativa y bloqueo de IPs'],
      ['m7 (Reporting)', 'Build local (services/reporting_engine)', '8007', 'Generacion de reportes PDF/ZIP'],
      ['orchestrator', 'Build local (Dockerfile.orchestrator)', '8009', 'Coordinador del ciclo semanal'],
      ['cowrie', 'cowrie/cowrie:latest', '2222, 2223', 'Honeypot SSH/Telnet'],
      ['frontend', 'Build local (Dockerfile.frontend)', '80, 443', 'React SPA + Nginx reverse proxy TLS'],
    ],
    [1600, 2400, 1200, Math.round(CONTENT - 1600 - 2400 - 1200)]
  ));
  children.push(spacer());
  children.push(h2('1.2 SIEM adicional (docker-compose.siem.yml)'));
  children.push(makeTable(
    ['Nombre servicio', 'Imagen Docker', 'Puerto(s)', 'Descripcion'],
    [
      ['scanops-suricata', 'jasonish/suricata:latest', 'host mode', 'IDS/IPS de red — captura de trafico real'],
      ['scanops-cowrie', 'cowrie/cowrie:latest', '2222, 2223', 'Honeypot SSH/Telnet (SIEM stack)'],
      ['scanops-beelzebub', 'm4r10/beelzebub:latest', '8880, 13306', 'Honeypot HTTP impulsado por LLM'],
      ['misp-db', 'mysql:8.0', 'interno', 'Base de datos MISP'],
      ['misp-redis', 'redis:7-alpine', 'interno', 'Cache MISP'],
      ['misp (Core)', 'ghcr.io/misp/misp-docker/misp-core:latest', '8888', 'Plataforma de Threat Intelligence'],
    ],
    [1800, 2800, 1200, Math.round(CONTENT - 1800 - 2800 - 1200)]
  ));

  // ── 2. HERRAMIENTAS DE SEGURIDAD ────────────────────────────────
  children.push(h1('2. Herramientas de Seguridad (Binarios)'));
  children.push(body('Las siguientes herramientas deben estar instaladas en el host o dentro de las imagenes Docker correspondientes. Se invocan como subprocesos desde los modulos Python.'));
  children.push(spacer());

  children.push(h2('2.1 Reconocimiento y Escaneo (M2, M3)'));
  children.push(makeTable(
    ['Herramienta', 'Binario', 'Version recomendada', 'Modulo', 'URL de descarga'],
    [
      ['Nmap', { text: 'nmap', mono: true }, '7.94+', 'M1, M2', { text: 'https://nmap.org/download', url: 'https://nmap.org/download' }],
      ['Nikto', { text: 'nikto', mono: true }, '2.1.6+', 'M3', { text: 'https://cirt.net/Nikto2', url: 'https://cirt.net/Nikto2' }],
      ['Nuclei', { text: 'nuclei', mono: true }, 'v3.3+', 'M3', { text: 'https://github.com/projectdiscovery/nuclei/releases', url: 'https://github.com/projectdiscovery/nuclei/releases' }],
      ['ffuf', { text: 'ffuf', mono: true }, 'v2.1+', 'M2, M3', { text: 'https://github.com/ffuf/ffuf/releases', url: 'https://github.com/ffuf/ffuf/releases' }],
      ['WhatWeb', { text: 'whatweb', mono: true }, '0.5.5+', 'M3', { text: 'https://github.com/urbanadventurer/WhatWeb', url: 'https://github.com/urbanadventurer/WhatWeb' }],
      ['TestSSL.sh', { text: 'testssl.sh', mono: true }, '3.0.8+', 'M3', { text: 'https://testssl.sh/', url: 'https://testssl.sh/' }],
    ],
    [1400, 1200, 1400, 800, Math.round(CONTENT - 1400 - 1200 - 1400 - 800)]
  ));
  children.push(spacer());
  children.push(h2('2.2 Explotacion y Fuerza Bruta (M4)'));
  children.push(makeTable(
    ['Herramienta', 'Binario', 'Version recomendada', 'Uso en M4', 'URL de descarga'],
    [
      ['Hydra', { text: 'hydra', mono: true }, '9.5+', 'Fuerza bruta SSH/FTP/HTTP', { text: 'https://github.com/vanhauser-thc/thc-hydra', url: 'https://github.com/vanhauser-thc/thc-hydra' }],
      ['SQLMap', { text: 'sqlmap', mono: true }, '1.7+', 'SQL Injection testing', { text: 'https://sqlmap.org/', url: 'https://sqlmap.org/' }],
      ['Gobuster', { text: 'gobuster', mono: true }, 'v3.6+', 'Enumeracion de directorios/subdominios', { text: 'https://github.com/OJ/gobuster/releases', url: 'https://github.com/OJ/gobuster/releases' }],
      ['NetExec (NXC)', { text: 'nxc', mono: true }, '1.3+', 'SMB/SSH/RDP lateral movement', { text: 'https://github.com/Pennyw0rth/NetExec', url: 'https://github.com/Pennyw0rth/NetExec' }],
    ],
    [1400, 1200, 1400, 2000, Math.round(CONTENT - 1400 - 1200 - 1400 - 2000)]
  ));
  children.push(spacer());
  children.push(h2('2.3 Deteccion y Analisis (M3, M5)'));
  children.push(makeTable(
    ['Herramienta', 'Tipo', 'Version recomendada', 'Uso en ScanOPS', 'URL'],
    [
      ['OpenVAS / GVM', 'Vulnerability Scanner', '22.x+', 'Escaneos autenticados de vulnerabilidades (M3)', { text: 'https://www.openvas.org/', url: 'https://www.openvas.org/' }],
      ['ZAP (OWASP)', 'DAST Web Scanner', '2.15+', 'Analisis dinamico de aplicaciones web (M3)', { text: 'https://www.zaproxy.org/download/', url: 'https://www.zaproxy.org/download/' }],
      ['YARA', 'Pattern Matching', '4.3+', 'Deteccion de malware en EDR (M3)', { text: 'https://github.com/VirusTotal/yara/releases', url: 'https://github.com/VirusTotal/yara/releases' }],
      ['Suricata', 'IDS/IPS', '7.x+', 'Deteccion de intrusiones de red (M5 SIEM)', { text: 'https://suricata.io/download/', url: 'https://suricata.io/download/' }],
      ['Wazuh Agent', 'HIDS', '4.7.2', 'Monitoreo de endpoints (M5 SIEM)', { text: 'https://documentation.wazuh.com/', url: 'https://documentation.wazuh.com/' }],
      ['CrowdSec', 'IPS colaborativo', 'latest', 'Bloqueo automatico de IPs maliciosas (M5)', { text: 'https://www.crowdsec.net/download', url: 'https://www.crowdsec.net/download' }],
    ],
    [1600, 1500, 1300, 2000, Math.round(CONTENT - 1600 - 1500 - 1300 - 2000)]
  ));

  // ── 3. MODELOS LLM (OLLAMA) ─────────────────────────────────────
  children.push(h1('3. Modelos LLM — Ollama'));
  children.push(body('ScanOPS utiliza LLMs locales a traves de Ollama para garantizar que los datos de vulnerabilidades no salgan de la infraestructura (requisito ENS confidencialidad).'));
  children.push(spacer());
  children.push(makeTable(
    ['Modelo', 'Tag Ollama', 'Tamano aprox.', 'Uso en ScanOPS', 'Modulo(s)'],
    [
      ['Qwen2.5', 'qwen2.5:14b', '~9 GB', 'Analisis post-explotacion y razonamiento avanzado', 'M8, celery-worker'],
      ['Mistral', 'mistral:7b', '~4.1 GB', 'Razonamiento de amenazas, correlacion SIEM, analisis rapido', 'M4, M5, M8, orchestrator'],
    ],
    [1400, 1500, 1200, 3000, Math.round(CONTENT - 1400 - 1500 - 1200 - 3000)]
  ));
  children.push(spacer());
  children.push(body('Comandos de descarga de modelos:', { bold: true }));
  children.push(new Paragraph({
    spacing: { before: 100, after: 100 },
    shading: { fill: 'EFF4FB', type: ShadingType.CLEAR },
    border: { top: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR }, bottom: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR }, left: { style: BorderStyle.THICK, size: 6, color: BLUE }, right: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR } },
    indent: { left: 200, right: 200 },
    children: [
      new TextRun({ text: 'ollama pull qwen2.5:14b', font: 'Courier New', size: pt(9), break: 0 }),
      new TextRun({ text: 'ollama pull mistral:7b', font: 'Courier New', size: pt(9), break: 1 }),
    ],
  }));
  children.push(spacer());
  children.push(body('Nota: Ollama debe ejecutarse en el host (no en Docker). La URL de acceso desde contenedores es http://host.docker.internal:11434', { italics: true }));
  children.push(body('Descarga Ollama en: https://ollama.com/download', { italics: true }));

  // ── 4. DEPENDENCIAS PYTHON ──────────────────────────────────────
  children.push(h1('4. Dependencias Python (Backend)'));
  children.push(h2('4.1 Core — requirements.txt'));
  children.push(makeTable(
    ['Paquete', 'Version', 'Uso'],
    [
      ['fastapi', '== 0.104.1', 'Framework REST API para todos los modulos'],
      ['uvicorn[standard]', '== 0.24.0', 'ASGI server'],
      ['sqlalchemy', '>= 2.0.0', 'ORM y gestion de esquemas PostgreSQL'],
      ['alembic', '>= 1.12.0', 'Migraciones de base de datos'],
      ['psycopg2-binary', '>= 2.9.0', 'Driver PostgreSQL'],
      ['pydantic', '>= 2.0.0', 'Validacion de datos y modelos'],
      ['pydantic-settings', '>= 2.0.0', 'Gestion de variables de entorno'],
      ['celery', '>= 5.3.0', 'Cola de tareas distribuidas'],
      ['redis', '>= 4.5.0', 'Cliente Redis para cache y colas'],
      ['httpx', '>= 0.24.0', 'HTTP client asincrono'],
      ['python-jose[cryptography]', '>= 3.3.0', 'JWT HS256'],
      ['passlib[bcrypt]', '>= 1.7.0', 'Hashing de contrasenas'],
      ['python-multipart', '>= 0.0.6', 'Soporte de formularios y uploads'],
      ['paramiko', '>= 3.1.0', 'SSH client para telemetria agentless (M3)'],
      ['hvac', '>= 2.0.0', 'Cliente HashiCorp Vault'],
      ['pyotp', '>= 2.9.0', 'Generacion y validacion TOTP'],
      ['qrcode', '>= 7.4.2', 'Generacion de QR para TOTP'],
      ['pillow', '>= 10.0.0', 'Procesamiento de imagenes'],
      ['reportlab', '>= 4.4.0', 'Generacion de PDFs (M7)'],
      ['jinja2', '>= 3.1.0', 'Plantillas de reportes'],
      ['aiohttp', '>= 3.9.0', 'HTTP asincrono para integraciones externas'],
      ['lxml', '>= 4.9.0', 'Procesamiento XML/HTML'],
      ['PyYAML', '>= 6.0', 'Parsing de configuracion YAML'],
      ['dnspython', '>= 2.4.0', 'Resoluciones DNS (M2)'],
      ['python-whois', '>= 0.8.0', 'Consultas WHOIS (M2)'],
      ['yara-python', '>= 4.3.0', 'Reglas YARA para deteccion EDR'],
      ['python-gvm', '>= 24.1.0', 'Cliente API OpenVAS/GVM (M3)'],
      ['gvm-tools', '>= 20.8.0', 'Herramientas CLI para GVM'],
      ['psutil', '>= 5.9.0', 'Metricas del sistema'],
      ['pybreaker', '>= 1.2.0', 'Circuit breaker para llamadas externas'],
      ['msgpack', '>= 1.0.0', 'Serializacion binaria para Celery'],
    ],
    [2200, 1400, Math.round(CONTENT - 2200 - 1400)]
  ));
  children.push(spacer());
  children.push(h2('4.2 Reporting Engine — requirements adicionales'));
  children.push(makeTable(
    ['Paquete', 'Version', 'Uso'],
    [
      ['weasyprint', '>= 62.1', 'Conversion HTML a PDF'],
      ['PyMuPDF', '>= 1.23.8', 'Manipulacion y merge de PDFs'],
      ['google-api-python-client', '>= 2.0.0', 'Integracion con Google Drive (M7 opcional)'],
      ['google-auth-httplib2', '>= 0.1.0', 'Autenticacion Google OAuth'],
      ['google-auth-oauthlib', '>= 1.0.0', 'Flujo OAuth2 para Google'],
      ['PyJWT', '>= 2.8.0', 'JWT alternativo para M7'],
    ],
    [2200, 1400, Math.round(CONTENT - 2200 - 1400)]
  ));
  children.push(spacer());
  children.push(h2('4.3 Orchestrator — requirements.orchestrator.txt'));
  children.push(makeTable(
    ['Paquete', 'Version', 'Uso'],
    [
      ['fastapi', '>= 0.100.0', 'Framework API Orchestrator'],
      ['uvicorn', '>= 0.20.0', 'ASGI server'],
      ['httpx', '>= 0.24.0', 'Health checks de modulos'],
      ['pydantic', '>= 2.0.0', 'Modelos y validacion'],
      ['pydantic-settings', '>= 2.0.0', 'Variables de entorno'],
      ['sqlalchemy', '>= 2.0.0', 'ORM para users/sessions'],
      ['psycopg2-binary', '>= 2.9.0', 'Driver PostgreSQL'],
      ['python-jose[cryptography]', '>= 3.3.0', 'JWT'],
      ['bcrypt', '>= 4.0.0', 'Hashing de contrasenas'],
      ['python-multipart', '>= 0.0.6', 'Formularios'],
      ['redis', '>= 4.5.0', 'Kill switch y session cache'],
    ],
    [2200, 1400, Math.round(CONTENT - 2200 - 1400)]
  ));

  // ── 5. DEPENDENCIAS FRONTEND ────────────────────────────────────
  children.push(h1('5. Dependencias Frontend (npm)'));
  children.push(h2('5.1 Dependencias de produccion'));
  children.push(makeTable(
    ['Paquete npm', 'Version', 'Uso'],
    [
      ['react', '18.3.1', 'Framework UI'],
      ['react-dom', '18.3.1', 'Renderizado DOM'],
      ['react-router', '7.13.0', 'Enrutamiento SPA'],
      ['recharts', '2.15.2', 'Graficas y sparklines KPI'],
      ['lucide-react', '0.487.0', 'Iconografia'],
      ['motion', '12.23.24', 'Animaciones'],
      ['sonner', '2.0.3', 'Notificaciones toast'],
      ['otpauth', '^9.5.1', 'Generacion TOTP en cliente'],
      ['@radix-ui/react-*', 'varios', 'Componentes accesibles (shadcn/ui)'],
      ['@mui/material', '7.3.5', 'Componentes Material UI adicionales'],
      ['react-hook-form', '7.55.0', 'Gestion de formularios'],
      ['date-fns', '3.6.0', 'Utilidades de fecha'],
      ['clsx', '2.1.1', 'Clases CSS condicionales'],
      ['class-variance-authority', '0.7.1', 'Variantes de componentes'],
      ['tailwind-merge', '3.2.0', 'Merge de clases Tailwind'],
      ['cmdk', '1.1.1', 'Command palette'],
      ['vaul', '1.1.2', 'Drawer component'],
      ['embla-carousel-react', '8.6.0', 'Carrusel de componentes'],
      ['react-resizable-panels', '2.1.7', 'Paneles redimensionables'],
      ['input-otp', '1.4.2', 'Input de codigos OTP'],
      ['canvas-confetti', '1.9.4', 'Efectos visuales'],
    ],
    [2600, 1200, Math.round(CONTENT - 2600 - 1200)]
  ));
  children.push(spacer());
  children.push(h2('5.2 Dependencias de desarrollo'));
  children.push(makeTable(
    ['Paquete npm', 'Version', 'Uso'],
    [
      ['vite', '6.3.5', 'Build tool y dev server'],
      ['typescript', '^6.0.3', 'Tipado estatico'],
      ['tailwindcss', '4.1.12', 'Framework CSS utility-first'],
      ['@tailwindcss/vite', '4.1.12', 'Plugin Vite para Tailwind'],
      ['@vitejs/plugin-react', '4.7.0', 'Plugin React para Vite'],
      ['@types/react', '^19.2.14', 'Tipos TypeScript para React'],
      ['@types/react-dom', '^19.2.3', 'Tipos TypeScript para React DOM'],
      ['@playwright/test', '^1.60.0', 'Tests E2E'],
    ],
    [2600, 1200, Math.round(CONTENT - 2600 - 1200)]
  ));

  // ── 6. APIS EXTERNAS ─────────────────────────────────────────────
  children.push(h1('6. APIs e Integraciones Externas'));
  children.push(body('Las siguientes integraciones son opcionales pero recomendadas para despliegues en produccion. Las variables de entorno deben configurarse en docker-compose.yml o en un fichero .env.'));
  children.push(spacer());
  children.push(makeTable(
    ['Servicio', 'Variable de entorno', 'Modulo(s)', 'Obtencion / Registro'],
    [
      ['Telegram Bot API', 'TELEGRAM_BOT_TOKEN\nTELEGRAM_CHAT_ID', 'M4, M5, M7, Orchestrator', { text: 'https://t.me/BotFather', url: 'https://t.me/BotFather' }],
      ['MISP Threat Intelligence', 'MISP_API_KEY\nMISP_URL', 'M5 SIEM', { text: 'https://www.misp-project.org/', url: 'https://www.misp-project.org/' }],
      ['Wazuh REST API', 'WAZUH_API_URL\nWAZUH_USER\nWAZUH_PASSWORD', 'M5 SIEM', { text: 'https://documentation.wazuh.com/', url: 'https://documentation.wazuh.com/' }],
      ['Graylog REST API', 'GRAYLOG_API_URL', 'M5 SIEM', { text: 'https://go2docs.graylog.org/', url: 'https://go2docs.graylog.org/' }],
      ['CrowdSec API', 'CROWDSEC_API_URL\nCROWDSEC_BOUNCER_KEY', 'M5 SIEM', { text: 'https://www.crowdsec.net/', url: 'https://www.crowdsec.net/' }],
      ['Google Drive API (opcional)', 'GOOGLE_DRIVE_FOLDER_ID', 'M7 Reporting', { text: 'https://console.cloud.google.com/', url: 'https://console.cloud.google.com/' }],
      ['SMTP Email (opcional)', 'SMTP_HOST, SMTP_PORT\nSMTP_USER, SMTP_PASSWORD\nALERT_EMAIL_TO', 'M5 SIEM', 'Proveedor SMTP corporativo o servicio como SendGrid'],
      ['HashiCorp Vault', 'VAULT_ADDR\nVAULT_TOKEN', 'M1 Asset Manager', { text: 'https://developer.hashicorp.com/vault', url: 'https://developer.hashicorp.com/vault' }],
    ],
    [1600, 2000, 1200, Math.round(CONTENT - 1600 - 2000 - 1200)]
  ));

  // ── 7. VARIABLES DE ENTORNO ─────────────────────────────────────
  children.push(h1('7. Variables de Entorno Completas'));
  children.push(body('Referencia completa de todas las variables de entorno utilizadas en ScanOPS. Las marcadas como REQUERIDO deben configurarse antes del primer arranque.'));
  children.push(spacer());

  const W_ENV = [2400, 900, 1400, Math.round(CONTENT - 2400 - 900 - 1400)];
  // Custom table with colored badge for required column
  const envBorderB = border();
  function envRow(varName, req, defaultVal, desc, idx) {
    const shade = idx % 2 === 0;
    const bg = shade ? LIGHT : WHITE;
    const reqColor = req === 'SI' ? RED : req === 'Opcional' ? AMBER : GREEN;
    return new TableRow({
      children: [
        new TableCell({ width: { size: W_ENV[0], type: WidthType.DXA }, borders: envBorderB, shading: shade ? { fill: LIGHT, type: ShadingType.CLEAR } : undefined, margins: { top: 70, bottom: 70, left: 130, right: 130 }, children: [new Paragraph({ children: [new TextRun({ text: varName, font: 'Courier New', size: pt(8), color: '1E293B' })] })] }),
        new TableCell({ width: { size: W_ENV[1], type: WidthType.DXA }, borders: envBorderB, shading: { fill: reqColor, type: ShadingType.CLEAR }, margins: { top: 70, bottom: 70, left: 130, right: 130 }, children: [new Paragraph({ children: [new TextRun({ text: req, bold: true, size: pt(8), font: 'Arial', color: WHITE })] })] }),
        new TableCell({ width: { size: W_ENV[2], type: WidthType.DXA }, borders: envBorderB, shading: shade ? { fill: LIGHT, type: ShadingType.CLEAR } : undefined, margins: { top: 70, bottom: 70, left: 130, right: 130 }, children: [new Paragraph({ children: [new TextRun({ text: defaultVal, font: 'Courier New', size: pt(8), color: '64748B' })] })] }),
        new TableCell({ width: { size: W_ENV[3], type: WidthType.DXA }, borders: envBorderB, shading: shade ? { fill: LIGHT, type: ShadingType.CLEAR } : undefined, margins: { top: 70, bottom: 70, left: 130, right: 130 }, children: [new Paragraph({ children: [new TextRun({ text: desc, size: pt(8.5), font: 'Arial' })] })] }),
      ],
    });
  }

  const envVars = [
    ['JWT_SECRET_KEY', 'SI', 'CHANGE_ME_IN_PROD', 'Clave de firma JWT — cambiar siempre en produccion'],
    ['DATABASE_URL', 'SI', 'postgresql://scanops:scanops@postgres:5432/scanops', 'URL de conexion PostgreSQL'],
    ['REDIS_URL', 'SI', 'redis://scanops-main-redis:6379/0', 'URL de conexion Redis'],
    ['VAULT_ADDR', 'SI', 'http://vault:8200', 'URL HashiCorp Vault'],
    ['VAULT_TOKEN', 'SI', '(secreto)', 'Token de acceso a Vault'],
    ['M1_URL', 'SI', 'http://m1:8001', 'URL interna M1 Asset Manager'],
    ['M2_URL', 'SI', 'http://m2:8003', 'URL interna M2 Recon Engine'],
    ['M3_URL', 'SI', 'http://scanner-engine:8002', 'URL interna M3 Scanner'],
    ['M4_URL', 'SI', 'http://m4:8004', 'URL interna M4 Exploit Engine'],
    ['M5_URL', 'SI', 'http://m5:8006', 'URL interna M5 SIEM'],
    ['M7_URL', 'SI', 'http://m7:8000', 'URL interna M7 Reporting'],
    ['M8_URL', 'SI', 'http://m8:8005', 'URL interna M8 AI Reasoning'],
    ['OLLAMA_BASE_URL', 'SI', 'http://host.docker.internal:11434', 'URL Ollama en el host'],
    ['OLLAMA_MODEL', 'SI', 'mistral:7b', 'Modelo Ollama principal'],
    ['OLLAMA_POST_EXPLOIT_MODEL', 'SI', 'qwen2.5:14b', 'Modelo Ollama para post-explotacion'],
    ['TELEGRAM_BOT_TOKEN', 'Opcional', '', 'Token del bot de Telegram para alertas'],
    ['TELEGRAM_CHAT_ID', 'Opcional', '', 'ID del chat de destino en Telegram'],
    ['MISP_API_KEY', 'Opcional', '', 'API Key de la instancia MISP'],
    ['MISP_URL', 'Opcional', 'http://misp:8888', 'URL de la instancia MISP'],
    ['WAZUH_API_URL', 'Opcional', 'https://wazuh-manager:55000', 'URL API Wazuh Manager'],
    ['WAZUH_USER', 'Opcional', 'wazuh', 'Usuario API Wazuh'],
    ['WAZUH_PASSWORD', 'Opcional', '(secreto)', 'Contrasena API Wazuh'],
    ['GRAYLOG_API_URL', 'Opcional', 'http://graylog:9000/api', 'URL API Graylog'],
    ['CROWDSEC_API_URL', 'Opcional', 'http://crowdsec:8080', 'URL API CrowdSec'],
    ['CROWDSEC_BOUNCER_KEY', 'Opcional', '(secreto)', 'Clave del bouncer CrowdSec'],
    ['SMTP_HOST', 'Opcional', '', 'Host servidor SMTP para alertas email'],
    ['SMTP_PORT', 'Opcional', '587', 'Puerto SMTP'],
    ['SMTP_USER', 'Opcional', '', 'Usuario SMTP'],
    ['SMTP_PASSWORD', 'Opcional', '', 'Contrasena SMTP'],
    ['ALERT_EMAIL_TO', 'Opcional', '', 'Email destino para alertas criticas'],
    ['GOOGLE_DRIVE_FOLDER_ID', 'Opcional', '', 'ID carpeta Google Drive para reportes (M7)'],
  ];
  children.push(new Table({
    width: { size: CONTENT, type: WidthType.DXA },
    columnWidths: W_ENV,
    rows: [
      new TableRow({ children: [hCell('Variable', W_ENV[0]), hCell('Requerida', W_ENV[1]), hCell('Default', W_ENV[2]), hCell('Descripcion', W_ENV[3])], tableHeader: true }),
      ...envVars.map((row, i) => envRow(...row, i)),
    ],
  }));

  return {
    properties: {
      page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } },
    },
    headers: makeHeader(),
    footers: makeFooter(),
    children,
  };
}

async function main() {
  const doc = new Document({
    numbering: {
      config: [{
        reference: 'bullets',
        levels: [{ level: 0, format: LevelFormat.BULLET, text: '-', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 480, hanging: 240 } } } }],
      }],
    },
    styles: {
      default: { document: { run: { font: 'Arial', size: pt(10) } } },
      paragraphStyles: [
        { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: pt(15), bold: true, font: 'Arial', color: NAVY }, paragraph: { spacing: { before: 480, after: 240 }, outlineLevel: 0 } },
        { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: pt(11), bold: true, font: 'Arial', color: BLUE }, paragraph: { spacing: { before: 320, after: 160 }, outlineLevel: 1 } },
        { id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: pt(10), bold: true, font: 'Arial', color: SLATE }, paragraph: { spacing: { before: 240, after: 100 }, outlineLevel: 2 } },
      ],
    },
    settings: { updateFields: true },
    sections: [makeCover(), makeTOC(), makeBody()],
  });
  const buffer = await Packer.toBuffer(doc);
  const out = path.join(__dirname, 'ScanOPS_APIs_y_Herramientas_v2.4.1.docx');
  fs.writeFileSync(out, buffer);
  console.log('Written:', out, '|', Math.round(buffer.length / 1024), 'KB');
}

main().catch(err => { console.error(err); process.exit(1); });
