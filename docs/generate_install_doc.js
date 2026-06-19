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
const GREEN = '15803D';
const AMBER = 'B45309';
const RED   = 'B91C1C';
const SLATE = '334155';
const WHITE = 'FFFFFF';
const LIGHT = 'F1F5F9';
const BORDER_COLOR = 'CBD5E1';

const PAGE_W  = 11906;
const PAGE_H  = 16838;
const MARGIN  = 1100;
const CONTENT = PAGE_W - MARGIN * 2;

function pt(n) { return n * 2; }
function border(c = BORDER_COLOR) { const b = { style: BorderStyle.SINGLE, size: 1, color: c }; return { top: b, bottom: b, left: b, right: b }; }

function hCell(text, w, bg = NAVY) {
  return new TableCell({ width: { size: w, type: WidthType.DXA }, borders: border(bg), shading: { fill: bg, type: ShadingType.CLEAR }, margins: { top: 80, bottom: 80, left: 130, right: 130 }, children: [new Paragraph({ children: [new TextRun({ text, bold: true, color: WHITE, size: pt(8.5), font: 'Arial' })] })] });
}
function dCell(text, w, shade = false, mono = false) {
  return new TableCell({ width: { size: w, type: WidthType.DXA }, borders: border(), shading: shade ? { fill: LIGHT, type: ShadingType.CLEAR } : undefined, margins: { top: 70, bottom: 70, left: 130, right: 130 }, children: [new Paragraph({ children: [new TextRun({ text, size: pt(8.5), font: mono ? 'Courier New' : 'Arial' })] })] });
}
function makeTable(headers, rows, widths) {
  const total = widths.reduce((s, v) => s + v, 0);
  return new Table({ width: { size: total, type: WidthType.DXA }, columnWidths: widths, rows: [
    new TableRow({ children: headers.map((h, i) => hCell(h, widths[i])), tableHeader: true }),
    ...rows.map((cols, ri) => new TableRow({ children: cols.map((c, ci) => dCell(typeof c === 'object' ? c.text : c, widths[ci], ri % 2 === 0, typeof c === 'object' && c.mono)) })),
  ]});
}

function h1(text) { return new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, children: [new TextRun({ text, bold: true, size: pt(15), font: 'Arial', color: NAVY })] }); }
function h2(text) { return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 140 }, children: [new TextRun({ text, bold: true, size: pt(11), font: 'Arial', color: BLUE })] }); }
function h3(text) { return new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 100 }, children: [new TextRun({ text, bold: true, size: pt(10), font: 'Arial', color: SLATE })] }); }
function body(text, opts = {}) { return new Paragraph({ spacing: { before: 80, after: 80 }, children: [new TextRun({ text, size: pt(10), font: 'Arial', ...opts })] }); }
function spacer() { return new Paragraph({ spacing: { before: 80, after: 80 }, children: [new TextRun('')] }); }
function bullet(text) { return new Paragraph({ numbering: { reference: 'bullets', level: 0 }, spacing: { before: 50, after: 50 }, children: [new TextRun({ text, size: pt(9.5), font: 'Arial' })] }); }
function numItem(text) { return new Paragraph({ numbering: { reference: 'numbers', level: 0 }, spacing: { before: 60, after: 60 }, children: [new TextRun({ text, size: pt(9.5), font: 'Arial' })] }); }

function codeBlock(lines) {
  return new Paragraph({
    spacing: { before: 120, after: 120 },
    shading: { fill: '0F172A', type: ShadingType.CLEAR },
    border: { top: { style: BorderStyle.SINGLE, size: 1, color: '334155' }, bottom: { style: BorderStyle.SINGLE, size: 1, color: '334155' }, left: { style: BorderStyle.THICK, size: 6, color: BLUE }, right: { style: BorderStyle.SINGLE, size: 1, color: '334155' } },
    indent: { left: 200, right: 200 },
    children: lines.map((l, i) => new TextRun({ text: l || ' ', font: 'Courier New', size: pt(8.5), color: 'A5F3FC', break: i === 0 ? 0 : 1 })),
  });
}

function noteBox(title, lines, bg = 'EFF6FF', borderColor = BLUE) {
  return new Table({ width: { size: CONTENT, type: WidthType.DXA }, columnWidths: [CONTENT], rows: [new TableRow({ children: [new TableCell({ width: { size: CONTENT, type: WidthType.DXA }, shading: { fill: bg, type: ShadingType.CLEAR }, borders: { top: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR }, bottom: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR }, left: { style: BorderStyle.THICK, size: 8, color: borderColor }, right: { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR } }, margins: { top: 120, bottom: 120, left: 200, right: 200 }, children: [
    new Paragraph({ children: [new TextRun({ text: title, bold: true, size: pt(9.5), font: 'Arial', color: borderColor })] }),
    ...lines.map(l => new Paragraph({ spacing: { before: 40, after: 40 }, children: [new TextRun({ text: l, size: pt(9), font: 'Arial' })] })),
  ] })] })] });
}

function stepBox(num, title, children_content) {
  return new Table({ width: { size: CONTENT, type: WidthType.DXA }, columnWidths: [700, CONTENT - 700], rows: [new TableRow({ children: [
    new TableCell({ width: { size: 700, type: WidthType.DXA }, borders: border('E2E8F0'), shading: { fill: NAVY, type: ShadingType.CLEAR }, verticalAlign: 'center', margins: { top: 140, bottom: 140, left: 140, right: 140 }, children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: `${num}`, bold: true, size: pt(20), font: 'Arial', color: WHITE })] })] }),
    new TableCell({ width: { size: CONTENT - 700, type: WidthType.DXA }, borders: border('E2E8F0'), shading: { fill: 'F8FAFC', type: ShadingType.CLEAR }, margins: { top: 100, bottom: 100, left: 200, right: 200 }, children: [
      new Paragraph({ spacing: { before: 0, after: 80 }, children: [new TextRun({ text: title, bold: true, size: pt(11), font: 'Arial', color: NAVY })] }),
      ...children_content,
    ] }),
  ]})]});
}

function makeHeader() {
  return { default: new Header({ children: [new Paragraph({ border: { bottom: { style: BorderStyle.SINGLE, size: 3, color: BORDER_COLOR, space: 1 } }, spacing: { before: 0, after: 100 }, tabStops: [{ type: 'right', position: CONTENT }], children: [new TextRun({ text: 'ScanOPS — Guia de Instalacion y Despliegue', size: pt(8), font: 'Arial', color: SLATE }), new TextRun({ text: '\tv2.4.1 | CONFIDENCIAL', size: pt(8), font: 'Arial', color: SLATE })] })] }) };
}
function makeFooter() {
  return { default: new Footer({ children: [new Paragraph({ border: { top: { style: BorderStyle.SINGLE, size: 3, color: BORDER_COLOR, space: 1 } }, spacing: { before: 100, after: 0 }, tabStops: [{ type: 'right', position: CONTENT }], children: [new TextRun({ text: 'UNUWARE | ScanOPS', size: pt(8), font: 'Arial', color: SLATE }), new TextRun({ text: '\tPagina ', size: pt(8), font: 'Arial', color: SLATE }), new TextRun({ children: [PageNumber.CURRENT], size: pt(8), font: 'Arial', color: SLATE }), new TextRun({ text: ' de ', size: pt(8), font: 'Arial', color: SLATE }), new TextRun({ children: [PageNumber.TOTAL_PAGES], size: pt(8), font: 'Arial', color: SLATE })] })] }) };
}

function makeCover() {
  return {
    properties: { page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } } },
    children: [
      new Paragraph({ border: { top: { style: BorderStyle.THICK, size: 12, color: NAVY } }, spacing: { before: 0, after: 400 }, children: [] }),
      new Paragraph({ alignment: AlignmentType.RIGHT, spacing: { before: 0, after: 200 }, children: [new TextRun({ text: 'UNUWARE', bold: true, size: pt(20), font: 'Arial', color: BLUE })] }),
      new Paragraph({ alignment: AlignmentType.RIGHT, spacing: { before: 0, after: 2400 }, children: [new TextRun({ text: 'Ciberseguridad Empresarial', size: pt(11), font: 'Arial', color: SLATE })] }),
      new Paragraph({ alignment: AlignmentType.LEFT, spacing: { before: 0, after: 300 }, indent: { left: 400 }, border: { left: { style: BorderStyle.THICK, size: 16, color: GREEN, space: 300 } }, children: [new TextRun({ text: 'ScanOPS', bold: true, size: pt(32), font: 'Arial', color: NAVY })] }),
      new Paragraph({ alignment: AlignmentType.LEFT, spacing: { before: 0, after: 200 }, indent: { left: 400 }, children: [new TextRun({ text: 'Guia de Instalacion y Despliegue', bold: true, size: pt(16), font: 'Arial', color: NAVY })] }),
      new Paragraph({ alignment: AlignmentType.LEFT, spacing: { before: 0, after: 2400 }, indent: { left: 400 }, children: [new TextRun({ text: 'Descarga, configuracion y puesta en marcha en un nuevo servidor', size: pt(11), font: 'Arial', color: SLATE })] }),
      makeTable(['Campo', 'Valor'], [
        ['Version', 'v2.4.1'],
        ['Fecha', 'Junio 2026'],
        ['Sistema Operativo objetivo', 'Ubuntu 22.04 LTS / Debian 12'],
        ['Clasificacion', 'CONFIDENCIAL — Uso Interno'],
      ], [Math.round(CONTENT * 0.32), Math.round(CONTENT * 0.68)]),
      spacer(), spacer(),
      new Paragraph({ border: { bottom: { style: BorderStyle.THICK, size: 12, color: NAVY } }, spacing: { before: 800, after: 0 }, children: [] }),
    ],
  };
}

function makeTOC() {
  return {
    properties: { page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } } },
    headers: makeHeader(), footers: makeFooter(),
    children: [
      new Paragraph({ spacing: { before: 0, after: 400 }, children: [new TextRun({ text: 'INDICE DE CONTENIDOS', bold: true, size: pt(16), font: 'Arial', color: NAVY })] }),
      new TableOfContents('Tabla de Contenidos', { hyperlink: true, headingStyleRange: '1-2' }),
      new Paragraph({ children: [new PageBreak()] }),
    ],
  };
}

function makeBody() {
  const children = [];

  // ── 0. RESUMEN ──────────────────────────────────────────────────
  children.push(h1('0. Resumen del Proceso'));
  children.push(body('Esta guia describe como descargar, instalar y configurar ScanOPS desde cero en un servidor limpio. El proceso completo requiere aproximadamente 45-90 minutos dependiendo de la velocidad de internet y hardware disponible.'));
  children.push(spacer());
  children.push(makeTable(
    ['Fase', 'Tarea', 'Tiempo estimado'],
    [
      ['1', 'Preparar el sistema operativo y requisitos previos', '10 min'],
      ['2', 'Instalar Docker y Docker Compose', '5 min'],
      ['3', 'Instalar Ollama y descargar modelos LLM', '15-30 min (descarga)'],
      ['4', 'Instalar herramientas de seguridad (nmap, nuclei, hydra...)', '10 min'],
      ['5', 'Clonar el repositorio ScanOPS', '2 min'],
      ['6', 'Configurar variables de entorno', '5 min'],
      ['7', 'Configurar certificados TLS', '5 min'],
      ['8', 'Arrancar los servicios Docker', '5-10 min'],
      ['9', 'Verificar el despliegue', '5 min'],
      ['10', 'Configurar integraciones externas (Telegram, MISP...)', 'Opcional'],
    ],
    [600, Math.round(CONTENT * 0.6), Math.round(CONTENT * 0.4) - 600]
  ));

  // ── 1. REQUISITOS PREVIOS ───────────────────────────────────────
  children.push(h1('1. Requisitos Previos del Sistema'));
  children.push(h2('1.1 Sistema Operativo'));
  children.push(makeTable(['SO', 'Version', 'Estado'], [
    ['Ubuntu', '22.04 LTS (Jammy)', 'RECOMENDADO'],
    ['Ubuntu', '24.04 LTS (Noble)', 'Compatible'],
    ['Debian', '12 (Bookworm)', 'Compatible'],
    ['RHEL / Rocky Linux', '9.x', 'Compatible (ajustes menores)'],
    ['Windows Server', '2022 + WSL2', 'No recomendado para produccion'],
  ], [2000, 2000, Math.round(CONTENT - 4000)]));
  children.push(spacer());
  children.push(h2('1.2 Hardware Minimo'));
  children.push(makeTable(['Componente', 'Minimo', 'Recomendado para produccion'], [
    ['CPU', '8 cores', '16 cores (para Ollama sin GPU)'],
    ['RAM', '16 GB', '32 GB (+ 10 GB para Ollama qwen2.5:14b)'],
    ['Almacenamiento', '100 GB SSD', '500 GB NVMe'],
    ['Red', '100 Mbps', '1 Gbps'],
    ['GPU (opcional)', 'Sin GPU (CPU lento)', 'NVIDIA con 8+ GB VRAM — inferencia 10x mas rapida'],
  ], [2000, 2400, Math.round(CONTENT - 4400)]));
  children.push(spacer());
  children.push(h2('1.3 Puertos de Red a Abrir'));
  children.push(makeTable(['Puerto', 'Protocolo', 'Servicio', 'Exposicion'], [
    ['80', 'TCP', 'Nginx (redirect a HTTPS)', 'Publico'],
    ['443', 'TCP', 'Frontend ScanOPS (HTTPS)', 'Publico'],
    ['2222', 'TCP', 'Cowrie SSH Honeypot', 'Publico (intencionado)'],
    ['2223', 'TCP', 'Cowrie Telnet Honeypot', 'Publico (intencionado)'],
    ['8880', 'TCP', 'Beelzebub HTTP Honeypot', 'Publico (intencionado)'],
    ['8009', 'TCP', 'Orchestrator API', 'Solo interno / VPN'],
    ['9000', 'TCP', 'Graylog Web UI', 'Solo interno'],
    ['55000', 'TCP', 'Wazuh Manager API', 'Solo interno'],
  ], [800, 900, 2200, Math.round(CONTENT - 800 - 900 - 2200)]));

  // ── 2. PREPARAR SISTEMA ─────────────────────────────────────────
  children.push(h1('2. Preparar el Sistema Operativo'));
  children.push(stepBox(1, 'Actualizar el sistema', [
    codeBlock([
      'sudo apt update && sudo apt upgrade -y',
      'sudo apt install -y curl wget git build-essential ca-certificates gnupg',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(2, 'Configurar hostname (recomendado)', [
    codeBlock([
      '# Cambiar hostname al servidor ScanOPS',
      'sudo hostnamectl set-hostname scanops-server',
      'echo "127.0.1.1 scanops-server" | sudo tee -a /etc/hosts',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(3, 'Configurar firewall UFW', [
    codeBlock([
      'sudo ufw allow 22/tcp      # SSH administracion',
      'sudo ufw allow 80/tcp      # HTTP -> redirect HTTPS',
      'sudo ufw allow 443/tcp     # HTTPS frontend',
      'sudo ufw allow 2222/tcp    # Cowrie SSH honeypot',
      'sudo ufw allow 2223/tcp    # Cowrie Telnet honeypot',
      'sudo ufw allow 8880/tcp    # Beelzebub HTTP honeypot',
      'sudo ufw enable',
      'sudo ufw status',
    ]),
  ]));

  // ── 3. DOCKER ────────────────────────────────────────────────────
  children.push(h1('3. Instalar Docker y Docker Compose'));
  children.push(stepBox(1, 'Instalar Docker Engine (metodo oficial)', [
    codeBlock([
      '# Anadir clave GPG oficial de Docker',
      'sudo install -m 0755 -d /etc/apt/keyrings',
      'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg',
      'sudo chmod a+r /etc/apt/keyrings/docker.gpg',
      '',
      '# Anadir repositorio Docker',
      'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list',
      '',
      '# Instalar Docker',
      'sudo apt update',
      'sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(2, 'Configurar Docker para usuario actual', [
    codeBlock([
      '# Anadir usuario al grupo docker (evitar sudo en cada comando)',
      'sudo usermod -aG docker $USER',
      'newgrp docker',
      '',
      '# Verificar instalacion',
      'docker --version',
      'docker compose version',
    ]),
  ]));
  children.push(spacer());
  children.push(noteBox('Versiones requeridas', [
    'Docker Engine: 24.x o superior',
    'Docker Compose Plugin: 2.20 o superior (incluido con Docker Engine moderno)',
    'Alternativa: docker-compose standalone v2.x (NO v1 — usa YAML v3 syntax)',
  ]));

  // ── 4. OLLAMA ────────────────────────────────────────────────────
  children.push(h1('4. Instalar Ollama y Descargar Modelos LLM'));
  children.push(body('Ollama debe ejecutarse en el HOST (no dentro de Docker). Los contenedores acceden a el via la URL especial host.docker.internal:11434.'));
  children.push(spacer());
  children.push(stepBox(1, 'Instalar Ollama', [
    codeBlock([
      '# Instalador oficial (Linux/macOS)',
      'curl -fsSL https://ollama.com/install.sh | sh',
      '',
      '# Verificar que el servicio esta corriendo',
      'systemctl status ollama',
      'ollama --version',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(2, 'Descargar los modelos LLM requeridos', [
    body('ADVERTENCIA: mistral:7b requiere ~4.1 GB y qwen2.5:14b requiere ~9 GB de espacio en disco.', { italics: true, color: AMBER }),
    codeBlock([
      '# Modelo principal (razonamiento de amenazas, correlacion SIEM)',
      'ollama pull mistral:7b',
      '',
      '# Modelo avanzado (post-explotacion, analisis M8)',
      'ollama pull qwen2.5:14b',
      '',
      '# Verificar modelos descargados',
      'ollama list',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(3, 'Configurar Ollama para escucha en red (necesario para Docker)', [
    codeBlock([
      '# Editar el servicio systemd de Ollama',
      'sudo systemctl edit ollama',
      '',
      '# Agregar dentro de [Service]:',
      'Environment="OLLAMA_HOST=0.0.0.0:11434"',
      '',
      '# Aplicar cambios',
      'sudo systemctl daemon-reload',
      'sudo systemctl restart ollama',
    ]),
  ]));
  children.push(spacer());
  children.push(noteBox('Si tienes GPU NVIDIA', [
    '1. Instalar drivers NVIDIA: sudo apt install nvidia-driver-525 (o superior)',
    '2. Instalar NVIDIA Container Toolkit: curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg',
    '3. sudo apt install nvidia-container-toolkit',
    '4. sudo systemctl restart docker',
    'Ollama detectara la GPU automaticamente y la usara para inferencia.',
  ], 'ECFDF5', GREEN));

  // ── 5. HERRAMIENTAS SEGURIDAD ───────────────────────────────────
  children.push(h1('5. Instalar Herramientas de Seguridad'));
  children.push(body('Las herramientas de seguridad deben instalarse en el HOST o estar disponibles en las imagenes Docker correspondientes. Las que se instalan en host son invocadas via subprocess desde los contenedores con Docker socket o mediante volumenes montados.'));
  children.push(spacer());
  children.push(h2('5.1 Herramientas via apt (Ubuntu/Debian)'));
  children.push(codeBlock([
    'sudo apt update',
    'sudo apt install -y \\',
    '  nmap \\                    # M1, M2 — reconocimiento de red',
    '  nikto \\                   # M3 — scanner web',
    '  ffuf \\                    # M2, M3 — fuzzing',
    '  whatweb \\                 # M3 — fingerprinting web',
    '  hydra \\                   # M4 — fuerza bruta',
    '  sqlmap \\                  # M4 — SQL injection',
    '  yara \\                    # M3 — deteccion EDR',
    '  python3-yara \\            # M3 — binding Python para YARA',
    '  git curl wget unzip',
  ]));
  children.push(spacer());
  children.push(h2('5.2 Herramientas via binarios GitHub (versiones recientes)'));
  children.push(codeBlock([
    '# Nuclei (M3 — CVE scanner)',
    'wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m).zip',
    'unzip nuclei_*.zip && sudo mv nuclei /usr/local/bin/ && rm nuclei_*.zip',
    'nuclei -version',
    '',
    '# Gobuster (M4 — directory enumeration)',
    'wget https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_x86_64.tar.gz',
    'tar xzf gobuster_*.tar.gz && sudo mv gobuster /usr/local/bin/ && rm gobuster_*.tar.gz',
    '',
    '# TestSSL.sh (M3 — TLS audit)',
    'git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl',
    'sudo ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh',
    '',
    '# NetExec / NXC (M4 — network exploitation)',
    'pip3 install netexec',
  ]));
  children.push(spacer());
  children.push(h2('5.3 OpenVAS / GVM (opcional, M3)'));
  children.push(codeBlock([
    '# Instalar OpenVAS via paquete (Ubuntu)',
    'sudo apt install -y openvas',
    'sudo gvm-setup',
    'sudo gvm-start',
    '',
    '# O via Docker (mas sencillo)',
    'docker run -d -p 9392:9392 --name openvas greenbone/openvas-scanner',
  ]));
  children.push(spacer());
  children.push(h2('5.4 OWASP ZAP (opcional, M3)'));
  children.push(codeBlock([
    '# Via Docker (recomendado)',
    'docker pull zaproxy/zap-stable',
    '',
    '# O instalar Java y JAR',
    'sudo apt install -y default-jre',
    'wget https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_LINUX.tar.gz',
    'tar xzf ZAP_LINUX.tar.gz -C /opt/',
  ]));

  // ── 6. CLONAR REPOSITORIO ───────────────────────────────────────
  children.push(h1('6. Obtener el Codigo de ScanOPS'));
  children.push(stepBox(1, 'Clonar el repositorio Git', [
    codeBlock([
      '# Clonar el repositorio principal',
      'git clone <URL_DEL_REPOSITORIO_SCANOPS> /opt/scanops',
      'cd /opt/scanops',
      '',
      '# Verificar rama y ultimo commit',
      'git log --oneline -5',
      'git branch',
    ]),
    body('Sustituye <URL_DEL_REPOSITORIO_SCANOPS> por la URL real del repositorio Git de tu organizacion.', { italics: true }),
  ]));
  children.push(spacer());
  children.push(stepBox(2, 'Verificar estructura del proyecto', [
    codeBlock([
      'ls -la /opt/scanops/',
      '# Debes ver: docker-compose.yml, docker-compose.siem.yml,',
      '# frontend/, services/, shared/, docs/, nginx.conf, ...',
    ]),
  ]));

  // ── 7. VARIABLES DE ENTORNO ─────────────────────────────────────
  children.push(h1('7. Configurar Variables de Entorno'));
  children.push(stepBox(1, 'Crear el fichero .env', [
    codeBlock([
      'cd /opt/scanops',
      'cp .env.example .env    # si existe fichero de ejemplo',
      '# o crear desde cero:',
      'nano .env',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(2, 'Contenido minimo del fichero .env', [
    codeBlock([
      '# === OBLIGATORIO — cambiar antes de arrancar ===',
      'JWT_SECRET_KEY=genera_una_clave_aleatoria_de_64_caracteres_aqui',
      '',
      '# Base de datos',
      'DATABASE_URL=postgresql://scanops:scanops@postgres:5432/scanops',
      'REDIS_URL=redis://scanops-main-redis:6379/0',
      '',
      '# Vault',
      'VAULT_ADDR=http://vault:8200',
      'VAULT_TOKEN=mi_token_vault_seguro',
      '',
      '# Ollama (en host)',
      'OLLAMA_BASE_URL=http://host.docker.internal:11434',
      'OLLAMA_MODEL=mistral:7b',
      'OLLAMA_POST_EXPLOIT_MODEL=qwen2.5:14b',
      '',
      '# URLs internas de modulos',
      'M1_URL=http://m1:8001',
      'M2_URL=http://m2:8003',
      'M3_URL=http://scanner-engine:8002',
      'M4_URL=http://m4:8004',
      'M5_URL=http://m5:8006',
      'M7_URL=http://m7:8000',
      'M8_URL=http://m8:8005',
      '',
      '# === OPCIONAL ===',
      '# TELEGRAM_BOT_TOKEN=',
      '# TELEGRAM_CHAT_ID=',
      '# MISP_API_KEY=',
      '# MISP_URL=http://misp:8888',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(3, 'Generar JWT_SECRET_KEY aleatoria', [
    codeBlock([
      '# Generar clave de 64 caracteres hex',
      'openssl rand -hex 32',
      '# Copiar el resultado y pegarlo en JWT_SECRET_KEY=',
    ]),
  ]));

  // ── 8. CERTIFICADOS TLS ──────────────────────────────────────────
  children.push(h1('8. Configurar Certificados TLS'));
  children.push(h2('8.1 Opcion A — mkcert para desarrollo/laboratorio'));
  children.push(codeBlock([
    '# Instalar mkcert',
    'sudo apt install -y libnss3-tools',
    'wget https://github.com/FiloSottile/mkcert/releases/latest/download/mkcert-v*-linux-amd64 -O mkcert',
    'chmod +x mkcert && sudo mv mkcert /usr/local/bin/',
    '',
    '# Instalar CA local y generar certificado',
    'mkcert -install',
    'cd /opt/scanops/certs',
    'mkcert localhost 127.0.0.1 $(hostname) $(hostname -I | awk "{print \\$1}")',
    '',
    '# Renombrar para que nginx los encuentre',
    'mv localhost+*.pem localhost+2.pem',
    'mv localhost+*-key.pem localhost+2-key.pem',
  ]));
  children.push(spacer());
  children.push(h2('8.2 Opcion B — Certificado Let\'s Encrypt (produccion con dominio)'));
  children.push(codeBlock([
    '# Instalar certbot',
    'sudo apt install -y certbot',
    '',
    '# Obtener certificado (sustituir tu.dominio.com)',
    'sudo certbot certonly --standalone -d tu.dominio.com',
    '',
    '# Copiar a la carpeta de certs de ScanOPS',
    'sudo cp /etc/letsencrypt/live/tu.dominio.com/fullchain.pem /opt/scanops/certs/localhost+2.pem',
    'sudo cp /etc/letsencrypt/live/tu.dominio.com/privkey.pem /opt/scanops/certs/localhost+2-key.pem',
    'sudo chown $USER:$USER /opt/scanops/certs/*.pem',
  ]));

  // ── 9. ARRANCAR SERVICIOS ────────────────────────────────────────
  children.push(h1('9. Arrancar los Servicios Docker'));
  children.push(stepBox(1, 'Construir las imagenes locales', [
    codeBlock([
      'cd /opt/scanops',
      '',
      '# Construir TODAS las imagenes (primera vez — puede tardar 10-15 min)',
      'docker compose -f docker-compose.yml build',
      '',
      '# O construir solo una imagen especifica',
      'docker compose -f docker-compose.yml build frontend',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(2, 'Arrancar servicios core', [
    codeBlock([
      '# Arrancar en segundo plano',
      'docker compose -f docker-compose.yml up -d',
      '',
      '# Ver estado de contenedores',
      'docker compose ps',
      '',
      '# Ver logs en tiempo real',
      'docker compose logs -f orchestrator',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(3, 'Arrancar servicios SIEM (opcional)', [
    codeBlock([
      '# Suricata, Cowrie, Beelzebub, MISP',
      'docker compose -f docker-compose.siem.yml up -d',
      '',
      '# NOTA: Suricata usa network_mode: host',
      '# Requiere que el host tenga la interfaz de red correcta configurada en suricata.yaml',
    ]),
  ]));
  children.push(spacer());
  children.push(noteBox('Orden de arranque recomendado', [
    '1. postgres y redis (base de datos) — arrancan automaticamente como dependencias',
    '2. vault — inicializar y configurar antes que los modulos que usan credenciales',
    '3. orchestrator — arranca el ciclo y comprueba salud de modulos',
    '4. m1 a m8 — modulos de negocio',
    '5. frontend — reverse proxy Nginx',
    'Docker Compose gestiona el orden por depends_on automaticamente.',
  ]));

  // ── 10. VERIFICAR DESPLIEGUE ─────────────────────────────────────
  children.push(h1('10. Verificar el Despliegue'));
  children.push(stepBox(1, 'Comprobar health checks de modulos', [
    codeBlock([
      '# Estado general del orquestador',
      'curl -k https://localhost/api/orchestrator/orchestrator/modules/health',
      '',
      '# Verificar cada modulo individualmente',
      'curl http://localhost:8001/health    # M1 Asset Manager',
      'curl http://localhost:8003/health    # M2 Recon Engine',
      'curl http://localhost:8002/health    # M3 Scanner',
      'curl http://localhost:8004/health    # M4 Exploit',
      'curl http://localhost:8006/health    # M5 SIEM',
      'curl http://localhost:8007/health    # M7 Reporting',
      'curl http://localhost:8005/health    # M8 AI Reasoning',
      'curl http://localhost:8009/health    # M0 Orchestrator',
    ]),
  ]));
  children.push(spacer());
  children.push(stepBox(2, 'Acceder al frontend', [
    body('Abrir en el navegador: https://localhost (o https://IP_DEL_SERVIDOR)'),
    spacer(),
    body('Credenciales por defecto (cambiar INMEDIATAMENTE en produccion):', { bold: true }),
    makeTable(['Campo', 'Valor por defecto'], [
      ['Usuario', 'admin'],
      ['Contrasena', 'scanops2024!'],
      ['Rol', 'system_manager'],
    ], [Math.round(CONTENT * 0.4), Math.round(CONTENT * 0.6)]),
  ]));
  children.push(spacer());
  children.push(stepBox(3, 'Ejecutar migraciones de base de datos (si es primera vez)', [
    codeBlock([
      '# Ejecutar migraciones Alembic',
      'docker compose exec m1 alembic upgrade head',
      'docker compose exec scanner-engine alembic upgrade head',
      '',
      '# O usar el script incluido',
      'bash /opt/scanops/run_migrations.sh',
    ]),
  ]));

  // ── 11. CONFIGURAR INTEGRACIONES ─────────────────────────────────
  children.push(h1('11. Configurar Integraciones Externas (Opcional)'));
  children.push(h2('11.1 Telegram Bot (alertas en tiempo real)'));
  children.push(numItem('Abrir Telegram y buscar @BotFather'));
  children.push(numItem('Enviar /newbot y seguir las instrucciones — obtener TOKEN'));
  children.push(numItem('Crear un grupo o canal, agregar el bot como administrador'));
  children.push(numItem('Obtener el CHAT_ID: enviar un mensaje al bot y acceder a https://api.telegram.org/bot<TOKEN>/getUpdates'));
  children.push(numItem('Actualizar en .env: TELEGRAM_BOT_TOKEN=<token> y TELEGRAM_CHAT_ID=<chat_id>'));
  children.push(numItem('Reiniciar los servicios afectados: docker compose restart m4 m5 m7 orchestrator'));
  children.push(spacer());
  children.push(h2('11.2 MISP (Threat Intelligence)'));
  children.push(numItem('MISP ya viene incluido en docker-compose.siem.yml en el puerto 8888'));
  children.push(numItem('Acceder a http://IP:8888 con admin@admin.test / admin (cambiar en primer login)'));
  children.push(numItem('En MISP: Administration > API Access > Create API Key'));
  children.push(numItem('Actualizar en .env: MISP_API_KEY=<key> y MISP_URL=http://misp:8888'));
  children.push(spacer());
  children.push(h2('11.3 CrowdSec (bloqueo colaborativo de IPs)'));
  children.push(codeBlock([
    '# Instalar agente CrowdSec en el host',
    'curl -s https://install.crowdsec.net | sudo sh',
    '',
    '# Crear API key para bouncer',
    'sudo cscli bouncers add scanops-bouncer',
    '',
    '# Copiar la key generada a .env',
    '# CROWDSEC_BOUNCER_KEY=<key>',
  ]));

  // ── 12. COMANDOS DE MANTENIMIENTO ───────────────────────────────
  children.push(h1('12. Comandos de Mantenimiento'));
  children.push(makeTable(
    ['Tarea', 'Comando'],
    [
      ['Ver estado de todos los contenedores', { text: 'docker compose ps', mono: true }],
      ['Ver logs de un modulo', { text: 'docker compose logs -f <servicio>', mono: true }],
      ['Reiniciar un modulo especifico', { text: 'docker compose restart <servicio>', mono: true }],
      ['Parar todos los servicios', { text: 'docker compose down', mono: true }],
      ['Parar y borrar volumenes (DESTRUCTIVO)', { text: 'docker compose down -v', mono: true }],
      ['Reconstruir y reiniciar frontend', { text: 'docker compose build frontend && docker compose up -d frontend', mono: true }],
      ['Ver uso de recursos', { text: 'docker stats', mono: true }],
      ['Acceder a shell de un contenedor', { text: 'docker compose exec <servicio> bash', mono: true }],
      ['Actualizar imagenes externas', { text: 'docker compose pull && docker compose up -d', mono: true }],
      ['Limpiar imagenes sin usar', { text: 'docker image prune -a', mono: true }],
      ['Backup de base de datos PostgreSQL', { text: 'docker compose exec postgres pg_dump -U scanops scanops > backup_$(date +%Y%m%d).sql', mono: true }],
    ],
    [Math.round(CONTENT * 0.42), Math.round(CONTENT * 0.58)]
  ));

  // ── 13. SOLUCIÓN DE PROBLEMAS ───────────────────────────────────
  children.push(h1('13. Solucion de Problemas Comunes'));
  children.push(makeTable(
    ['Sintoma', 'Causa probable', 'Solucion'],
    [
      ['Frontend muestra pantalla en blanco', 'Build de React no actualizado', 'docker compose build frontend && docker compose up -d frontend'],
      ['Modulo aparece como OFFLINE en dashboard', 'Contenedor caido o en error', 'docker compose logs <modulo> para ver el error y reiniciar'],
      ['Ollama no responde desde contenedores', 'host.docker.internal no resuelve o Ollama no escucha en 0.0.0.0', 'Revisar OLLAMA_HOST=0.0.0.0:11434 en el servicio systemd'],
      ['Error 429 Too Many Requests', 'Rate limiting activado', 'Esperar 60s o ajustar limites en nginx.conf y orchestrator/main.py'],
      ['Kill switch no responde con TOTP', 'Secreto TOTP incorrecto o reloj desincronizado', 'Sincronizar NTP: sudo ntpdate pool.ntp.org'],
      ['PostgreSQL no arranca', 'Conflicto de volumen corrupto', 'docker compose down -v && docker compose up -d postgres (BORRA DATOS)'],
      ['Certificado TLS expirado', 'mkcert o Let\'s Encrypt vencido', 'Regenerar certificados y reiniciar frontend'],
      ['Nuclei falla al escanear', 'Templates desactualizados', 'nuclei -update-templates dentro del contenedor M3'],
    ],
    [2000, 2000, Math.round(CONTENT - 4000)]
  ));

  return {
    properties: { page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } } },
    headers: makeHeader(), footers: makeFooter(),
    children,
  };
}

async function main() {
  const doc = new Document({
    numbering: {
      config: [
        { reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '-', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 480, hanging: 240 } } } }] },
        { reference: 'numbers', levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 560, hanging: 280 } } } }] },
      ],
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
  const out = path.join(__dirname, 'ScanOPS_Guia_Instalacion_v2.4.1.docx');
  fs.writeFileSync(out, buffer);
  console.log('Written:', out, '|', Math.round(buffer.length / 1024), 'KB');
}

main().catch(err => { console.error(err); process.exit(1); });
