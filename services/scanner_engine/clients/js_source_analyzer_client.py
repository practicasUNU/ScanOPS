"""
JS Source Code Analyzer — M3 Scanner Client
Descarga HTML y ficheros JS del target, escanea con 15 catálogos de patrones
para detectar secretos hardcoded, tokens, claves API y rutas internas.
ENS: mp.info.3, mp.info.4
"""
import re
import urllib.request
import urllib.error
from html.parser import HTMLParser
from typing import List, Dict

from shared.scan_logger import ScanLogger

logger = ScanLogger("js_source_analyzer")

# ---------------------------------------------------------------------------
# Catálogo de patrones — 15 categorías extraídas de WSTG-Scan
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: List[Dict] = [
    {
        "name": "PEM Private Key",
        "pattern": re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----", re.IGNORECASE),
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cwe": "CWE-321",
        "ens": "mp.info.3",
        "remediation": "Eliminar clave privada del código fuente. Usar gestión de secretos (Vault, AWS Secrets Manager).",
    },
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-798",
        "ens": "mp.info.3",
        "remediation": "Revocar la clave AWS inmediatamente. Rotar credenciales y auditar accesos en CloudTrail.",
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{82}\b"),
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-798",
        "ens": "mp.info.3",
        "remediation": "Revocar el token en GitHub Settings → Developer settings. Usar GitHub Secrets o variables de entorno.",
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-798",
        "ens": "mp.info.3",
        "remediation": "Restringir la clave a dominios/IPs autorizados en Google Cloud Console o revocarla si está comprometida.",
    },
    {
        "name": "Stripe Secret Key",
        "pattern": re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-798",
        "ens": "mp.info.3",
        "remediation": "Rotar la clave Stripe inmediatamente desde el Dashboard. Nunca exponer sk_live en frontend.",
    },
    {
        "name": "Slack Token",
        "pattern": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"),
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-798",
        "ens": "mp.info.3",
        "remediation": "Revocar el token en Slack API → Apps. Usar variables de entorno en servidor, no en código cliente.",
    },
    {
        "name": "JWT Token Hardcoded",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_.+/=]{10,}\b"),
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-522",
        "ens": "op.acc.1",
        "remediation": "Invalidar el token. Los JWT no deben estar hardcoded — usar autenticación dinámica.",
    },
    {
        "name": "Hardcoded Password",
        "pattern": re.compile(r"""(?:password|passwd|pwd|secret|token)\s*[:=]\s*['"][^'"]{8,}['"]""", re.IGNORECASE),
        "severity": "HIGH",
        "cvss": 8.0,
        "cwe": "CWE-259",
        "ens": "op.acc.5",
        "remediation": "Eliminar credenciales hardcoded. Usar variables de entorno o un gestor de secretos.",
    },
    {
        "name": "Private IP Address Exposed",
        "pattern": re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
        "severity": "LOW",
        "cvss": 3.1,
        "cwe": "CWE-200",
        "ens": "mp.info.4",
        "remediation": "Evitar referencias a IPs privadas en código JS público. Usar variables de entorno.",
    },
    {
        "name": "Internal Path Disclosure",
        "pattern": re.compile(r"""['"/](?:var|etc|home|root|tmp|proc|usr/local|app|srv)/[^\s'"<>]{4,}"""),
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cwe": "CWE-200",
        "ens": "mp.info.4",
        "remediation": "Eliminar rutas del sistema de ficheros del código fuente. Usar rutas relativas.",
    },
    {
        "name": "Generic API Key",
        "pattern": re.compile(
            r"""(?:api[_-]?key|apikey|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9\-_]{16,}['"]""",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-798",
        "ens": "mp.info.3",
        "remediation": "Mover la API key al backend o a variables de entorno. Rotar si ya estuvo expuesta.",
    },
    {
        "name": "Firebase Server Key",
        "pattern": re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"),
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-798",
        "ens": "mp.info.3",
        "remediation": "Restringir las reglas de seguridad de Firebase. Revocar y rotar la clave de servidor.",
    },
    {
        "name": "Basic Auth in URL",
        "pattern": re.compile(r"https?://[A-Za-z0-9_\-]{3,}:[A-Za-z0-9_\-!@#$%^&*]{3,}@"),
        "severity": "HIGH",
        "cvss": 8.0,
        "cwe": "CWE-312",
        "ens": "mp.info.3",
        "remediation": "Eliminar credenciales de URLs. Usar cabeceras Authorization Bearer.",
    },
    {
        "name": "RSA/SSH Public Key Material",
        "pattern": re.compile(r"(?:AAAAB3NzaC1yc2E|AAAAB3NzaC1kc3M|AAAAE2VjZHNhLXNoYTItbmlzdHA)[A-Za-z0-9+/]{20,}"),
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-200",
        "ens": "mp.info.4",
        "remediation": "Las claves públicas SSH en JS pueden revelar infraestructura. Revisar si es intencional.",
    },
    {
        "name": "Hardcoded Bearer Token",
        "pattern": re.compile(r"""[Bb]earer\s+['"]?[A-Za-z0-9\-_\.]{40,}['"]?"""),
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-522",
        "ens": "op.acc.1",
        "remediation": "Los tokens Bearer no deben estar hardcoded. Generar dinámicamente tras autenticación.",
    },
]

_MAX_JS_FILES = 20
_MAX_JS_SIZE = 512 * 1024  # 512 KB por fichero
_REQUEST_TIMEOUT = 10


class _ScriptSrcParser(HTMLParser):
    """Extrae URLs de atributos src en etiquetas <script>."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self.js_urls: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        attrs_dict = dict(attrs)
        src = (attrs_dict.get("src") or "").strip()
        if not src:
            return
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = self.base_url + src
        elif not src.startswith("http"):
            src = self.base_url + "/" + src
        if src not in self.js_urls:
            self.js_urls.append(src)


def _fetch_url(url: str, timeout: int = _REQUEST_TIMEOUT) -> str:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ScanOPS-JS-Analyzer/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if any(ct in content_type for ct in ("image/", "video/", "audio/", "font/")):
                return ""
            return resp.read(_MAX_JS_SIZE).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _scan_content(content: str, source_url: str) -> List[Dict]:
    findings = []
    seen_keys = set()
    for pat_info in _SECRET_PATTERNS:
        matches = pat_info["pattern"].findall(content)
        if not matches:
            continue
        key = (pat_info["name"], source_url)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        sample = str(matches[0])[:60] + ("..." if len(str(matches[0])) > 60 else "")
        findings.append({
            "title": f"Secreto Hardcoded en JS: {pat_info['name']}",
            "severity": pat_info["severity"],
            "description": (
                f"{pat_info['name']} detectado en {source_url}. "
                f"Muestra (redactada): {sample} — {len(matches)} ocurrencia(s)."
            ),
            "cve_id": None,
            "cvss_score": pat_info["cvss"],
            "evidence": {
                "source_url": source_url,
                "pattern_name": pat_info["name"],
                "occurrences": len(matches),
                "cwe": pat_info["cwe"],
            },
            "remediation": pat_info["remediation"],
            "scanner": "JS-SourceAnalyzer",
            "ens_measure": pat_info["ens"],
        })
    return findings


def run_js_source_analysis(asset_id: int, target_url: str) -> List[Dict]:
    logger.info("JS_ANALYZER_START", target=target_url)

    html = _fetch_url(target_url)
    if not html:
        logger.warning("JS_ANALYZER_NO_HTML", target=target_url)
        return []

    parser = _ScriptSrcParser(target_url)
    try:
        parser.feed(html)
    except Exception:
        pass

    # Analizar el HTML completo (scripts inline y atributos)
    all_findings: List[Dict] = _scan_content(html, target_url + " [HTML-inline]")

    js_urls = parser.js_urls[:_MAX_JS_FILES]
    logger.info("JS_ANALYZER_SCRIPTS_FOUND", count=len(js_urls), target=target_url)

    for js_url in js_urls:
        js_content = _fetch_url(js_url)
        if js_content:
            all_findings.extend(_scan_content(js_content, js_url))

    # Deduplicar por (title, source_url)
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f["title"], f["evidence"].get("source_url", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    logger.info("JS_ANALYZER_FINISH", target=target_url, findings=len(deduped))
    return deduped
