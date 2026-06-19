import subprocess
import json
import os
from shared.scan_logger import ScanLogger

logger = ScanLogger("nuclei_wrapper")

# Templates: technologies para fingerprint rápido, misconfiguration para hallazgos relevantes.
# Se excluyen directorios muy lentos (fuzzing/, passive/) para mantener el escaneo ágil.
NUCLEI_TEMPLATES = [
    "http/technologies/",
    "http/misconfiguration/",
    "http/exposures/",
    "/app/templates/nuclei/custom/",
]

# Remediaciones por tipo de finding
NUCLEI_REMEDIATIONS = {
    "missing-security-headers": "Add the missing HTTP security header to prevent common web attacks.",
    "http-missing-security-headers": "Configure the web server to include all recommended security headers.",
    "ssl-dns-names": "Verify SSL certificate covers all required domain names.",
    "self-signed-certificate": "Replace self-signed certificate with one issued by a trusted CA.",
    "expired-ssl-certificate": "Renew the SSL/TLS certificate immediately.",
    "tls-version": "Disable TLS 1.0 and 1.1. Configure TLS 1.2 minimum.",
    "weak-cipher-suites": "Remove weak cipher suites. Use ECDHE and AES-GCM.",
    "phpinfo": "Remove or restrict access to phpinfo() pages. They disclose sensitive server configuration.",
    "php-errors": "Disable PHP error display in production. Set display_errors = Off in php.ini.",
    "apache-detect": "Consider hiding Apache version information (ServerTokens Prod in httpd.conf).",
    "nginx-version": "Hide nginx version (server_tokens off in nginx.conf).",
    "waf-detect": "WAF detected. Verify WAF rules are properly configured.",
    "wordpress": "Keep WordPress core, themes and plugins updated. Use security hardening plugins.",
    "default-login": "Change all default credentials immediately.",
    "exposed-panels": "Restrict access to administrative panels with IP whitelist and strong authentication.",
    "ssh-weakalgorithm": "Disable weak SSH algorithms. Use Ed25519 or RSA-4096 keys.",
    "openssh": "Keep OpenSSH updated to latest stable version.",
    "http-cors-misconfig": "Review CORS policy. Avoid wildcard (*) origins in production.",
}

def _get_remediation(template_id: str, matcher_name: str, description: str) -> str:
    """Obtiene remediación específica para el finding."""
    for key, remediation in NUCLEI_REMEDIATIONS.items():
        if key in template_id.lower() or key in matcher_name.lower():
            return remediation

    desc_lower = description.lower()
    if "header" in desc_lower:
        return "Add the missing HTTP security header to your web server configuration."
    if "ssl" in desc_lower or "tls" in desc_lower or "certificate" in desc_lower:
        return "Review SSL/TLS configuration and ensure proper certificate management."
    if "version" in desc_lower or "detect" in desc_lower:
        return "Keep software updated to latest stable version and minimize version disclosure."
    if "default" in desc_lower:
        return "Remove or restrict access to default pages and change default credentials."

    return "Review this finding and apply appropriate security controls per OWASP guidelines."

def _get_professional_title(template_id: str, matcher_name: str, info_name: str) -> str:
    """Genera un título profesional y descriptivo."""
    if "tech-detect" in template_id and matcher_name:
        return f"Technology Detected: {matcher_name.title()}"
    if "wappalyzer" in template_id.lower() and matcher_name:
        return f"Technology Fingerprint: {matcher_name.title()}"
    if "apache" in template_id.lower():
        return "Apache Web Server Detected and Version Disclosed"
    if "nginx" in template_id.lower():
        return "Nginx Web Server Detected and Version Disclosed"
    if "php" in template_id.lower():
        return "PHP Application Detected"
    if "wordpress" in template_id.lower():
        return "WordPress CMS Detected"
    if "missing-security-headers" in template_id.lower() or "http-missing-security-headers" in template_id.lower():
        header_name = matcher_name.replace("-", " ").title() if matcher_name else "Security Header"
        return f"Missing HTTP Security Header: {header_name}"
    if "ssl" in template_id.lower() or "tls" in template_id.lower():
        return f"SSL/TLS Issue: {info_name}"
    if "phpinfo" in template_id.lower():
        return "PHP Configuration Page Exposed (phpinfo)"
    if "self-signed" in template_id.lower():
        return "Self-Signed SSL Certificate Detected"
    if "expired" in template_id.lower():
        return "Expired SSL Certificate Detected"
    if "waf-detect" in template_id.lower():
        return f"Web Application Firewall Detected: {matcher_name.title() if matcher_name else 'Unknown'}"
    if "openssh" in template_id.lower():
        return "OpenSSH Service Detected"

    if info_name and info_name != "Unknown":
        return info_name
    return template_id.replace("-", " ").replace("/", " - ").title()

def _resolves(host: str) -> bool:
    """True si el hostname resuelve por DNS desde este contenedor."""
    import socket
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


def run_nuclei_scan(target_ip: str, hostname: str = None):
    logger.info("NUCLEI_START", target=target_ip)

    # Siempre escaneamos por IP: el contenedor del worker no resuelve los
    # hostnames internos de los assets, así que apuntar a la IP evita que
    # nuclei agote el timeout completo intentando resolver un host inexistente.
    targets = [f"http://{target_ip}", f"https://{target_ip}"]

    # Si el hostname resuelve y es distinto de la IP, lo inyectamos como
    # cabecera Host para virtual-hosting sin depender de DNS para el destino.
    host_header = None
    if hostname and hostname != target_ip and _resolves(hostname):
        host_header = hostname

    logger.info("NUCLEI_TARGETS", targets=targets, host_header=host_header)

    output_file = f"/tmp/nuclei_output_{os.getpid()}.jsonl"

    cmd = [
        "nuclei",
        "-silent",
        "-jsonl",
        "-output", output_file,
        "-duc",
        "-timeout", "10",
        "-bulk-size", "10",
        "-rate-limit", "30",
        "-retries", "0",
        "-max-host-error", "5",
        "-no-interactsh",
        "-follow-redirects",
        "-nh",
    ]

    for template in NUCLEI_TEMPLATES:
        cmd.extend(["-t", template])

    if host_header:
        cmd.extend(["-H", f"Host: {host_header}"])

    for target in targets:
        cmd.extend(["-u", target])

    env = os.environ.copy()
    env.setdefault("HOME", "/root")

    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            env=env,
        )

        findings = []
        seen = set()

        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw_vuln = json.loads(line)
                        info = raw_vuln.get("info", {})
                        template_id = raw_vuln.get("template-id", "")
                        matcher_name = raw_vuln.get("matcher-name", "")
                        matched_at = raw_vuln.get("matched-at", "")
                        extracted = raw_vuln.get("extracted-results", [])

                        classification = info.get("classification", {})
                        cve_ids = classification.get("cve-id")
                        cve_str = ",".join(cve_ids) if isinstance(cve_ids, list) else (cve_ids or "")

                        severity_raw = info.get("severity", "info").upper()
                        severity = severity_raw if severity_raw in ("CRITICAL","HIGH","MEDIUM","LOW","INFO") else "INFO"

                        info_name = info.get("name", "Unknown")
                        description = info.get("description") or info_name

                        if extracted:
                            description = f"{description} | Detected: {', '.join(str(e) for e in extracted[:5])}"

                        title = _get_professional_title(template_id, matcher_name, info_name)
                        remediation = _get_remediation(template_id, matcher_name, description)

                        dedup_key = (title, matched_at)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        _cvss_raw = info.get("classification", {}).get("cvss-score")
                        try:
                            _cvss = float(_cvss_raw) if _cvss_raw is not None else None
                        except (ValueError, TypeError):
                            _cvss = None

                        findings.append({
                            "title": title,
                            "severity": severity,
                            "description": description,
                            "cve_id": cve_str,
                            "cvss_score": _cvss,
                            "evidence": matched_at,
                            "remediation": remediation,
                            "ens_measure": "op.exp.2"
                        })
                    except json.JSONDecodeError:
                        continue
            os.remove(output_file)

        logger.info("NUCLEI_FINISH", target=target_ip, count=len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.error("NUCLEI_TIMEOUT", target=target_ip)
        if os.path.exists(output_file):
            os.remove(output_file)
        return []
    except FileNotFoundError:
        logger.error("NUCLEI_NOT_FOUND")
        return []
    except Exception as e:
        logger.error("NUCLEI_ERROR", target=target_ip, error=str(e))
        if os.path.exists(output_file):
            os.remove(output_file)
        return []
