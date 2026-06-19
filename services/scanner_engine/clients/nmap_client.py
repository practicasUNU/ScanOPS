"""
Nmap NSE Client - Scanner Engine M3
Escaneo profesional de vulnerabilidades usando Nmap con scripts NSE.
"""

import subprocess
import re
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)

# Versiones con vulnerabilidades conocidas — severidad HIGH o CRITICAL
VULNERABLE_VERSIONS = {
    "OpenSSH": [
        ("7.", "HIGH", "OpenSSH < 8.0 may be vulnerable to username enumeration (CVE-2018-15473)"),
        ("8.0", "MEDIUM", "OpenSSH 8.0 has known vulnerabilities, consider upgrading to 8.9+"),
        ("8.1", "MEDIUM", "OpenSSH 8.1 has known vulnerabilities, consider upgrading to 8.9+"),
        ("8.2", "MEDIUM", "OpenSSH 8.2 is affected by CVE-2023-38408 (ssh-agent forwarding RCE)"),
        ("8.3", "MEDIUM", "OpenSSH 8.3 has known vulnerabilities"),
        ("8.4", "MEDIUM", "OpenSSH 8.4 has known vulnerabilities"),
    ],
    "Apache httpd": [
        ("2.4.49", "CRITICAL", "Apache 2.4.49 is vulnerable to Path Traversal RCE (CVE-2021-41773)"),
        ("2.4.50", "CRITICAL", "Apache 2.4.50 is vulnerable to Path Traversal RCE (CVE-2021-42013)"),
        ("2.4.41", "MEDIUM", "Apache 2.4.41 has multiple known CVEs. Upgrade to 2.4.58+"),
        ("2.4.3", "HIGH", "Apache 2.4.3x series has multiple HIGH severity CVEs"),
        ("2.2.", "HIGH", "Apache 2.2.x is End-of-Life and has numerous unpatched vulnerabilities"),
    ],
    "nginx": [
        ("1.14", "MEDIUM", "nginx 1.14.x has known vulnerabilities (CVE-2019-9511)"),
        ("1.16", "MEDIUM", "nginx 1.16.x has known vulnerabilities"),
    ],
    "MySQL": [
        ("5.5", "HIGH", "MySQL 5.5.x is End-of-Life with unpatched vulnerabilities"),
        ("5.6", "HIGH", "MySQL 5.6.x is End-of-Life with unpatched vulnerabilities"),
        ("5.7", "MEDIUM", "MySQL 5.7.x reaching End-of-Life, multiple CVEs exist"),
    ],
    "OpenSSL": [
        ("1.0", "CRITICAL", "OpenSSL 1.0.x is End-of-Life and vulnerable to Heartbleed and others"),
        ("1.1.0", "HIGH", "OpenSSL 1.1.0 is End-of-Life"),
        ("3.0.0", "HIGH", "OpenSSL 3.0.0-3.0.6 vulnerable to Critical CVE-2022-3786 and CVE-2022-3602"),
    ],
}

# Servicios peligrosos expuestos
DANGEROUS_SERVICES = {
    "23": ("Telnet Service Exposed", "HIGH",
           "Telnet transmits data in plaintext including credentials. Disable immediately.",
           "CVE-1999-0528"),
    "21": ("FTP Service Exposed", "MEDIUM",
           "FTP may transmit credentials in plaintext. Consider using SFTP or FTPS.",
           ""),
    "445": ("SMB Service Exposed", "HIGH",
            "SMB exposed to network may be vulnerable to EternalBlue and ransomware attacks.",
            "CVE-2017-0144"),
    "3389": ("RDP Service Exposed", "HIGH",
             "RDP exposed to network is a common attack vector. Restrict access with firewall.",
             "CVE-2019-0708"),
    "3306": ("MySQL Database Exposed", "HIGH",
             "MySQL database port exposed. Database should not be accessible from untrusted networks.",
             ""),
    "27017": ("MongoDB Exposed (No Auth)", "CRITICAL",
              "MongoDB may be exposed without authentication. Critical data exposure risk.",
              ""),
}

NMAP_CVSS_MAP = {
    "CVE-2021-41773": 9.8,
    "CVE-2021-42013": 9.8,
    "CVE-2018-15473": 5.3,
    "CVE-2023-38408": 9.8,
    "CVE-2019-9511":  7.5,
    "CVE-2017-0144":  8.1,
    "CVE-2019-0708":  9.8,
    "CVE-1999-0528":  7.5,
    "CVE-2022-3786":  7.5,
    "CVE-2022-3602":  7.5,
    "_CRITICAL": 9.0,
    "_HIGH":     7.5,
    "_MEDIUM":   5.0,
    "_LOW":      3.1,
    "_INFO":     0.0,
}


def _resolve_cvss(cve_id: str, severity: str) -> float:
    """Devuelve CVSS: primero busca por CVE, luego fallback por severidad."""
    if cve_id and cve_id in NMAP_CVSS_MAP:
        return NMAP_CVSS_MAP[cve_id]
    fallback_key = f"_{severity.upper()}"
    return NMAP_CVSS_MAP.get(fallback_key, 0.0)


def _check_version_vulnerabilities(product: str, version: str, port_id: str) -> List[Dict]:
    """Detecta versiones vulnerables conocidas y genera findings."""
    findings = []
    for software, vuln_list in VULNERABLE_VERSIONS.items():
        if software.lower() in product.lower():
            for version_prefix, severity, description in vuln_list:
                if version.startswith(version_prefix):
                    cve_match = re.search(r"CVE-\d{4}-\d+", description)
                    cve_id = cve_match.group(0) if cve_match else None
                    findings.append({
                        "title": f"Vulnerable Version: {product} {version}",
                        "severity": severity,
                        "description": description,
                        "cve_id": cve_id,
                        "cvss_score": _resolve_cvss(cve_id or "", severity),
                        "evidence": {"host": "", "port": port_id, "product": product, "version": version},
                        "remediation": f"Upgrade {software} to the latest stable version immediately.",
                        "scanner": "Nmap",
                        "ens_measure": "op.exp.2"
                    })
                    break
    return findings

def _classify_script_output(script_id: str, output: str, port_id: str, asset_ip: str, protocol: str) -> Dict:
    """Genera un finding profesional a partir del output de un script NSE."""
    severity = "INFO"
    cve_id = ""
    remediation = "Review this finding and apply appropriate security controls."

    cve_match = re.search(r"CVE-\d{4}-\d+", output, re.IGNORECASE)
    if cve_match:
        cve_id = cve_match.group(0).upper()
        severity = "HIGH"

    if script_id == "ssl-enum-ciphers":
        if "NULL" in output or "EXPORT" in output or "SSLv2" in output or "SSLv3" in output:
            severity = "CRITICAL"
            remediation = "Disable NULL, EXPORT, SSLv2, SSLv3 ciphers immediately. Configure TLS 1.2+ with strong cipher suites."
        elif "TLSv1.0" in output or "TLSv1.1" in output:
            severity = "HIGH"
            remediation = "Disable TLS 1.0 and TLS 1.1. Configure server to use TLS 1.2 minimum (TLS 1.3 recommended)."
        elif "WEAK" in output.upper() or "RC4" in output or "DES" in output or "3DES" in output:
            severity = "HIGH"
            remediation = "Remove weak cipher suites (RC4, DES, 3DES). Use ECDHE and AES-GCM cipher suites."
        else:
            severity = "INFO"
        title = f"SSL/TLS Cipher Configuration on port {port_id}"

    elif script_id == "ssl-cert":
        if "EXPIRED" in output.upper():
            severity = "HIGH"
            remediation = "Renew the SSL/TLS certificate immediately. Expired certificates break trust and may expose users to MITM attacks."
            title = f"Expired SSL Certificate on port {port_id}"
        elif "SELF SIGNED" in output.upper() or "self-signed" in output.lower():
            severity = "MEDIUM"
            remediation = "Replace self-signed certificate with one issued by a trusted Certificate Authority (CA)."
            title = f"Self-Signed SSL Certificate on port {port_id}"
        else:
            cert_match = re.search(r"Subject: (.*)", output)
            subject = cert_match.group(1).strip() if cert_match else "Unknown"
            title = f"SSL Certificate Info: {subject}"
            severity = "INFO"
            remediation = "Verify certificate validity, expiration date, and issuing CA."

    elif script_id == "http-headers":
        missing_headers = []
        security_headers = [
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options",
            "referrer-policy", "permissions-policy"
        ]
        for h in security_headers:
            if h not in output.lower():
                missing_headers.append(h)
        if missing_headers:
            severity = "MEDIUM"
            title = f"Missing Security Headers on port {port_id}"
            remediation = f"Add the following security headers: {', '.join(missing_headers)}"
        else:
            title = f"HTTP Headers on port {port_id}"
            severity = "INFO"
            remediation = "Security headers appear to be configured."

    elif script_id == "ssh-hostkey":
        if "1024" in output:
            severity = "HIGH"
            title = "Weak SSH Host Key (1024-bit RSA)"
            remediation = "Regenerate SSH host keys with minimum 2048-bit RSA or use Ed25519 keys."
        else:
            title = f"SSH Host Key Information on port {port_id}"
            severity = "INFO"
            remediation = "Verify SSH host keys match expected fingerprints to prevent MITM attacks."

    elif script_id == "banner":
        if any(w in output.lower() for w in ["apache", "nginx", "iis", "openssh", "ftp", "smtp"]):
            severity = "LOW"
            title = f"Service Banner Disclosure on port {port_id}"
            remediation = "Configure server to suppress or minimize banner information to reduce attack surface."
        else:
            title = f"Service Banner on port {port_id}"
            severity = "INFO"
            remediation = "Review banner information disclosure."

    elif script_id == "http-server-header":
        severity = "LOW"
        title = f"Server Header Disclosure on port {port_id}"
        remediation = "Configure web server to suppress version information in Server header (Apache: ServerTokens Prod)."

    else:
        title = f"NSE Finding: {script_id} on port {port_id}"
        if "VULNERABLE" in output.upper() or "EXPLOIT" in output.upper():
            severity = "HIGH"
            remediation = "This service appears to be vulnerable. Apply patches immediately."
        elif "WARNING" in output.upper() or "WEAK" in output.upper():
            severity = "MEDIUM"
            remediation = "Review this security warning and apply appropriate hardening."

    return {
        "title": title,
        "severity": severity,
        "description": output[:800],
        "cve_id": cve_id if cve_id else None,
        "cvss_score": _resolve_cvss(cve_id, severity),
        "evidence": {"host": asset_ip, "port": port_id, "protocol": protocol, "script": script_id},
        "remediation": remediation,
        "scanner": "Nmap",
        "ens_measure": "op.exp.2"
    }

def run_nmap_scan(asset_id: int, asset_ip: str) -> List[Dict]:
    logger.info(f"NMAP_START target={asset_ip}")

    cmd = [
        "nmap",
        "-sV", "--version-intensity", "9",
        "--script", "vuln,banner,ssh-hostkey,http-headers,ssl-cert,ssl-enum-ciphers,http-server-header",
        "--script-timeout", "30s",
        "-T4",
        "-p", "21,22,23,25,80,443,445,3000,3306,3389,8080,8081,8082,8083,8443,8888,9000",
        "-oX", "-",
        asset_ip
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0 and not result.stdout:
            logger.error(f"NMAP_ERROR: {result.stderr[:300]}")
            return []

        findings = []
        seen_titles = set()
        root = ET.fromstring(result.stdout)

        for host in root.findall(".//host"):
            for port in host.findall(".//port"):
                port_id = port.attrib.get("portid", "")
                protocol = port.attrib.get("protocol", "tcp")
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue

                service = port.find("service")
                service_name = service.attrib.get("name", "") if service is not None else ""
                service_version = service.attrib.get("version", "") if service is not None else ""
                service_product = service.attrib.get("product", "") if service is not None else ""
                extra_info = service.attrib.get("extrainfo", "") if service is not None else ""
                ostype = service.attrib.get("ostype", "") if service is not None else ""

                # Infer HTTP for ports where nmap fingerprint shows HTTP traffic but service name is generic
                if service is not None and service_name not in ("http", "https", "http-alt", "http-proxy"):
                    servicefp = service.attrib.get("servicefp", "")
                    if "HTTP/" in servicefp or "HTTP/" in extra_info:
                        service_name = "http"
                        if not service_product:
                            service_product = "HTTP Service"

                if service_product:
                    full_version = f"{service_product} {service_version}".strip()
                    title = f"Open Service: {full_version} on port {port_id}/{protocol}"

                    version_findings = _check_version_vulnerabilities(service_product, service_version, port_id)
                    for vf in version_findings:
                        vf["evidence"]["host"] = asset_ip
                        dedup_key = (vf["title"], port_id)
                        if dedup_key not in seen_titles:
                            seen_titles.add(dedup_key)
                            findings.append(vf)

                    svc_severity = "INFO"
                    if port_id in DANGEROUS_SERVICES:
                        svc_title, svc_severity, svc_desc, svc_cve = DANGEROUS_SERVICES[port_id]
                        findings.append({
                            "title": svc_title,
                            "severity": svc_severity,
                            "description": f"{svc_desc} | Detected: {full_version} on {asset_ip}:{port_id}",
                            "cve_id": svc_cve if svc_cve else None,
                            "cvss_score": _resolve_cvss(svc_cve if svc_cve else "", svc_severity),
                            "evidence": {"host": asset_ip, "port": port_id, "protocol": protocol, "service": service_name},
                            "remediation": svc_desc,
                            "scanner": "Nmap",
                            "ens_measure": "op.exp.2"
                        })
                    else:
                        os_info = f" | OS: {ostype}" if ostype else ""
                        extra = f" | {extra_info}" if extra_info else ""
                        findings.append({
                            "title": title,
                            "severity": svc_severity,
                            "description": f"Service {service_name} running {full_version} detected on port {port_id}/{protocol}{os_info}{extra}",
                            "cve_id": None,
                            "cvss_score": _resolve_cvss("", svc_severity),
                            "evidence": {"host": asset_ip, "port": port_id, "protocol": protocol, "service": service_name, "version": full_version},
                            "remediation": f"Ensure {service_product} is updated to latest stable version and access is restricted to authorized hosts.",
                            "scanner": "Nmap",
                            "ens_measure": "op.exp.2"
                        })
                else:
                    # Port is open but nmap could not identify the service (e.g. ppp? on 3000).
                    # Emit a minimal finding so extract_http_ports can see this port in evidence.
                    display_service = service_name if service_name and service_name != "ppp" else "unknown"
                    findings.append({
                        "title": f"Open Port: {port_id}/{protocol} (unrecognized service)",
                        "severity": "INFO",
                        "description": f"Port {port_id}/{protocol} is open on {asset_ip}. Service fingerprint unrecognized by Nmap.",
                        "cve_id": None,
                        "cvss_score": 0.0,
                        "evidence": {"host": asset_ip, "port": port_id, "protocol": protocol, "service": display_service},
                        "remediation": "Investigate what service is running on this port and verify it is intended.",
                        "scanner": "Nmap",
                        "ens_measure": "op.exp.2"
                    })

                for script in port.findall("script"):
                    script_id = script.attrib.get("id", "")
                    script_output = script.attrib.get("output", "")

                    if not script_output or len(script_output.strip()) < 5:
                        continue
                    if "Couldn't find" in script_output or "ERROR" in script_output[:20]:
                        continue

                    finding = _classify_script_output(script_id, script_output, port_id, asset_ip, protocol)

                    dedup_key = (finding["title"], port_id)
                    if dedup_key not in seen_titles:
                        seen_titles.add(dedup_key)
                        findings.append(finding)

        logger.info(f"NMAP_FINISH target={asset_ip} count={len(findings)}")
        return findings

    except subprocess.TimeoutExpired:
        logger.error(f"NMAP_TIMEOUT target={asset_ip}")
        return []
    except FileNotFoundError:
        logger.error("NMAP_NOT_FOUND: nmap is not installed or not in PATH")
        return []
    except ET.ParseError as e:
        logger.error(f"NMAP_XML_PARSE_ERROR: {e}")
        return []
    except Exception as e:
        logger.error(f"NMAP_ERROR: {e}")
        return []


HTTP_SERVICE_NAMES = {"http", "http-alt", "http-proxy", "https", "www", "webcache"}
HTTP_PORTS_ALWAYS = {80, 443, 3000, 8080, 8081, 8082, 8083, 8443, 8888, 9000}


def extract_http_ports(nmap_findings: List[Dict]) -> List[int]:
    """Return open HTTP ports inferred from nmap findings evidence fields."""
    ports = set()
    for f in nmap_findings:
        evidence = f.get("evidence", {})
        port_str = evidence.get("port", "")
        service = evidence.get("service", "") or ""
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            continue
        if service.lower() in HTTP_SERVICE_NAMES or port in HTTP_PORTS_ALWAYS:
            ports.add(port)
    return sorted(ports)
