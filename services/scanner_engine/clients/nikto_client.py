import subprocess
import re
from typing import List, Dict
from shared.scan_logger import ScanLogger

logger = ScanLogger("nikto_client")

NIKTO_ID_MAP = {
    "013587": ("Missing Security Header", "MEDIUM"),
    "600050": ("Outdated Software Version Detected", "HIGH"),
    "000777": ("Potentially Dangerous HTTP Method Enabled", "HIGH"),
    "000398": ("Apache Default Files Exposed", "MEDIUM"),
    "000461": ("Directory Indexing Enabled", "MEDIUM"),
    "001166": ("SQL Injection Possible", "HIGH"),
    "000760": ("Cross-Site Scripting (XSS) Possible", "HIGH"),
    "000379": ("PHP Information Disclosure", "HIGH"),
    "001232": ("Backup File Exposed", "MEDIUM"),
    "000001": ("Web Server Version Disclosure", "LOW"),
}

NIKTO_CVSS_MAP = {
    "CVE-2017-9798": 7.5,
    "CVE-2019-0211": 7.8,
    "strict-transport-security": 7.4,
    "content-security-policy": 6.1,
    "x-frame-options": 6.1,
    "x-content-type-options": 5.3,
    "referrer-policy": 3.1,
    "permissions-policy": 3.1,
    "missing security header": 5.3,
    "outdated software": 7.5,
    "dangerous http method": 6.5,
    "directory indexing": 5.3,
    "sql injection": 9.8,
    "cross-site scripting": 6.1,
    "php information": 5.3,
    "backup file": 5.3,
    "web server version": 5.3,
    "_CRITICAL": 9.0,
    "_HIGH": 7.5,
    "_MEDIUM": 5.0,
    "_LOW": 3.1,
    "_INFO": 0.0,
}


def _resolve_nikto_cvss(cve_id: str, title: str, severity: str) -> float:
    if cve_id and cve_id in NIKTO_CVSS_MAP:
        return NIKTO_CVSS_MAP[cve_id]
    title_lower = title.lower()
    for keyword, score in NIKTO_CVSS_MAP.items():
        if keyword.startswith("_"):
            continue
        if keyword in title_lower:
            return score
    return NIKTO_CVSS_MAP.get(f"_{severity.upper()}", 0.0)


def _classify_nikto_finding(nikto_id: str, msg: str) -> tuple:
    if nikto_id in NIKTO_ID_MAP:
        base_title, base_severity = NIKTO_ID_MAP[nikto_id]
    else:
        base_title = "Web Vulnerability Finding"
        base_severity = "MEDIUM"

    msg_upper = msg.upper()
    if any(w in msg_upper for w in ["CRITICAL", "REMOTE CODE", "RCE", "SQL INJECTION", "SQLI"]):
        base_severity = "CRITICAL"
    elif any(w in msg_upper for w in ["XSS", "CROSS-SITE", "INJECTION", "TRAVERSAL", "BACKDOOR", "SHELL"]):
        base_severity = "HIGH"
    elif any(w in msg_upper for w in ["OUTDATED", "OLD VERSION", "DEPRECATED", "INSECURE"]):
        base_severity = "HIGH"
    elif any(w in msg_upper for w in ["MISSING", "HEADER", "CSRF", "CLICKJACK"]):
        base_severity = "MEDIUM"
    elif any(w in msg_upper for w in ["INFORMATION", "DISCLOSURE", "VERSION"]):
        base_severity = "LOW"

    if "MISSING" in msg_upper and "HEADER" in msg_upper:
        header_match = re.search(r"missing:\s*([a-z0-9\-]+)", msg, re.IGNORECASE)
        if header_match:
            base_title = f"Missing Security Header: {header_match.group(1)}"

    return base_title, base_severity


def _extract_cve(msg: str) -> str:
    cve_match = re.search(r"CVE-\d{4}-\d+", msg, re.IGNORECASE)
    return cve_match.group(0).upper() if cve_match else ""


def _get_remediation(nikto_id: str, msg: str) -> str:
    msg_upper = msg.upper()
    if "STRICT-TRANSPORT-SECURITY" in msg_upper or "HSTS" in msg_upper:
        return "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
    if "CONTENT-SECURITY-POLICY" in msg_upper or "CSP" in msg_upper:
        return "Implement Content-Security-Policy header to prevent XSS and data injection attacks."
    if "X-FRAME-OPTIONS" in msg_upper:
        return "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header to prevent clickjacking attacks."
    if "X-CONTENT-TYPE" in msg_upper:
        return "Add 'X-Content-Type-Options: nosniff' header to prevent MIME type sniffing."
    if "REFERRER-POLICY" in msg_upper:
        return "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."
    if "PERMISSIONS-POLICY" in msg_upper:
        return "Add Permissions-Policy header to control browser features and APIs."
    if "OUTDATED" in msg_upper or "OLD VERSION" in msg_upper:
        return "Update server software to the latest stable version."
    if "DIRECTORY" in msg_upper and "INDEX" in msg_upper:
        return "Disable directory listing in web server configuration (Apache: Options -Indexes)."
    if "METHOD" in msg_upper and ("PUT" in msg_upper or "DELETE" in msg_upper or "TRACE" in msg_upper):
        return "Disable dangerous HTTP methods (PUT, DELETE, TRACE) in web server configuration."
    return "Review and remediate this finding according to OWASP security best practices."


# Parses nikto plain-text stdout lines like:
#   + [013587] /path: message text
#   + message without id
_NIKTO_LINE_RE = re.compile(r"^\+\s+(?:\[(\d+)\]\s+)?(/[^\s:]*)?\s*:?\s*(.*)")


def run_nikto_scan(asset_id: int, target_url: str) -> List[Dict]:
    logger.info("NIKTO_START", target=target_url)

    cmd = [
        "nikto",
        "-h", target_url,
        "-Tuning", "1234578",
        "-timeout", "10",
        "-nointeractive",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        stdout = result.stdout or ""
        findings = []
        seen = set()

        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            # skip header/separator lines
            if line.startswith("+ -") or "Start Time" in line or "Target" in line:
                continue
            if "No CGI" in line or "Nikto" in line or line == "+":
                continue

            m = _NIKTO_LINE_RE.match(line)
            if not m:
                continue

            nikto_id = m.group(1) or "UNKNOWN"
            url_path = m.group(2) or "/"
            msg = m.group(3).strip()
            if not msg:
                continue

            dedup_key = (nikto_id, msg[:100])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            title, severity = _classify_nikto_finding(nikto_id, msg)
            cve_id = _extract_cve(msg)
            if cve_id:
                severity = "HIGH"
            remediation = _get_remediation(nikto_id, msg)

            findings.append({
                "title": title,
                "severity": severity,
                "description": msg,
                "cve_id": cve_id if cve_id else None,
                "cvss_score": _resolve_nikto_cvss(cve_id, title, severity),
                "evidence": {
                    "nikto_id": nikto_id,
                    "url": url_path,
                    "method": "GET",
                    "target": target_url,
                    "references": "",
                },
                "remediation": remediation,
                "scanner": "Nikto",
                "ens_measure": "op.exp.2",
            })

        if not findings:
            logger.warning("NIKTO_EMPTY_OUTPUT", target=target_url)

        logger.info("NIKTO_FINISH", target=target_url, count=len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.error("NIKTO_TIMEOUT", target=target_url)
        return []
    except FileNotFoundError:
        logger.error("NIKTO_NOT_FOUND", target=target_url)
        return []
    except Exception as e:
        logger.error("NIKTO_ERROR", target=target_url, error=str(e))
        return []
