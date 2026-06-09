"""
ffuf Client - Directory/Endpoint Fuzzing - Scanner Engine M3
Busca rutas ocultas, paneles de administración y endpoints no documentados.
"""

import subprocess
import json
import os
from typing import List, Dict

from shared.scan_logger import ScanLogger

logger = ScanLogger("ffuf_client")

SENSITIVE_PATTERNS = {"admin", "backup", ".env", ".git", "sql", "config", "swagger", "actuator", "phpinfo"}

FALLBACK_WORDLIST = [
    "admin", "login", "backup", ".env", ".git/HEAD", "wp-admin", "api", "api/v1", "api/v2",
    "console", "phpmyadmin", "phpinfo.php", "config.php", ".htaccess", "robots.txt",
    "sitemap.xml", "swagger.json", "openapi.json", "actuator", "actuator/health",
    "actuator/env", "manager/html", "server-status", "server-info", "test", "debug",
    "old", "tmp", "upload", "uploads", "files", "static/admin", "admin/config",
    "backup.zip", "backup.sql", "db.sql", "config.bak", "web.config", "crossdomain.xml",
]

WORDLIST_PATH = "/usr/share/wordlists/ffuf_web.txt"


def _is_sensitive_path(url: str) -> bool:
    url_lower = url.lower()
    return any(p in url_lower for p in SENSITIVE_PATTERNS)


def _assign_severity(status: int, url: str) -> str:
    if status in (200, 201):
        return "HIGH" if _is_sensitive_path(url) else "MEDIUM"
    if status == 403:
        return "LOW"
    return "INFO"


REDIRECT_CONSOLIDATION_THRESHOLD = 5


def _consolidate_redirects(findings: List[Dict], target_url: str) -> List[Dict]:
    redirect_findings = [f for f in findings if f["evidence"]["status"] in (301, 302)]
    non_redirect_findings = [f for f in findings if f["evidence"]["status"] not in (301, 302)]

    if len(redirect_findings) >= REDIRECT_CONSOLIDATION_THRESHOLD:
        consolidated = {
            "title": "Global HTTP Redirect Detected (Possible HTTPS Enforcement)",
            "severity": "INFO",
            "description": (
                f"{len(redirect_findings)} endpoints returned 301/302 redirects. "
                "The server likely enforces HTTPS globally. "
                "Run testssl and whatweb against the HTTPS target for full coverage."
            ),
            "cve_id": None,
            "evidence": {
                "redirect_count": len(redirect_findings),
                "sample_urls": [f["evidence"]["url"] for f in redirect_findings[:3]],
                "target": target_url,
            },
            "remediation": "Verify HTTPS redirect is enforced with HSTS header (Strict-Transport-Security).",
            "ens_measure": "op.exp.2",
            "scanner": "ffuf",
        }
        return non_redirect_findings + [consolidated]

    return findings


def _ensure_wordlist() -> str:
    if os.path.exists(WORDLIST_PATH):
        return WORDLIST_PATH
    tmp_wl = f"/tmp/ffuf_wordlist_{os.getpid()}.txt"
    with open(tmp_wl, "w") as f:
        f.write("\n".join(FALLBACK_WORDLIST) + "\n")
    return tmp_wl


def run_ffuf_scan(asset_id: int, target_url: str) -> List[Dict]:
    logger.info("FFUF_START", target=target_url)
    output_file = f"/tmp/ffuf_output_{os.getpid()}.json"
    tmp_wordlist = None

    try:
        wordlist = _ensure_wordlist()
        if wordlist != WORDLIST_PATH:
            tmp_wordlist = wordlist

        cmd = [
            "ffuf",
            "-u", f"{target_url}/FUZZ",
            "-w", wordlist,
            "-mc", "200,201,204,301,302,403",
            "-t", "10",
            "-timeout", "5",
            "-o", output_file,
            "-of", "json",
            "-s",
        ]

        subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                try:
                    raw = f.read().strip()
                    if not raw:
                        logger.warning("FFUF_EMPTY_OUTPUT", target=target_url)
                        return []
                    data = json.loads(raw)
                    results = data.get("results", [])
                    for r in results:
                        url = r.get("url", "")
                        status = r.get("status", 0)
                        length = r.get("length", 0)
                        severity = _assign_severity(status, url)
                        path = url.replace(target_url, "").lstrip("/")
                        findings.append({
                            "title": f"Exposed Endpoint: /{path}",
                            "severity": severity,
                            "description": f"Endpoint /{path} returned HTTP {status}.",
                            "cve_id": None,
                            "evidence": {"url": url, "status": status, "length": length},
                            "remediation": "Restrict access to this endpoint with authentication, IP whitelisting, or remove if not needed.",
                            "ens_measure": "op.exp.2",
                            "scanner": "ffuf",
                        })
                except json.JSONDecodeError:
                    logger.error("FFUF_JSON_ERROR", target=target_url)

        findings = _consolidate_redirects(findings, target_url)
        logger.info("FFUF_FINISH", target=target_url, count=len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.error("FFUF_TIMEOUT", target=target_url)
        return []
    except FileNotFoundError:
        logger.error("FFUF_NOT_FOUND", target=target_url)
        return []
    except Exception as e:
        logger.error("FFUF_ERROR", target=target_url, error=str(e))
        return []
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)
        if tmp_wordlist and os.path.exists(tmp_wordlist):
            os.remove(tmp_wordlist)
