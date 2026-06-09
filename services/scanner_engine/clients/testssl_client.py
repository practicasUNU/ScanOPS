"""
testssl Client - TLS/SSL Deep Analysis - Scanner Engine M3
Detecta: BEAST, POODLE, Heartbleed, ROBOT, cipher suites débiles, versiones TLS inseguras.
Cumple ENS Alto mp.com.2 (protección de comunicaciones).
"""

import subprocess
import json
import os
import re
from typing import List, Dict
from urllib.parse import urlparse

from shared.scan_logger import ScanLogger

logger = ScanLogger("testssl_client")

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "NOT_TESTED": "INFO",
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _parse_target(target_url: str):
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url
    if parsed.scheme == "https":
        port = parsed.port or 443
    else:
        port = parsed.port or 80
    return host, port


def _extract_cve(finding_text: str) -> str | None:
    match = CVE_PATTERN.search(finding_text)
    return match.group(0).upper() if match else None


def run_testssl_scan(asset_id: int, target_url: str) -> List[Dict]:
    logger.info("TESTSSL_START", target=target_url)
    output_file = f"/tmp/testssl_output_{os.getpid()}.json"
    target_host, port = _parse_target(target_url)

    try:
        cmd = [
            "testssl.sh",
            f"--jsonfile={output_file}",
            "--quiet",
            "--nodns", "min",
            "--severity", "LOW",
            f"{target_host}:{port}",
        ]

        subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                try:
                    raw = f.read().strip()
                    if not raw:
                        logger.warning("TESTSSL_EMPTY_OUTPUT", target=target_url)
                        return []
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        items = data.get("findings", data.get("results", []))
                    else:
                        items = data

                    for item in items:
                        testssl_severity = item.get("severity", "INFO").upper()
                        if testssl_severity == "OK":
                            continue
                        scanops_severity = SEVERITY_MAP.get(testssl_severity, "INFO")
                        finding_text = item.get("finding", "")
                        testssl_id = item.get("id", "unknown")
                        cve_id = _extract_cve(finding_text)
                        findings.append({
                            "title": testssl_id.replace("_", " ").title(),
                            "severity": scanops_severity,
                            "description": finding_text,
                            "cve_id": cve_id,
                            "evidence": {
                                "testssl_id": testssl_id,
                                "finding": finding_text,
                                "target": f"{target_host}:{port}",
                            },
                            "remediation": "Update TLS configuration: disable weak ciphers, enable TLS 1.2+, apply patches for known CVEs.",
                            "ens_measure": "mp.com.2",
                            "scanner": "testssl",
                        })
                except json.JSONDecodeError:
                    logger.error("TESTSSL_JSON_ERROR", target=target_url)

        logger.info("TESTSSL_FINISH", target=target_url, count=len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.error("TESTSSL_TIMEOUT", target=target_url)
        return []
    except FileNotFoundError:
        logger.error("TESTSSL_NOT_FOUND", target=target_url)
        return []
    except Exception as e:
        logger.error("TESTSSL_ERROR", target=target_url, error=str(e))
        return []
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)
