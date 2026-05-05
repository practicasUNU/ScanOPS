import subprocess
import json
from shared.scan_logger import ScanLogger

logger = ScanLogger("nuclei_wrapper")

def run_nuclei_scan(target_ip: str):
    logger.info("NUCLEI_START", target=target_ip)

    NUCLEI_TEMPLATES = [
        "http/technologies/",
        "http/exposures/",
        "ssl/",
    ]

    cmd = [
        "nuclei",
        "-target", target_ip,
        "-silent",
        "-jsonl",
        "-timeout", "5",
        "-bulk-size", "10",
        "-rate-limit", "20",
        "-retries", "0",
    ]

    for template in NUCLEI_TEMPLATES:
        cmd.extend(["-t", template])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        findings = []
        if result.stdout:
            for line in result.stdout.splitlines():
                try:
                    raw_vuln = json.loads(line)
                    info = raw_vuln.get("info", {})
                    classification = info.get("classification", {})
                    cve_ids = classification.get("cve-id")
                    cve_str = ",".join(cve_ids) if isinstance(cve_ids, list) else ""
                    findings.append({
                        "title": info.get("name"),
                        "severity": info.get("severity", "").upper(),
                        "description": info.get("description") or info.get("name"),
                        "cve_id": cve_str,
                        "evidence": raw_vuln.get("matched-at"),
                        "ens_measure": "op.exp.2"
                    })
                except json.JSONDecodeError:
                    continue
        logger.info("NUCLEI_FINISH", target=target_ip, count=len(findings))
        return findings
    except subprocess.TimeoutExpired:
        logger.error("NUCLEI_TIMEOUT", target=target_ip)
        return []
    except Exception as e:
        logger.error("NUCLEI_ERROR", target=target_ip, error=str(e))
        return []