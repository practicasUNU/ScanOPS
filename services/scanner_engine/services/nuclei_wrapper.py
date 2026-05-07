import subprocess
import json
import os
from shared.scan_logger import ScanLogger

logger = ScanLogger("nuclei_wrapper")

NUCLEI_TEMPLATES = [
    "http/technologies/tech-detect.yaml",
]

def run_nuclei_scan(target_ip: str, hostname: str = None):
    logger.info("NUCLEI_START", target=target_ip)

    if hostname and hostname != target_ip:
        targets = [f"https://{hostname}"]
    else:
        targets = [f"https://{target_ip}", f"http://{target_ip}"]

    logger.info("NUCLEI_TARGETS", targets=targets)

    cmd = [
        "nuclei",
        "-silent",
        "-jsonl",
        "-duc",           # disable update check — sin esto Nuclei cuelga conectando a GitHub
        "-timeout", "8",
        "-bulk-size", "5",
        "-rate-limit", "10",
        "-retries", "0",
        "-max-host-error", "3",
        "-no-interactsh",
        "-follow-redirects",
    ]

    for template in NUCLEI_TEMPLATES:
        cmd.extend(["-t", template])

    for target in targets:
        cmd.extend(["-u", target])

    # Entorno explícito: evita que el proceso hijo herede variables corruptas del fork de Celery
    env = os.environ.copy()
    env.setdefault("HOME", "/root")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
            env=env,
            start_new_session=True,  # nueva sesión: no hereda signal mask del worker Celery prefork
        )
        findings = []

        output = result.stdout or ""
        if not output and result.stderr:
            logger.warning("NUCLEI_NO_STDOUT", stderr=result.stderr[:500])

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw_vuln = json.loads(line)
                info = raw_vuln.get("info", {})
                classification = info.get("classification", {})
                cve_ids = classification.get("cve-id")
                cve_str = ",".join(cve_ids) if isinstance(cve_ids, list) else (cve_ids or "")
                severity = info.get("severity", "info").upper()
                findings.append({
                    "title": info.get("name", raw_vuln.get("template-id", "Unknown")),
                    "severity": severity if severity in ("CRITICAL","HIGH","MEDIUM","LOW","INFO") else "INFO",
                    "description": info.get("description") or info.get("name", ""),
                    "cve_id": cve_str,
                    "evidence": raw_vuln.get("matched-at", ""),
                    "remediation": info.get("remediation", "Review Nuclei finding."),
                    "ens_measure": "op.exp.2"
                })
            except json.JSONDecodeError:
                continue

        logger.info("NUCLEI_FINISH", target=target_ip, count=len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.error("NUCLEI_TIMEOUT", target=target_ip)
        return []
    except FileNotFoundError:
        logger.error("NUCLEI_NOT_FOUND")
        return []
    except Exception as e:
        logger.error("NUCLEI_ERROR", target=target_ip, error=str(e))
        return []
