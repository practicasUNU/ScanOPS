"""
Celery tasks for vulnerability scanning orchestration — M3.
Flujo orquestado: OpenVAS + Nuclei + ZAP con merge de resultados y stats.
"""

import asyncio
import logging
import time
from typing import Dict, List, Any
from datetime import datetime
from celery import group, chord
from celery.exceptions import SoftTimeLimitExceeded

from shared.celery_app import app
from shared.database import SessionLocal
from shared.scan_logger import ScanLogger
from services.scanner_engine.models.vulnerability import VulnFinding
from services.scanner_engine.services.nuclei_wrapper import run_nuclei_scan as execute_nuclei_binary
from services.scanner_engine.clients.nmap_client import run_nmap_scan

logger = ScanLogger("scanner_tasks")

# --- TAREA: NUCLEI (US-3.2) ---
@app.task(name="tasks.run_nuclei_vulnerability_scan", queue="vulnerabilities")
def run_nuclei_task(asset_id: int, ip: str, hostname: str = None) -> List[Dict]:
    """Ejecuta Nuclei y devuelve hallazgos sin persistir (el orquestador persiste)."""
    logger.info("NUCLEI_TASK_START", asset_id=asset_id, target=ip)
    try:
        findings = execute_nuclei_binary(ip, hostname)
        return [{"scanner": "Nuclei", **f} for f in findings]
    except Exception as e:
        logger.error("NUCLEI_TASK_ERROR", error=str(e))
        return []

@app.task(name="tasks.run_nmap_vulnerability_scan", queue="vulnerabilities")
def run_nmap_task(asset_id: int, ip: str) -> List[Dict]:
    """Ejecuta Nmap NSE y devuelve hallazgos sin persistir."""
    logger.info("NMAP_TASK_START", asset_id=asset_id, target=ip)
    try:
        findings = run_nmap_scan(asset_id, ip)
        return findings
    except Exception as e:
        logger.error("NMAP_TASK_ERROR", error=str(e))
        return []

# --- TAREA: OPENVAS (US-3.1) ---
@app.task(name="scanner.openvas.scan_asset", queue="heavy_scans",
          time_limit=1800, soft_time_limit=1750)
def run_openvas_scan(asset_id: int, asset_ip: str, asset_name: str) -> List[Dict]:
    """Ejecuta OpenVAS real y devuelve hallazgos normalizados."""
    logger.info("OPENVAS_TASK_START", ip=asset_ip)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        from services.scanner_engine.clients.openvas_client import get_openvas_client
        client = loop.run_until_complete(get_openvas_client())
        findings = loop.run_until_complete(client.scan_asset(asset_id, asset_ip, asset_name))
        return [{"scanner": "OpenVAS", **f.to_dict()} for f in findings]
    except SoftTimeLimitExceeded:
        logger.error("OPENVAS_TASK_TIMEOUT", ip=asset_ip)
        return []
    except Exception as e:
        logger.error("OPENVAS_TASK_ERROR", error=str(e))
        return []
    finally:
        loop.close()


@app.task(name="tasks.run_nikto_vulnerability_scan", queue="vulnerabilities")
def run_nikto_task(asset_id: int, ip: str) -> List[Dict]:
    from services.scanner_engine.clients.nikto_client import run_nikto_scan
    logger.info("NIKTO_TASK_START", target=ip)
    try:
        target_url = f"http://{ip}"
        findings = run_nikto_scan(asset_id, target_url)
        return [{"scanner": "Nikto", **f} for f in findings]
    except Exception as e:
        logger.error("NIKTO_TASK_ERROR", error=str(e))
        return []

# --- CALLBACK: MERGE & PERSIST (US-3.4) ---
@app.task(name="tasks.merge_and_persist_results")
def merge_and_persist_results(results_list: List[List[Dict]], asset_id: int):
    """
    Recibe los resultados de todos los scanners, los une, persiste y genera stats.
    """
    all_findings = [finding for sublist in results_list for finding in sublist]
    db = SessionLocal()
    scan_id = f"scan_multi_{int(time.time())}"
    
    stats = {"total": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    try:
        for f in all_findings:
            severity = f.get("severity", "INFO").upper()
            raw_evidence = f.get("evidence", {})
            evidence = raw_evidence if isinstance(raw_evidence, dict) else {"raw": str(raw_evidence)}
            vuln = VulnFinding(
                asset_id=asset_id,
                scan_id=scan_id,
                vulnerability_id=(f.get("cve_id") or f.get("vulnerability_id") or "VULN_GENERIC")[:32],
                title=f.get("title", "Unknown Vulnerability")[:255],
                severity=severity[:16],
                description=f.get("description", ""),
                scanner_name=f.get("scanner", "Generic")[:32],
                evidence=evidence,
                created_by="system-orchestrator"
            )
            db.add(vuln)
            stats["total"] += 1
            if severity in stats:
                stats[severity] += 1
        
        db.commit()
        logger.info("SCAN_MERGE_COMPLETE", asset_id=asset_id, total=stats["total"])
        return {"status": "completed", "asset_id": asset_id, "scan_id": scan_id, "stats": stats}
    except Exception as e:
        db.rollback()
        logger.error("MERGE_PERSIST_ERROR", error=str(e))
        return {"status": "error", "message": str(e)}
    finally:
        db.close()

# --- ORQUESTADOR PARALELO (US-3.4) ---
@app.task(name="services.scanner_engine.tasks.vuln_tasks.scan_asset_parallel")
def scan_asset_parallel(asset_id: int, asset_ip: str, asset_name: str, scan_types: List[str] = None):
    """
    Lanza múltiples scanners en paralelo usando un Chord de Celery.
    Nuclei || OpenVAS || Nikto -> merge_and_persist_results
    """
    if not scan_types:
        scan_types = ["nuclei", "nmap", "nikto"]
    
    tasks = []
    if "nuclei" in scan_types:
        tasks.append(run_nuclei_task.s(asset_id, asset_ip, asset_name))
    if "openvas" in scan_types or "nmap" in scan_types:
        tasks.append(run_nmap_task.s(asset_id, asset_ip))
    if "nikto" in scan_types:
        tasks.append(run_nikto_task.s(asset_id, asset_ip))

    if not tasks:
        return {"status": "no_scans_selected"}

    # Ejecutar en paralelo y llamar al callback al finalizar
    workflow = chord(group(tasks))(merge_and_persist_results.s(asset_id))
    
    logger.info("PARALLEL_SCAN_ORCHESTRATED", asset_id=asset_id, scanners=scan_types, hostname=asset_name)
    return {"status": "parallel_scans_initiated", "task_id": workflow.id}