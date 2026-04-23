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

from shared.celery_app import app
from shared.database import SessionLocal
from shared.scan_logger import ScanLogger
from services.scanner_engine.clients.openvas_client import OpenVASClient
from services.scanner_engine.clients.nuclei_client import NucleiClient
from services.scanner_engine.clients.zap_client_rest import ZAPClientREST
from services.scanner_engine.models.vulnerability import VulnFinding
from services.scanner_engine.services.nuclei_wrapper import run_nuclei_scan as execute_nuclei_binary

logger = ScanLogger("scanner_tasks")

# --- TAREA: NUCLEI (US-3.2) ---
@app.task(name="tasks.run_nuclei_vulnerability_scan", queue="vulnerabilities")
def run_nuclei_task(asset_id: int, ip: str) -> List[Dict]:
    """Ejecuta Nuclei y devuelve hallazgos sin persistir (el orquestador persiste)."""
    logger.info("NUCLEI_TASK_START", asset_id=asset_id, target=ip)
    try:
        findings = execute_nuclei_binary(ip)
        return [{"scanner": "Nuclei", **f} for f in findings]
    except Exception as e:
        logger.error("NUCLEI_TASK_ERROR", error=str(e))
        return []

# --- TAREA: OPENVAS (US-3.1) ---
@app.task(name="scanner.openvas.scan_asset", queue="scanner_tasks")
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
    except Exception as e:
        logger.error("OPENVAS_TASK_ERROR", error=str(e))
        return []
    finally:
        loop.close()

# --- TAREA: ZAP DAST (US-3.3) ---
@app.task(name="tasks.run_zap_vulnerability_scan", queue="vulnerabilities")
def run_zap_task(asset_id: int, ip: str) -> List[Dict]:
    """Ejecuta ZAP DAST vía API REST."""
    logger.info("ZAP_TASK_START", target=ip)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        client = ZAPClientREST()
        target_url = f"http://{ip}"
        findings = loop.run_until_complete(client.scan_asset(asset_id, target_url))
        return [{"scanner": "ZAP", **f.to_dict()} for f in findings]
    except Exception as e:
        logger.error("ZAP_TASK_ERROR", error=str(e))
        return []
    finally:
        loop.close()

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
            vuln = VulnFinding(
                asset_id=asset_id,
                scan_id=scan_id,
                vulnerability_id=f.get("cve_id") or f.get("vulnerability_id") or "VULN_GENERIC",
                title=f.get("title", "Unknown Vulnerability"),
                severity=severity,
                description=f.get("description", ""),
                scanner_name=f.get("scanner", "Generic"),
                evidence=f.get("evidence", {}),
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
    Nuclei || OpenVAS || ZAP -> merge_and_persist_results
    """
    if not scan_types:
        scan_types = ["nuclei", "openvas", "zap"]
    
    tasks = []
    if "nuclei" in scan_types:
        tasks.append(run_nuclei_task.s(asset_id, asset_ip))
    if "openvas" in scan_types:
        tasks.append(run_openvas_scan.s(asset_id, asset_ip, asset_name))
    if "zap" in scan_types:
        tasks.append(run_zap_task.s(asset_id, asset_ip))

    if not tasks:
        return {"status": "no_scans_selected"}

    # Ejecutar en paralelo y llamar al callback al finalizar
    workflow = chord(group(tasks))(merge_and_persist_results.s(asset_id))
    
    logger.info("PARALLEL_SCAN_ORCHESTRATED", asset_id=asset_id, scanners=scan_types)
    return {"status": "parallel_scans_initiated", "task_id": workflow.id}