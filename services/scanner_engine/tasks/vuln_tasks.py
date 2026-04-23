"""Celery tasks for vulnerability scanning orchestration — M3."""

import asyncio
import logging
import time
from typing import Dict, List
from datetime import datetime

from shared.celery_app import app
from shared.database import SessionLocal
from shared.scan_logger import ScanLogger
from services.scanner_engine.clients.openvas_client import OpenVASClient
from services.scanner_engine.clients.nuclei_client import NucleiClient
from services.scanner_engine.clients.zap_client import ZAPClient
from services.scanner_engine.models.vulnerability import VulnFinding
from services.scanner_engine.services.nuclei_wrapper import run_nuclei_scan as execute_nuclei_binary

logger = ScanLogger("scanner_tasks")

# --- TAREA: NUCLEI (US-3.2 y US-3.5) ---
@app.task(name="tasks.run_nuclei_vulnerability_scan", queue="vulnerabilities")
def run_nuclei_task(asset_id: int, ip: str):
    """Ejecuta Nuclei y persiste los hallazgos en la DB [op.exp.2]."""
    logger.info("NUCLEI_TASK_START", asset_id=asset_id, target=ip)
    
    # 1. Ejecutar escaneo real via wrapper binario
    findings = execute_nuclei_binary(ip)
    
    if not findings:
        logger.info("NUCLEI_TASK_CLEAN", asset_id=asset_id)
        return {"status": "success", "found": 0}

    # 2. Persistir en PostgreSQL usando el modelo VulnFinding
    db = SessionLocal()
    try:
        for f in findings:
            vuln = VulnFinding(
                asset_id=asset_id,
                scan_id=f"nuclei_{int(time.time())}",
                vulnerability_id=f.get("cve_id") or "NUCLEI_GENERIC",
                title=f["title"],
                severity=f["severity"],
                description=f["description"],
                scanner_name="Nuclei",
                scanner_reference=f.get("cve_id"),
                evidence={"url": f["evidence"]},
                ens_requirement="op.exp.2", # Medida ENS Alto
                created_by="system-nuclei"
            )
            db.add(vuln)
        db.commit()
        logger.info("NUCLEI_TASK_PERSISTED", asset_id=asset_id, count=len(findings))
        return {"status": "success", "found": len(findings)}
    except Exception as e:
        db.rollback()
        logger.error("NUCLEI_DB_ERROR", asset_id=asset_id, error=str(e))
        return {"status": "error", "message": str(e)}
    finally:
        db.close()

# --- TAREA: OPENVAS (US-3.1) ---
@app.task(name="scanner.openvas.scan_asset", bind=True, queue="scanner_tasks")
def run_openvvas_scan(self, asset_id: int, asset_ip: str, asset_name: str) -> Dict:
    """Execute OpenVAS vulnerability scan with slot management."""
    from redis import Redis
    redis_client = Redis(host='redis', port=6379, db=0, decode_responses=True)

    # Control de concurrencia [ENS Alto: op.exp.3]
    while int(redis_client.get('active_scans') or 0) >= 5:
        time.sleep(5)

    redis_client.incr('active_scans')
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            client = OpenVASClient(host="openvas")
            findings = loop.run_until_complete(client.scan_asset(asset_id, asset_ip, asset_name))
            
            db = SessionLocal()
            for f in findings:
                vuln = VulnFinding(
                    asset_id=asset_id,
                    scan_id=f"ovas_{int(time.time())}",
                    vulnerability_id=f.cve_id or "UNKNOWN",
                    title=f.title,
                    severity=f.severity,
                    scanner_name="OpenVAS",
                    evidence={"raw": f.evidence},
                    created_by="scanner-openvas"
                )
                db.add(vuln)
            db.commit()
            db.close()
            return {"scanner": "OpenVAS", "status": "success", "found": len(findings)}
        finally: loop.close()
    except Exception as e:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e, countdown=60)
        return {"status": "error", "error": str(e)}
    finally:
        redis_client.decr('active_scans')

# --- ORQUESTADOR PARALELO (US-3.4) ---
@app.task(name="services.scanner_engine.tasks.vuln_tasks.scan_asset_parallel")
def scan_asset_parallel(asset_id: int, asset_ip: str, asset_name: str, scan_types: List[str] = None):
    """Lanza múltiples scanners en paralelo según la US-3.4."""
    if not scan_types: scan_types = ["nuclei"]
    
    if "nuclei" in scan_types:
        run_nuclei_task.delay(asset_id, asset_ip)
    
    if "openvas" in scan_types:
        run_openvvas_scan.delay(asset_id, asset_ip, asset_name)
    
    return {"status": "parallel_scans_triggered", "asset_id": asset_id}