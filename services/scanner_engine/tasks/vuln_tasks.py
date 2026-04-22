"""Celery tasks for vulnerability scanning orchestration."""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime

from shared.celery_app import app

logger = logging.getLogger(__name__)

from services.scanner_engine.clients.openvas_client import OpenVASClient
from services.scanner_engine.clients.nuclei_client import NucleiClient
from services.scanner_engine.clients.zap_client import ZAPClient


# ============================================================================
# TASK 1: OpenVAS Scan Task
# ============================================================================
@app.task(
    name="scanner.openvas.scan_asset",
    bind=True,
    timeout=3600,
    max_retries=3,
    queue="scanner_tasks",
)
def run_openvvas_scan(self, asset_id: int, asset_ip: str, asset_name: str) -> Dict:
    """Execute OpenVAS vulnerability scan."""
    try:
        logger.info(f"→ OpenVAS scan: asset_id={asset_id}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            client = OpenVASClient()
            findings = loop.run_until_complete(
                client.scan_asset(asset_id, asset_ip, asset_name)
            )

            result = {
                "scanner": "OpenVAS",
                "status": "success",
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings],
                "error": None,
            }

            logger.info(f"✓ OpenVAS: {len(findings)} hallazgos")
            return result

        finally:
            loop.close()

    except Exception as e:
        logger.error(f"✗ OpenVAS error: {str(e)}")

        if self.request.retries < self.max_retries:
            logger.info(f"Reintentando OpenVAS (intento {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))

        return {
            "scanner": "OpenVAS",
            "status": "error",
            "findings_count": 0,
            "findings": [],
            "error": str(e),
        }


# ============================================================================
# TASK 2: Nuclei Scan Task
# ============================================================================
@app.task(
    name="scanner.nuclei.scan_asset",
    bind=True,
    timeout=1800,
    max_retries=2,
    queue="scanner_tasks",
)
def run_nuclei_scan(self, asset_id: int, asset_ip: str, asset_name: str) -> Dict:
    """Execute Nuclei template-based scan."""
    try:
        logger.info(f"→ Nuclei scan: asset_id={asset_id}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            client = NucleiClient()
            findings = loop.run_until_complete(
                client.scan_asset(asset_id, asset_ip, asset_name)
            )

            result = {
                "scanner": "Nuclei",
                "status": "success",
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings],
                "error": None,
            }

            logger.info(f"✓ Nuclei: {len(findings)} hallazgos")
            return result

        finally:
            loop.close()

    except Exception as e:
        logger.error(f"✗ Nuclei error: {str(e)}")

        if self.request.retries < self.max_retries:
            logger.info(f"Reintentando Nuclei (intento {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))

        return {
            "scanner": "Nuclei",
            "status": "error",
            "findings_count": 0,
            "findings": [],
            "error": str(e),
        }


# ============================================================================
# TASK 3: ZAP Scan Task
# ============================================================================
@app.task(
    name="scanner.zap.scan_asset",
    bind=True,
    timeout=1800,
    max_retries=2,
    queue="scanner_tasks",
)
def run_zap_scan(self, asset_id: int, asset_url: str, asset_name: str) -> Dict:
    """Execute ZAP web vulnerability scan."""
    try:
        logger.info(f"→ ZAP scan: asset_id={asset_id}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            client = ZAPClient()
            findings = loop.run_until_complete(
                client.scan_asset(asset_id, asset_url, asset_name)
            )

            result = {
                "scanner": "ZAP",
                "status": "success",
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings],
                "error": None,
            }

            logger.info(f"✓ ZAP: {len(findings)} hallazgos")
            return result

        finally:
            loop.close()

    except Exception as e:
        logger.error(f"✗ ZAP error: {str(e)}")

        if self.request.retries < self.max_retries:
            logger.info(f"Reintentando ZAP (intento {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))

        return {
            "scanner": "ZAP",
            "status": "error",
            "findings_count": 0,
            "findings": [],
            "error": str(e),
        }


# ============================================================================
# TASK 4: Merge Scan Results
# ============================================================================
@app.task(
    name="scanner.merge_results",
    bind=True,
    queue="scanner_tasks",
)
def merge_scan_results(self, results: List[Dict], asset_id: int) -> Dict:
    """Merge results from multiple scanners."""
    try:
        logger.info(f"→ Merge: asset_id={asset_id}, scanners={len(results)}")

        findings_by_scanner = {}
        total_findings = 0

        for result in results:
            if result and result.get("status") == "success":
                scanner = result.get("scanner")
                findings = result.get("findings", [])
                findings_by_scanner[scanner] = findings
                total_findings += len(findings)
                logger.debug(f"  {scanner}: {len(findings)} hallazgos")

        merged = {
            "asset_id": asset_id,
            "total_findings": total_findings,
            "findings_by_scanner": findings_by_scanner,
            "completed_at": datetime.utcnow().isoformat(),
        }

        logger.info(f"✓ Merge: {total_findings} total hallazgos")
        return merged

    except Exception as e:
        logger.error(f"✗ Merge error: {str(e)}")
        raise


# ============================================================================
# TASK 5: Parallel Orchestrator
# ============================================================================
@app.task(
    name="scanner.orchestrator.scan_parallel",
    bind=True,
    timeout=7200,
    queue="scanner_orchestrator",
)
def scan_asset_parallel(
    self,
    asset_id: int,
    asset_ip: str,
    asset_name: str,
    scan_types: Optional[List[str]] = None,
) -> Dict:
    """Execute multiple scanners in parallel using Celery chord."""
    from celery import chord

    if scan_types is None:
        scan_types = ["openvas", "nuclei", "zap"]

    logger.info(f"→ Orchestrator: asset_id={asset_id}, scanners={scan_types}")

    # Create tasks for each scanner
    tasks = []

    if "openvas" in scan_types:
        tasks.append(run_openvvas_scan.s(asset_id, asset_ip, asset_name))

    if "nuclei" in scan_types:
        tasks.append(run_nuclei_scan.s(asset_id, asset_ip, asset_name))

    if "zap" in scan_types:
        tasks.append(run_zap_scan.s(asset_id, asset_ip, asset_name))

    if not tasks:
        logger.warning("✗ No scan types especificados")
        return {"status": "error", "message": "No scan types specified"}

    # Execute all tasks in parallel using chord
    result = chord(tasks)(merge_scan_results.s(asset_id))

    logger.info(f"✓ Orchestrator: {len(tasks)} scanners en paralelo")

    return result.get()