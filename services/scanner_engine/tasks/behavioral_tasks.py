"""
Behavioral EDR Tasks — M3.1
============================
Celery tasks for SSH-based behavioral process analysis.
Persists anomalies to behavioral_findings table.
Runs independently from the vulnerability chord (own queue slot).

ENS Alto op.exp.4: read-only analysis, no modifications to target systems.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from shared.celery_app import app
from shared.database import SessionLocal
from shared.scan_logger import ScanLogger

logger = ScanLogger("behavioral_tasks")

_M1_URL = os.getenv("M1_URL", "http://m1:8001")


# ── Helper: fetch asset credentials from M1 ────────────────────────────────────

def _get_asset(asset_id: int) -> Optional[Dict]:
    """Synchronous HTTP call to M1 to get asset data including SSH credentials."""
    try:
        import requests
        from shared.auth import create_access_token
        token = create_access_token("scanops_service", "service")
        resp = requests.get(
            f"{_M1_URL}/api/v1/assets/{asset_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.warning("BEHAVIORAL_GET_ASSET_FAILED", asset_id=asset_id, error=str(e))
    return None


# ── Main task ──────────────────────────────────────────────────────────────────

@app.task(
    name="tasks.run_behavioral_scan",
    queue="vulnerabilities",
    time_limit=120,
    soft_time_limit=110,
)
def run_behavioral_scan(
    asset_id: int,
    ssh_host: str,
    ssh_user: Optional[str] = None,
    ssh_password: Optional[str] = None,
    ssh_port: int = 22,
    scan_id: Optional[str] = None,
) -> Dict:
    """
    Connect to target via SSH, collect running processes, detect anomalies
    and persist findings to behavioral_findings.

    Returns a summary dict (total, by severity, scan_id) for logging.
    Does NOT raise on partial failure — always returns a result dict.
    """
    if not scan_id:
        scan_id = f"beh_{int(time.time())}_{asset_id}"

    logger.info("BEHAVIORAL_SCAN_START", asset_id=asset_id, host=ssh_host, scan_id=scan_id)

    # ── Resolve SSH credentials from asset if not supplied ─────────────────
    if not ssh_user or not ssh_password:
        asset = _get_asset(asset_id)
        if asset:
            ssh_user     = ssh_user     or asset.get("ssh_user")
            ssh_password = ssh_password or asset.get("ssh_password")
            ssh_host     = asset.get("ip", ssh_host)

    if not ssh_user:
        logger.warning("BEHAVIORAL_NO_SSH_USER", asset_id=asset_id)
        return {"status": "skipped", "reason": "no_ssh_credentials", "asset_id": asset_id}

    if not ssh_password:
        logger.warning("BEHAVIORAL_NO_SSH_PASSWORD", asset_id=asset_id)
        return {"status": "skipped", "reason": "no_ssh_credentials", "asset_id": asset_id}

    # ── SSH connection ─────────────────────────────────────────────────────
    try:
        from services.scanner_engine.clients.behavioral_ssh_client import BehavioralSSHClient
        from services.scanner_engine.services.anomaly_detector import analyze_processes

        with BehavioralSSHClient(
            host=ssh_host,
            username=ssh_user,
            password=ssh_password,
            port=ssh_port,
        ) as client:
            processes = client.get_processes()
            logger.info("BEHAVIORAL_PROCESSES_COLLECTED", count=len(processes), asset_id=asset_id)

            anomalies = analyze_processes(processes)
            logger.info("BEHAVIORAL_ANOMALIES_DETECTED", count=len(anomalies), asset_id=asset_id)

            # ── FASE 4: YARA pattern matching ──────────────────────────────
            try:
                from services.scanner_engine.services.yara_scanner import (
                    merge_yara_with_anomalies,
                )
                anomalies = merge_yara_with_anomalies(processes, anomalies)
                yara_hits = sum(
                    1 for a in anomalies if "yara" in a.detection_method
                )
                logger.info("YARA_SCAN_COMPLETE", yara_hits=yara_hits, asset_id=asset_id)
            except Exception as _ye:
                logger.warning("YARA_SCAN_SKIPPED", error=str(_ye))
            # ── end YARA ───────────────────────────────────────────────────

    except Exception as e:
        logger.error("BEHAVIORAL_SSH_ERROR", asset_id=asset_id, host=ssh_host, error=str(e))
        return {"status": "error", "reason": str(e), "asset_id": asset_id}

    if not anomalies:
        logger.info("BEHAVIORAL_CLEAN", asset_id=asset_id, scan_id=scan_id)
        return {
            "status": "completed",
            "asset_id": asset_id,
            "scan_id": scan_id,
            "total_processes": len(processes),
            "anomalies_found": 0,
        }

    # ── Persist to behavioral_findings ────────────────────────────────────
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 0}
    new_finding_ids: list = []
    db = SessionLocal()
    try:
        for anomaly in anomalies:
            proc = anomaly.process
            result = db.execute(
                """
                INSERT INTO behavioral_findings
                    (asset_id, scan_id, pid, process_name, anomaly_type, severity,
                     confidence_score, detection_method, indicators,
                     mitre_attack_tactics, remediation_suggested, status, created_at)
                VALUES
                    (:asset_id, :scan_id, :pid, :process_name, :anomaly_type, :severity,
                     :confidence_score, :detection_method, CAST(:indicators AS json),
                     CAST(:mitre AS json), :remediation, 'open', NOW())
                RETURNING id
                """,
                {
                    "asset_id":         asset_id,
                    "scan_id":          scan_id,
                    "pid":              proc.pid,
                    "process_name":     proc.command[:255] if proc.command else None,
                    "anomaly_type":     anomaly.anomaly_type,
                    "severity":         anomaly.severity,
                    "confidence_score": anomaly.confidence_score,
                    "detection_method": anomaly.detection_method,
                    "indicators":       json.dumps({
                        "matched": anomaly.indicators,
                        "cmdline": proc.full_cmdline[:512],
                        "user":    proc.user,
                        "pid":     proc.pid,
                    }),
                    "mitre":            json.dumps(anomaly.mitre_attack_tactics),
                    "remediation":      anomaly.remediation_suggested,
                },
            )
            row = result.fetchone()
            if row:
                new_finding_ids.append(row[0])
            stats["total"] += 1
            if anomaly.severity in stats:
                stats[anomaly.severity] += 1

        db.commit()
        logger.info("BEHAVIORAL_PERSIST_COMPLETE", asset_id=asset_id, **stats)

    except Exception as e:
        db.rollback()
        logger.error("BEHAVIORAL_PERSIST_ERROR", asset_id=asset_id, error=str(e))
        return {"status": "error", "reason": f"DB persist failed: {e}", "asset_id": asset_id}
    finally:
        db.close()

    # ── Fire threat intel enrichment for new findings ──────────────────────
    if new_finding_ids:
        try:
            from services.scanner_engine.tasks.threat_intel_tasks import enrich_findings_with_threat_intel
            enrich_findings_with_threat_intel.delay(finding_ids=new_finding_ids)
            logger.info("THREAT_INTEL_QUEUED", finding_ids=new_finding_ids)
        except Exception as _e:
            logger.warning("THREAT_INTEL_QUEUE_FAILED", error=str(_e))

    return {
        "status": "completed",
        "asset_id": asset_id,
        "scan_id": scan_id,
        "total_processes": len(processes),
        "anomalies_found": stats["total"],
        "by_severity": {k: v for k, v in stats.items() if k != "total"},
    }
