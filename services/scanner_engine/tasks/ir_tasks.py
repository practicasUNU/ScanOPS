"""
Incident Response Tasks — M3.1 FASE 5
=======================================
Celery task that executes an approved incident response action.
Triggered automatically after TOTP+PIN approval (unless EDR_AUTO_REMEDIATE=false).

Flow: approve → status=approved → this task → status=executing → completed/failed
ENS op.exp.4: execution is logged with result, duration and approver identity.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Dict, Optional

from shared.celery_app import app
from shared.database import SessionLocal
from shared.scan_logger import ScanLogger

logger = ScanLogger("ir_tasks")


@app.task(
    name="tasks.execute_response_action",
    queue="vulnerabilities",
    time_limit=300,
    soft_time_limit=270,
)
def execute_response_action(action_id: int) -> Dict:
    """
    Execute an approved incident response action via SSH.
    Fetches SSH credentials from M1 (same pattern as behavioral tasks).
    Updates status → executing → completed/failed with full output.
    Returns result dict for Celery result backend.
    """
    from services.scanner_engine.models.edr import IncidentResponseLog
    from services.scanner_engine.services.incident_response_executor import execute_action

    db = SessionLocal()
    try:
        action = db.query(IncidentResponseLog).filter(
            IncidentResponseLog.id == action_id
        ).first()

        if not action:
            logger.error("IR_ACTION_NOT_FOUND", action_id=action_id)
            return {"status": "error", "reason": "action not found"}

        if action.status != "approved":
            logger.warning(
                "IR_ACTION_WRONG_STATUS",
                action_id=action_id,
                status=action.status,
            )
            return {"status": "skipped", "reason": f"status is {action.status}, expected approved"}

        # Mark as executing
        action.status = "executing"
        db.add(action)
        db.commit()

        # Fetch SSH credentials from M1
        asset = _get_asset(action.asset_id)
        if not asset:
            _fail(db, action, "Could not fetch asset from M1")
            return {"status": "error", "reason": "M1 unreachable or asset not found"}

        ssh_host = asset.get("ip")
        ssh_user = asset.get("ssh_user")
        ssh_password = asset.get("ssh_password")

        if not (ssh_host and ssh_user and ssh_password):
            _fail(db, action, "Asset missing SSH credentials (ip/ssh_user/ssh_password)")
            return {"status": "error", "reason": "incomplete SSH credentials"}

        logger.info(
            "IR_EXEC_START",
            action_id=action_id,
            action_type=action.action_type,
            target=action.target_detail,
            host=ssh_host,
        )

        result = execute_action(
            ssh_host=ssh_host,
            ssh_user=ssh_user,
            ssh_password=ssh_password,
            action_type=action.action_type,
            target_detail=action.target_detail,
        )

        # Persist result
        action.status                = "completed" if result.success else "failed"
        action.executed_at           = datetime.now(timezone.utc)
        action.execution_duration_ms = result.duration_ms
        action.rollback_capable      = result.rollback_capable
        action.result_output         = (
            f"{result.output}\n\nROLLBACK: {result.rollback_hint}"
            if result.rollback_hint else result.output
        )[:4000]
        db.add(action)
        db.commit()

        logger.info(
            "IR_EXEC_DONE",
            action_id=action_id,
            success=result.success,
            duration_ms=result.duration_ms,
        )
        return {
            "status":      action.status,
            "action_id":   action_id,
            "duration_ms": result.duration_ms,
            "success":     result.success,
        }

    except Exception as exc:
        db.rollback()
        logger.error("IR_TASK_FATAL", action_id=action_id, error=str(exc))
        try:
            _fail(db, action, str(exc))
        except Exception:
            pass
        return {"status": "error", "reason": str(exc)}
    finally:
        db.close()


def _fail(db, action, reason: str) -> None:
    action.status        = "failed"
    action.result_output = reason[:4000]
    action.executed_at   = datetime.now(timezone.utc)
    db.add(action)
    db.commit()


def _get_asset(asset_id: int) -> Optional[Dict]:
    import os
    import requests
    from shared.auth import create_access_token
    m1_url = os.getenv("M1_URL", "http://m1:8001")
    try:
        token = create_access_token("scanops_service", "service")
        resp = requests.get(
            f"{m1_url}/api/v1/assets/{asset_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        logger.warning("IR_GET_ASSET_FAILED", asset_id=asset_id, error=str(exc))
    return None
