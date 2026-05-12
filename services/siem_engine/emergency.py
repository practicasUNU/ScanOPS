"""
US-6.7 — Escaneo de emergencia M2+M3
ENS: op.exp.3
"""
import os
import asyncio
import uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from psycopg2.extras import RealDictCursor
import httpx
from shared.scan_logger import ScanLogger
from .db import get_conn

logger = ScanLogger("siem_engine.emergency")
router = APIRouter(tags=["US-6.7 Emergency Scan"])

M1_URL = os.getenv("M1_URL", "http://m1:8001")
M2_URL = os.getenv("M2_URL", "http://m2:8003")
M3_URL = os.getenv("M3_URL", "http://scanner-engine:8002")
SCANOPS_API_KEY = os.getenv("SCANOPS_API_KEY", "scanops_secret")
_HEADERS = {"Authorization": f"Bearer {SCANOPS_API_KEY}"}


class EmergencyScanRequest(BaseModel):
    asset_id: int
    reason: str = "anomaly_detected"
    triggered_by: str = "manual"


async def _get_asset_ip(asset_id: int) -> str:
    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.get(
            f"{M1_URL}/api/v1/assets/{asset_id}",
            headers=_HEADERS,
        )
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail=f"Activo {asset_id} no encontrado en M1")
        resp.raise_for_status()
        data = resp.json()
        return data.get("ip") or data.get("items", [{}])[0].get("ip", "")


async def _call_m2(asset_ip: str, asset_id: int) -> tuple[str | None, bool]:
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.post(
                f"{M2_URL}/api/v1/scan",
                params={"target": asset_ip, "asset_id": asset_id},
                headers=_HEADERS,
            )
            if resp.status_code in (200, 201, 202):
                body = resp.json()
                scan_id = (
                    body.get("scan_id")
                    or body.get("id")
                    or body.get("snapshot_id")
                    or str(uuid.uuid4())[:8]
                )
                return str(scan_id), True
            logger.warning(f"M2 returned {resp.status_code} for asset {asset_id}")
            return None, False
    except Exception as e:
        logger.warning(f"M2 call failed for asset {asset_id}: {e}")
        return None, False


async def _call_m3(asset_id: int) -> tuple[str | None, bool]:
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.post(
                f"{M3_URL}/api/v1/scan/asset/{asset_id}",
                json={"scan_types": ["nuclei", "nikto"]},
                headers=_HEADERS,
            )
            if resp.status_code in (200, 201, 202):
                body = resp.json()
                scan_id = (
                    body.get("task_id")
                    or body.get("scan_id")
                    or body.get("id")
                    or str(uuid.uuid4())[:8]
                )
                return str(scan_id), True
            logger.warning(f"M3 returned {resp.status_code} for asset {asset_id}")
            return None, False
    except Exception as e:
        logger.warning(f"M3 call failed for asset {asset_id}: {e}")
        return None, False


def _persist_emergency(
    asset_id: int,
    reason: str,
    triggered_by: str,
    m2_id: str | None,
    m3_id: str | None,
    status: str,
) -> int:
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO siem_emergency_scans
                        (asset_id, reason, triggered_by, m2_scan_id, m3_scan_id, status)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (asset_id, reason, triggered_by, m2_id, m3_id, status))
                row = cur.fetchone()
                return row[0] if row else -1
    finally:
        conn.close()


@router.post("/siem/emergency-scan")
async def emergency_scan(req: EmergencyScanRequest):
    """Dispara M2 + M3 en paralelo para el activo especificado — ENS op.exp.3."""
    asset_ip = await _get_asset_ip(req.asset_id)

    t0 = datetime.utcnow()
    (m2_id, m2_ok), (m3_id, m3_ok) = await asyncio.gather(
        _call_m2(asset_ip, req.asset_id),
        _call_m3(req.asset_id),
    )
    elapsed = (datetime.utcnow() - t0).total_seconds()

    status = "triggered" if (m2_ok or m3_ok) else "failed"
    scan_id = _persist_emergency(
        req.asset_id, req.reason, req.triggered_by, m2_id, m3_id, status
    )

    logger.info(
        f"[US-6.7] Emergency scan asset={req.asset_id} | m2={m2_ok} | m3={m3_ok} | {elapsed:.1f}s"
    )
    return {
        "emergency_scan_id": str(scan_id),
        "asset_id": req.asset_id,
        "asset_ip": asset_ip,
        "m2_triggered": m2_ok,
        "m2_scan_id": m2_id,
        "m3_triggered": m3_ok,
        "m3_scan_id": m3_id,
        "elapsed_seconds": round(elapsed, 2),
        "timestamp": t0.isoformat(),
    }


@router.get("/siem/emergency-scans")
async def list_emergency_scans():
    """Historial de escaneos de emergencia."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, asset_id, reason, triggered_by,
                       m2_scan_id, m3_scan_id, status, triggered_at
                FROM siem_emergency_scans
                ORDER BY triggered_at DESC
                LIMIT 200
            """)
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("triggered_at"):
                    r["triggered_at"] = r["triggered_at"].isoformat()
        return {"total": len(rows), "scans": rows}
    finally:
        conn.close()


async def _trigger_emergency_for_ip(agent_ip: str, reason: str, triggered_by: str) -> None:
    """Usado por el loop de alertas — busca activo por IP en M1 y dispara escaneo."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.get(
                f"{M1_URL}/api/v1/assets",
                params={"ip": agent_ip},
                headers=_HEADERS,
            )
            if resp.status_code != 200:
                return
            data = resp.json()
            items = data.get("items", data) if isinstance(data, dict) else data
            for asset in items:
                if asset.get("ip") == agent_ip:
                    crit = asset.get("criticidad", "").upper()
                    if crit in ("ALTA", "CRITICA", "CRITICAL", "HIGH"):
                        req = EmergencyScanRequest(
                            asset_id=asset["id"],
                            reason=reason,
                            triggered_by=triggered_by,
                        )
                        await emergency_scan(req)
                    break
    except Exception as e:
        logger.debug(f"_trigger_emergency_for_ip {agent_ip}: {e}")
