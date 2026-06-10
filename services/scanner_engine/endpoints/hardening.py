"""
Endpoints de bastionado ENS — M3
POST /api/v1/hardening/run               → lanza tarea batch Celery
GET  /api/v1/hardening/status/{task_id}  → estado de la tarea
GET  /api/v1/hardening/results/{asset_id}→ últimos resultados persistidos
ENS: op.exp.2
"""

import json
import os

import httpx
import psycopg2
import psycopg2.extras
from celery.result import AsyncResult
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List

from shared.auth import create_access_token
from shared.celery_app import app as celery_app
from shared.config import settings
from shared.scan_logger import ScanLogger
from services.scanner_engine.tasks.hardening_tasks import run_hardening_batch

logger = ScanLogger("hardening_endpoints")

router = APIRouter(prefix="/hardening", tags=["Bastionado ENS"])

M1_BASE_URL = os.getenv("M1_URL", "http://scanops-asset-manager:8001")


class HardeningRunRequest(BaseModel):
    asset_ids: List[int]


async def _get_asset(asset_id: int) -> dict:
    """Obtiene datos del activo desde M1 incluyendo credenciales SSH."""
    token = create_access_token("scanops_service", "service")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                f"{M1_BASE_URL}/assets/{asset_id}",
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type": "application/json"},
            )
            if r.status_code == 404:
                raise HTTPException(404, f"Activo {asset_id} no encontrado en M1")
            if r.status_code != 200:
                raise HTTPException(502, f"M1 devolvió {r.status_code} para activo {asset_id}")
            return r.json()
    except HTTPException:
        raise
    except httpx.RequestError as e:
        raise HTTPException(503, f"No se pudo conectar con M1: {e}")


@router.post("/run")
async def run_hardening(request: HardeningRunRequest):
    """
    Lanza verificación de bastionado sobre los activos indicados.
    Requiere ssh_user y ssh_password configurados en M1.
    ENS: op.exp.2
    """
    if not request.asset_ids:
        raise HTTPException(400, "Se requiere al menos un asset_id")

    asset_checks = []
    skipped = []

    for asset_id in request.asset_ids:
        try:
            asset = await _get_asset(asset_id)
        except HTTPException as e:
            skipped.append({"asset_id": asset_id, "reason": e.detail})
            continue

        ssh_user = asset.get("ssh_user") or asset.get("usuario_ssh")
        ssh_password = asset.get("ssh_password") or asset.get("password_ssh")

        if not ssh_user or not ssh_password:
            skipped.append({
                "asset_id": asset_id,
                "reason": "Sin credenciales SSH configuradas en M1",
            })
            continue

        asset_checks.append({
            "asset_id": asset_id,
            "target_ip": asset.get("ip_address") or asset.get("ip"),
            "ssh_user": ssh_user,
            "ssh_password": ssh_password,
            "hostname": (asset.get("hostname")
                         or asset.get("name")
                         or asset.get("nombre")
                         or f"Asset-{asset_id}"),
        })

    if not asset_checks:
        raise HTTPException(400, detail={
            "message": "Ningún activo tiene credenciales SSH configuradas",
            "skipped": skipped,
        })

    task = run_hardening_batch.delay(asset_checks)

    logger.info(
        f"HARDENING_BATCH_QUEUED task_id={task.id} "
        f"assets={[a['asset_id'] for a in asset_checks]} skipped={len(skipped)}"
    )

    return {
        "task_id": task.id,
        "status": "PENDING",
        "assets_queued": len(asset_checks),
        "assets_skipped": skipped,
        "message": f"Verificación de bastionado iniciada para {len(asset_checks)} activo/s",
    }


@router.get("/status/{task_id}")
async def get_hardening_status(task_id: str):
    """
    Consulta el estado de una tarea de bastionado.
    Devuelve status + results cuando status == SUCCESS.
    """
    try:
        result = AsyncResult(task_id, app=celery_app)
        state = result.state

        if state == "SUCCESS":
            data = result.result or {}
            return {
                "task_id": task_id,
                "status": "SUCCESS",
                "results": data.get("results", []),
            }
        if state in ("FAILURE", "REVOKED"):
            return {
                "task_id": task_id,
                "status": "FAILURE",
                "error": str(result.info) if result.info else "Error desconocido",
            }
        progress_map = {"PENDING": 10, "STARTED": 50, "RETRY": 30}
        return {
            "task_id": task_id,
            "status": state,
            "progress": progress_map.get(state, 10),
        }
    except Exception as e:
        raise HTTPException(500, f"Error consultando tarea: {e}")


@router.get("/results/{asset_id}")
async def get_hardening_results(asset_id: int, limit: int = 5):
    """
    Devuelve los últimos N resultados de bastionado persistidos para un activo.
    ENS: op.exp.2 — evidencia trimestral
    """
    try:
        conn = psycopg2.connect(settings.database_url)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, asset_id, target_ip, hostname, controles,
                       si_count, no_count, revisar_count, cumple_ens, verified_at
                FROM hardening_results
                WHERE asset_id = %s
                ORDER BY verified_at DESC
                LIMIT %s
            """, (asset_id, limit))
            rows = cur.fetchall()
        conn.close()

        results = []
        for r in rows:
            row = dict(r)
            if row.get("verified_at"):
                row["verified_at"] = row["verified_at"].isoformat()
            if isinstance(row.get("controles"), str):
                row["controles"] = json.loads(row["controles"])
            results.append(row)

        return {"asset_id": asset_id, "total": len(results), "results": results}

    except psycopg2.errors.UndefinedTable:
        return {"asset_id": asset_id, "total": 0, "results": []}
    except Exception as e:
        raise HTTPException(500, f"Error consultando resultados: {e}")
