"""
External Sync — US-1.6
======================
Importa activos desde Snipe-IT (o mock si no está configurado).
ENS Alto: [op.exp.1] — Inventario actualizado permanentemente.
"""
import os
import httpx
from sqlalchemy.orm import Session
from services.asset_manager.services import asset_service
from services.asset_manager.schemas import AssetCreate
from shared.scan_logger import ScanLogger

logger = ScanLogger("external_sync")

SNIPEIT_URL = os.getenv("SNIPEIT_BASE_URL", "")
SNIPEIT_KEY = os.getenv("SNIPEIT_API_KEY", "")


async def _fetch_snipeit_assets() -> list[dict]:
    """Llama a la API real de Snipe-IT. Si no está configurado, usa mock."""
    if not SNIPEIT_URL or not SNIPEIT_KEY:
        logger.warning("SNIPEIT_NOT_CONFIGURED — using mock data")
        return _mock_assets()

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{SNIPEIT_URL}/api/v1/hardware",
            headers={
                "Authorization": f"Bearer {SNIPEIT_KEY}",
                "Accept": "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json().get("rows", [])


def _mock_assets() -> list[dict]:
    """Datos de prueba cuando Snipe-IT no está disponible."""
    return [
        {"ip": "10.202.15.50", "hostname": "printer-cpd",
         "responsable": "Sistemas", "tipo": "OTRO"},
        {"ip": "10.202.15.60", "hostname": "nas-backups",
         "responsable": "Sistemas", "tipo": "SERVER"},
    ]


def _map_snipeit_to_asset(row: dict) -> dict:
    """Mapea campos de Snipe-IT al schema de ScanOPS."""
    return {
        "ip": row.get("ip_address") or row.get("ip", ""),
        "hostname": row.get("name") or row.get("hostname", ""),
        "responsable": (
            row.get("assigned_to", {}).get("name", "Pendiente")
            if isinstance(row.get("assigned_to"), dict)
            else row.get("responsable", "Pendiente")
        ),
        "tipo": row.get("tipo", "OTRO"),
        "criticidad": "PENDIENTE_CLASIFICAR",
    }


async def sync_from_external(db: Session) -> dict:
    """
    Importa activos desde fuente externa.
    Solo crea nuevos — no sobreescribe existentes.
    """
    rows = await _fetch_snipeit_assets()
    created = 0
    skipped = 0

    for row in rows:
        mapped = _map_snipeit_to_asset(row)
        ip = mapped.get("ip")
        if not ip:
            skipped += 1
            continue
        if asset_service.get_asset_by_ip(db, ip):
            skipped += 1
            continue
        try:
            asset_service.create_asset(
                db, AssetCreate(**mapped), user_id="external-sync"
            )
            created += 1
            logger.info("SYNC_CREATED", ip=ip)
        except Exception as e:
            logger.error("SYNC_ERROR", ip=ip, error=str(e))
            skipped += 1

    return {"synced": created, "skipped": skipped, "total_rows": len(rows)}