"""
Asset API Router — US-1.2 / US-1.5 / US-1.7
=============================================
CRUD endpoints + Ficha Única + Audit logs.
"""


from services.asset_manager.services.external_sync import sync_from_external

from services.asset_manager.tasks.discovery import run_network_discovery
from celery.result import AsyncResult

from shared.vault_client import vault_client
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from shared.database import get_db
from shared.auth import get_current_user

from services.asset_manager.models.asset import Asset, CriticidadEnum, TipoActivoEnum, AssetStatusEnum
from datetime import datetime
from services.asset_manager.schemas import (
    AssetCreate,
    AssetUpdate,
    AssetResponse,
    AssetListResponse,
    AssetFicha,
    AuditLogResponse,
    AuditLogListResponse,
)
from services.asset_manager.services import asset_service

from pydantic import BaseModel

class CredentialUpdateRequest(BaseModel):
    username: Optional[str] = None
    password: str
    descripcion: Optional[str] = None

class DiscoveryRequest(BaseModel):
    network_ranges: list[str]

router = APIRouter(prefix="/assets", tags=["Asset Manager (M1)"])


# ─── CRUD ─────────────────────────────────────────────────

@router.post("", response_model=AssetResponse, status_code=201)
async def create_asset(
    data: AssetCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a new asset in the inventory."""
    asset = asset_service.create_asset(
        db=db,
        data=data,
        user_id=current_user.get("user", "unknown"),
        user_role=current_user.get("role"),
        ip_origin=request.client.host if request.client else None,
    )
    return asset


@router.get("", response_model=AssetListResponse)
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    criticidad: Optional[CriticidadEnum] = None,
    tipo: Optional[TipoActivoEnum] = None,
    status: Optional[AssetStatusEnum] = None,
    search: Optional[str] = Query(None, description="Search by IP, hostname or responsable"),
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List assets with pagination and optional filters."""
    items, total = asset_service.list_assets(
        db=db, page=page, page_size=page_size,
        criticidad=criticidad, tipo=tipo, status=status,
        search=search, include_deleted=include_deleted,
    )
    return AssetListResponse(total=total, page=page, page_size=page_size, items=items)


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get a single asset by ID."""
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: int,
    data: AssetUpdate,
    request: Request,
    reason: Optional[str] = Query(None, description="Reason for the change"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update an existing asset. Only provided fields are changed."""
    asset = asset_service.update_asset(
        db=db, asset_id=asset_id, data=data,
        user_id=current_user.get("user", "unknown"),
        user_role=current_user.get("role"),
        ip_origin=request.client.host if request.client else None,
        reason=reason,
    )
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.delete("/{asset_id}", response_model=AssetResponse)
async def delete_asset(
    asset_id: int,
    request: Request,
    reason: Optional[str] = Query(None, description="Reason for deletion"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Soft-delete an asset (preserves audit trail)."""
    asset = asset_service.delete_asset(
        db=db, asset_id=asset_id,
        user_id=current_user.get("user", "unknown"),
        user_role=current_user.get("role"),
        ip_origin=request.client.host if request.client else None,
        reason=reason,
    )
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


# ─── Ficha Única (US-1.7) ────────────────────────────────
@router.get("/{asset_id}/ficha", response_model=AssetFicha)
async def get_asset_ficha(asset_id: int, db: Session = Depends(get_db)):
    from services.recon_engine.models.recon import ReconFinding
    from services.scanner_engine.models.vulnerability import VulnFinding
    
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset no encontrado")
    
    try:
        recon = db.query(ReconFinding).filter(ReconFinding.host == asset.ip).all()
        superficie = [{"puerto": f.port, "servicio": f.service, "estado": f.state} for f in recon] if recon else None
    except:
        superficie = None
    
    try:
        vulns = db.query(VulnFinding).filter(VulnFinding.asset_id == asset_id).all()
        vulnerabilidades = [{"titulo": v.title, "severidad": v.severity, "cvss": v.cvss_v3_score, "cve": v.scanner_reference, "scanner": v.scanner_name} for v in vulns] if vulns else None
    except:
        vulnerabilidades = None
    
    return AssetFicha(id=asset.id, ip=asset.ip, hostname=asset.hostname, criticidad=asset.criticidad, tipo=asset.tipo, status=asset.status, responsable=asset.responsable, tags_ens=asset.tags_ens or [], superficie=superficie, vulnerabilidades=vulnerabilidades, ficha_generated_at=datetime.utcnow(), ficha_version="1.0")
# ─── Audit Log (US-1.5) ──────────────────────────────────

@router.get("/{asset_id}/audit", response_model=AuditLogListResponse)
async def get_asset_audit_log(
    asset_id: int,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get audit history for an asset — who did what and when."""
    # Verify asset exists (even if deleted)
    asset = asset_service.get_asset(db, asset_id, include_deleted=True)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    items, total = asset_service.get_audit_logs(db, asset_id, limit=limit)
    return AuditLogListResponse(total=total, items=items)


# ─── Gestión de Credenciales (US-1.3) ──────────────────────

@router.post("/{asset_id}/credentials")
async def update_asset_credentials(
    asset_id: int,
    creds: CredentialUpdateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Actualiza credenciales de un activo en Vault.
    La contraseña NUNCA se almacena en la BD.
    ENS Alto: [mp.info.3]
    """
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    vault_path = f"assets/{asset_id}/credentials"
    data = creds.model_dump(exclude_none=True)
    ok = vault_client.store_credentials(vault_path, data)
    if not ok:
        raise HTTPException(status_code=500, detail="Vault storage failed")

    if not asset.vault_path:
        asset.vault_path = vault_path
        db.commit()

    return {
        "asset_id": asset_id,
        "vault_path": vault_path,
        "status": "credentials stored in Vault",
    }


@router.get("/{asset_id}/credentials/check")
async def check_credentials_exist(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Verifica si un activo tiene credenciales en Vault (sin revelarlas)."""
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    return {
        "asset_id": asset_id,
        "has_credentials": asset.vault_path is not None,
    }
    
    
# ─── Discovery (US-1.4) ────────────────────────────────────

@router.post("/discovery")
async def trigger_discovery(
    data: DiscoveryRequest,
    current_user: dict = Depends(get_current_user),
):
    """Lanza descubrimiento de activos en background [op.acc.1]."""
    tasks = []
    for cidr in data.network_ranges:
        task = run_network_discovery.delay(cidr)
        tasks.append({"cidr": cidr, "task_id": str(task.id)})
    return {"status": "started", "tasks": tasks}


@router.get("/discovery/{task_id}")
async def get_discovery_status(
    task_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Consulta el resultado de un discovery en curso."""
    task = AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": task.status,
        "result": task.result if task.ready() else None,
    }    
    
    
# ─── Sync Externa (US-1.6) ─────────────────────────────────

@router.post("/sync/external")
async def trigger_external_sync(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Importa activos desde Snipe-IT o fuente externa [op.exp.1]."""
    result = await sync_from_external(db)
    return result    

# ─── Gestión de Credenciales (US-1.3) ──────────────────────

@router.post("/{asset_id}/credentials")
async def update_asset_credentials(
    asset_id: int,
    creds: AssetCreate,  # Reutilizamos el campo password que ya existe
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Actualiza credenciales de un activo en Vault.
    La contraseña NUNCA se almacena en la BD — solo vault_path.
    ENS Alto: [mp.info.3]
    """
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    if not creds.password:
        raise HTTPException(status_code=400, detail="Password is required")

    vault_path = f"assets/{asset_id}/credentials"
    ok = vault_client.store_credentials(vault_path, {"password": creds.password})
    if not ok:
        raise HTTPException(status_code=500, detail="Vault storage failed")

    asset.vault_path = vault_path
    db.commit()

    return {
        "asset_id": asset_id,
        "vault_path": vault_path,
        "status": "credentials stored in Vault",
    }


@router.get("/{asset_id}/credentials/check")
async def check_credentials_exist(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Verifica si un activo tiene credenciales en Vault (sin revelarlas)."""
    asset = asset_service.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    return {
        "asset_id": asset_id,
        "has_credentials": asset.vault_path is not None,
    }