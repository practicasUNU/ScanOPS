"""
Asset Service — US-1.1 / US-1.2
================================
Business logic for asset CRUD. Keeps the API router thin.
"""

from typing import Optional, List, Tuple
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy import func

from services.asset_manager.models.asset import (
    Asset,
    AssetAuditLog,
    CriticidadEnum,
    TipoActivoEnum,
    AssetStatusEnum,
    AuditActionEnum,
)
from services.asset_manager.schemas import AssetCreate, AssetUpdate


def _asset_to_dict(asset: Asset) -> dict:
    """Serialize asset to dict for audit snapshots."""
    return {
        "id": asset.id,
        "ip": asset.ip,
        "hostname": asset.hostname,
        "dominio": asset.dominio,
        "mac_address": asset.mac_address,
        "criticidad": asset.criticidad.value if asset.criticidad else None,
        "tipo": asset.tipo.value if asset.tipo else None,
        "status": asset.status.value if asset.status else None,
        "responsable": asset.responsable,
        "departamento": asset.departamento,
        "ubicacion": asset.ubicacion,
        "tags_ens": asset.tags_ens,
        "notas": asset.notas,
        "vault_path": asset.vault_path,
        "os_family": asset.os_family,
        "os_version": asset.os_version,
    }


def _log_audit(
    db: Session,
    asset: Asset,
    action: AuditActionEnum,
    user_id: str,
    user_role: Optional[str] = None,
    changes: Optional[dict] = None,
    snapshot_before: Optional[dict] = None,
    snapshot_after: Optional[dict] = None,
    ip_origin: Optional[str] = None,
    reason: Optional[str] = None,
):
    """Write an immutable audit log entry (US-1.5)."""
    log = AssetAuditLog(
        asset_id=asset.id,
        action=action,
        user_id=user_id,
        user_role=user_role,
        changes=changes,
        snapshot_before=snapshot_before,
        snapshot_after=snapshot_after,
        ip_origin=ip_origin,
        reason=reason,
    )
    db.add(log)


from shared.vault_client import vault_client # <--- IMPORTACIÓN CORRECTA

def create_asset(db: Session, data: AssetCreate, user_id: str, **kwargs) -> Asset:
    # 1. Extraemos la contraseña y preparamos los datos para la DB
    password = data.password 
    asset_data = data.model_dump(exclude={'password'}) # Excluimos el password de la DB 
    
    # 2. Creamos el activo en PostgreSQL
    asset = Asset(**asset_data)
    db.add(asset)
    db.flush()  # Obtenemos el ID del activo sin cerrar la transacción [cite: 211]

    # 3. Si hay contraseña, la enviamos a Vault
    if password:
        v_path = f"assets/{asset.id}/credentials" # Ruta única en Vault [cite: 473]
        vault_client.store_credentials(v_path, {"password": password}) # Guardado seguro [cite: 471]
        asset.vault_path = v_path # Solo guardamos la RUTA en la DB [cite: 228]

    # 4. Registramos la acción en el Log de Auditoría (ENS Alto)
    _log_audit(
        db, asset, AuditActionEnum.CREDENTIAL_ACCESS, 
        user_id=user_id, 
        reason="Cifrado de credenciales en Vault iniciado"
    )
    
    db.commit() # Guardamos todo
    db.refresh(asset)
    return asset


def get_asset(db: Session, asset_id: int, include_deleted: bool = False) -> Optional[Asset]:
    """Get a single asset by ID."""
    query = db.query(Asset).filter(Asset.id == asset_id)
    if not include_deleted:
        query = query.filter(Asset.deleted_at.is_(None))
    return query.first()


def get_asset_by_ip(db: Session, ip: str) -> Optional[Asset]:
    """Find active asset by IP."""
    return db.query(Asset).filter(
        Asset.ip == ip,
        Asset.deleted_at.is_(None),
    ).first()


def list_assets(
    db: Session,
    page: int = 1,
    page_size: int = 50,
    criticidad: Optional[CriticidadEnum] = None,
    tipo: Optional[TipoActivoEnum] = None,
    status: Optional[AssetStatusEnum] = None,
    search: Optional[str] = None,
    include_deleted: bool = False,
) -> Tuple[List[Asset], int]:
    """List assets with pagination and filters. Returns (items, total)."""
    query = db.query(Asset)

    if not include_deleted:
        query = query.filter(Asset.deleted_at.is_(None))
    if criticidad:
        query = query.filter(Asset.criticidad == criticidad)
    if tipo:
        query = query.filter(Asset.tipo == tipo)
    if status:
        query = query.filter(Asset.status == status)
    if search:
        like = f"%{search}%"
        query = query.filter(
            (Asset.ip.ilike(like))
            | (Asset.hostname.ilike(like))
            | (Asset.responsable.ilike(like))
        )

    total = query.count()
    items = (
        query
        .order_by(Asset.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


def update_asset(
    db: Session,
    asset_id: int,
    data: AssetUpdate,
    user_id: str,
    user_role: Optional[str] = None,
    ip_origin: Optional[str] = None,
    reason: Optional[str] = None,
) -> Optional[Asset]:
    """Update an asset and log changes."""
    asset = get_asset(db, asset_id)
    if asset is None:
        return None

    snapshot_before = _asset_to_dict(asset)
    changes = {}

    update_data = data.model_dump(exclude_unset=True)
    for field, new_value in update_data.items():
        old_value = getattr(asset, field)
        if old_value != new_value:
            changes[field] = {"old": str(old_value), "new": str(new_value)}
            setattr(asset, field, new_value)

    if not changes:
        return asset  # nothing changed

    snapshot_after = _asset_to_dict(asset)
    _log_audit(
        db, asset, AuditActionEnum.UPDATE,
        user_id=user_id, user_role=user_role,
        changes=changes,
        snapshot_before=snapshot_before,
        snapshot_after=snapshot_after,
        ip_origin=ip_origin, reason=reason,
    )
    db.commit()
    db.refresh(asset)
    return asset


def delete_asset(
    db: Session,
    asset_id: int,
    user_id: str,
    user_role: Optional[str] = None,
    ip_origin: Optional[str] = None,
    reason: Optional[str] = None,
) -> Optional[Asset]:
    """Soft-delete an asset and log the action."""
    asset = get_asset(db, asset_id)
    if asset is None:
        return None

    snapshot_before = _asset_to_dict(asset)
    asset.soft_delete()
    snapshot_after = _asset_to_dict(asset)

    _log_audit(
        db, asset, AuditActionEnum.DELETE,
        user_id=user_id, user_role=user_role,
        snapshot_before=snapshot_before,
        snapshot_after=snapshot_after,
        ip_origin=ip_origin, reason=reason,
    )
    db.commit()
    db.refresh(asset)
    return asset


def get_audit_logs(
    db: Session,
    asset_id: int,
    limit: int = 100,
) -> Tuple[List[AssetAuditLog], int]:
    """Get audit logs for an asset (US-1.5)."""
    query = db.query(AssetAuditLog).filter(AssetAuditLog.asset_id == asset_id)
    total = query.count()
    items = query.order_by(AssetAuditLog.timestamp.desc()).limit(limit).all()
    return items, total
