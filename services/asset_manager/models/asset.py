"""
Asset Models — US-1.1
=====================
SQLAlchemy models for the Asset Manager (M1).

ENS Alto compliance:
  - [op.exp.1] Inventario de activos actualizado permanentemente
  - [op.acc.6] Control de privilegios
  - [mp.info.3] Credenciales cifradas vía Vault (solo vault_path en BD)
  - [op.exp.5] Trazabilidad alta/baja (AssetAuditLog)
"""

import enum
from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, DateTime, Enum, Text,
    Boolean, ForeignKey, JSON, Index,
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


# ─── Enums ────────────────────────────────────────────────

class CriticidadEnum(str, enum.Enum):
    BAJA = "BAJA"
    MEDIA = "MEDIA"
    ALTA = "ALTA"
    PENDIENTE_CLASIFICAR = "PENDIENTE_CLASIFICAR"


class TipoActivoEnum(str, enum.Enum):
    ENDPOINT = "ENDPOINT"
    SERVER = "SERVER"
    RED = "RED"
    APLICACION = "APLICACION"
    IOT = "IOT"
    OTRO = "OTRO"


class AssetStatusEnum(str, enum.Enum):
    ACTIVO = "ACTIVO"
    BAJA = "BAJA"
    MANTENIMIENTO = "MANTENIMIENTO"
    PENDIENTE_ALTA = "PENDIENTE_ALTA"


class AuditActionEnum(str, enum.Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    RESTORE = "RESTORE"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"


# ─── SQLAlchemy Models ────────────────────────────────────

class Asset(Base):
    """Core asset model — the 'DNI del activo' consumed by M2-M5."""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Identity
    ip = Column(String(45), nullable=False, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    dominio = Column(String(255), nullable=True)
    mac_address = Column(String(17), nullable=True)

    # Classification
    criticidad = Column(
        Enum(CriticidadEnum),
        nullable=False,
        default=CriticidadEnum.PENDIENTE_CLASIFICAR,
        index=True,
    )
    tipo = Column(
        Enum(TipoActivoEnum),
        nullable=False,
        default=TipoActivoEnum.OTRO,
        index=True,
    )
    status = Column(
        Enum(AssetStatusEnum),
        nullable=False,
        default=AssetStatusEnum.ACTIVO,
        index=True,
    )

    # Ownership
    responsable = Column(String(255), nullable=False)
    departamento = Column(String(255), nullable=True)
    ubicacion = Column(String(255), nullable=True)

    # ENS tags & notes
    tags_ens = Column(JSON, nullable=True, default=list)
    notas = Column(Text, nullable=True)

    # Vault (US-1.3)
    vault_path = Column(String(500), nullable=True)

    # External sync (US-1.6)
    external_id = Column(String(255), nullable=True, index=True)
    external_source = Column(String(50), nullable=True)

    # Discovery (US-1.4)
    discovered_by = Column(String(50), nullable=True)
    network_range = Column(String(50), nullable=True)

    # OS info (useful for M3)
    os_family = Column(String(50), nullable=True)
    os_version = Column(String(100), nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True)

    # Relationships
    audit_logs = relationship(
        "AssetAuditLog",
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="AssetAuditLog.timestamp.desc()",
    )

    __table_args__ = (
        Index("ix_assets_ip_status", "ip", "status"),
        Index("ix_assets_criticidad_tipo", "criticidad", "tipo"),
        Index("ix_assets_external", "external_source", "external_id"),
    )

    def __repr__(self):
        return f"<Asset(id={self.id}, ip='{self.ip}', criticidad='{self.criticidad}')>"

    @property
    def is_active(self) -> bool:
        return self.deleted_at is None and self.status == AssetStatusEnum.ACTIVO

    def soft_delete(self):
        self.deleted_at = datetime.utcnow()
        self.status = AssetStatusEnum.BAJA


class AssetAuditLog(Base):
    """Immutable audit trail for asset changes — US-1.5."""
    __tablename__ = "asset_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    action = Column(Enum(AuditActionEnum), nullable=False)
    user_id = Column(String(255), nullable=False)
    user_role = Column(String(100), nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    changes = Column(JSON, nullable=True)
    snapshot_before = Column(JSON, nullable=True)
    snapshot_after = Column(JSON, nullable=True)

    ip_origin = Column(String(45), nullable=True)
    reason = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_asset_action", "asset_id", "action"),
        Index("ix_audit_user", "user_id"),
    )

    def __repr__(self):
        return f"<AuditLog(id={self.id}, asset={self.asset_id}, action='{self.action}')>"
