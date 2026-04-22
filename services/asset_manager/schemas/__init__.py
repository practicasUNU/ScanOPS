"""
Asset Schemas — US-1.1 / US-1.7
================================
Pydantic schemas for API validation and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field, field_validator, ConfigDict

from services.asset_manager.models.asset import (
    CriticidadEnum,
    TipoActivoEnum,
    AssetStatusEnum,
    AuditActionEnum,
)


# ─── Validators ───────────────────────────────────────────

def _validate_ip(v: str) -> str:
    import ipaddress
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(f"'{v}' is not a valid IPv4 or IPv6 address")
    return v


def _validate_mac(v: Optional[str]) -> Optional[str]:
    if v is None:
        return v
    import re
    if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", v):
        raise ValueError(f"'{v}' is not a valid MAC address")
    return v.upper()


def _validate_tags_ens(v: Optional[List[str]]) -> Optional[List[str]]:
    if v is None:
        return v
    import re
    for tag in v:
        if not re.match(r"^(op|mp|org)\.[a-z]+\.\d+$", tag):
            raise ValueError(f"ENS tag '{tag}' invalid. Expected: 'op.exp.1'")
    return v


# ─── Create / Update ─────────────────────────────────────

class AssetCreate(BaseModel):
    """POST /assets"""
    ip: str = Field(..., min_length=7, max_length=45)
    hostname: Optional[str] = Field(None, max_length=255)
    dominio: Optional[str] = Field(None, max_length=255)
    mac_address: Optional[str] = Field(None, max_length=17)
    criticidad: CriticidadEnum = CriticidadEnum.PENDIENTE_CLASIFICAR
    tipo: TipoActivoEnum = TipoActivoEnum.OTRO
    status: AssetStatusEnum = AssetStatusEnum.ACTIVO
    responsable: str = Field(..., min_length=1, max_length=255)
    departamento: Optional[str] = Field(None, max_length=255)
    ubicacion: Optional[str] = Field(None, max_length=255)
    tags_ens: Optional[List[str]] = Field(default_factory=list)
    notas: Optional[str] = None
    os_family: Optional[str] = Field(None, max_length=50)
    os_version: Optional[str] = Field(None, max_length=100)
    password: Optional[str] = Field(None, description="Contraseña que se enviará a Vault")

    _validate_ip = field_validator("ip")(_validate_ip)
    _validate_mac = field_validator("mac_address")(_validate_mac)
    _validate_tags = field_validator("tags_ens")(_validate_tags_ens)


class AssetUpdate(BaseModel):
    """PUT /assets/{id} — all fields optional."""
    ip: Optional[str] = Field(None, min_length=7, max_length=45)
    hostname: Optional[str] = Field(None, max_length=255)
    dominio: Optional[str] = Field(None, max_length=255)
    mac_address: Optional[str] = Field(None, max_length=17)
    criticidad: Optional[CriticidadEnum] = None
    tipo: Optional[TipoActivoEnum] = None
    status: Optional[AssetStatusEnum] = None
    responsable: Optional[str] = Field(None, max_length=255)
    departamento: Optional[str] = Field(None, max_length=255)
    ubicacion: Optional[str] = Field(None, max_length=255)
    tags_ens: Optional[List[str]] = None
    notas: Optional[str] = None
    os_family: Optional[str] = Field(None, max_length=50)
    os_version: Optional[str] = Field(None, max_length=100)

    _validate_ip = field_validator("ip")(_validate_ip)
    _validate_mac = field_validator("mac_address")(_validate_mac)
    _validate_tags = field_validator("tags_ens")(_validate_tags_ens)


# ─── Responses ────────────────────────────────────────────

class AssetResponse(BaseModel):
    """Single asset in API responses."""
    id: int
    ip: str
    hostname: Optional[str] = None
    dominio: Optional[str] = None
    mac_address: Optional[str] = None
    criticidad: CriticidadEnum
    tipo: TipoActivoEnum
    status: AssetStatusEnum
    responsable: str
    departamento: Optional[str] = None
    ubicacion: Optional[str] = None
    tags_ens: Optional[List[str]] = None
    notas: Optional[str] = None
    vault_path: Optional[str] = None
    external_id: Optional[str] = None
    external_source: Optional[str] = None
    discovered_by: Optional[str] = None
    network_range: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AssetListResponse(BaseModel):
    """Paginated list for GET /assets."""
    total: int
    page: int
    page_size: int
    items: List[AssetResponse]


class AssetFicha(BaseModel):
    """
    'Ficha Única del Activo' — US-1.7.
    Consolidated doc consumed by M2/M3/M4.
    """
    id: int
    ip: str
    hostname: Optional[str] = None
    dominio: Optional[str] = None
    criticidad: CriticidadEnum
    tipo: TipoActivoEnum
    status: AssetStatusEnum
    responsable: str
    departamento: Optional[str] = None
    ubicacion: Optional[str] = None
    tags_ens: Optional[List[str]] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    vault_path: Optional[str] = None

    # Populated by M2 (Hito 2) and M3 (Hito 3)
    superficie: Optional[Dict[str, Any]] = None
    vulnerabilidades: Optional[List[Dict[str, Any]]] = None

    ficha_generated_at: datetime = Field(default_factory=datetime.utcnow)
    ficha_version: str = "1.0"

    model_config = ConfigDict(from_attributes=True)


# ─── Audit Log ────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    id: int
    asset_id: int
    action: AuditActionEnum
    user_id: str
    user_role: Optional[str] = None
    timestamp: datetime
    changes: Optional[Dict[str, Any]] = None
    ip_origin: Optional[str] = None
    reason: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AuditLogListResponse(BaseModel):
    total: int
    items: List[AuditLogResponse]


# ─── Discovery (US-1.4) ──────────────────────────────────

class DiscoveryRequest(BaseModel):
    network_ranges: List[str] = Field(..., min_length=1)
    responsable_default: str = "Pendiente asignar"

    @field_validator("network_ranges")
    @classmethod
    def validate_ranges(cls, v: List[str]) -> List[str]:
        import ipaddress
        for cidr in v:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise ValueError(f"'{cidr}' is not a valid CIDR range")
        return v


class DiscoveryResult(BaseModel):
    network_range: str
    hosts_scanned: int
    new_assets_found: int
    existing_assets_matched: int
    new_asset_ids: List[int] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime
