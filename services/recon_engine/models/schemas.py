"""
Reconnaissance Pydantic Schemas
================================
Schemas para validación y serialización de API.
Separación de responsabilidades: M2 (Recon) vs M3 (Scanner).
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class HttpHeaders(BaseModel):
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    strict_transport_security: Optional[str] = None
    content_security_policy: Optional[str] = None


class TlsInfo(BaseModel):
    tls_version: Optional[str] = None
    cert_expiry: Optional[str] = None
    cert_issuer: Optional[str] = None
    days_until_expiry: Optional[int] = None


class PortDiscovery(BaseModel):
    """Puerto descubierto — datos técnicos puros (M2)."""
    port: int
    protocol: str = "tcp"
    state: str
    service: str
    version: str
    product: Optional[str] = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    http_headers: Optional[HttpHeaders] = None
    tls_info: Optional[TlsInfo] = None


class OSInformation(BaseModel):
    """Detección de SO (M2)."""
    detected_family: str
    detected_version: str
    cpe: Optional[str] = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class HostInformation(BaseModel):
    """Datos básicos del host."""
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    latency_ms: Optional[float] = None
    asn: Optional[str] = None
    asn_description: Optional[str] = None
    country: Optional[str] = None


class DomainRecon(BaseModel):
    domain: str
    dns_records: Dict[str, Any]
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    whois_info: Dict[str, Any]
    scanned_at: str


class SubdomainInfo(BaseModel):
    subdomain: str
    resolved_ip: Optional[str] = None
    source: str = "subfinder"


class ReconData(BaseModel):
    """Bloque principal de reconocimiento."""
    ports_discovered: List[PortDiscovery] = []
    os_information: Optional[OSInformation] = None
    host_information: Optional[HostInformation] = None
    domain_recon: Optional[DomainRecon] = None
    subdomains: List[SubdomainInfo] = []


class ChangeDetection(BaseModel):
    """Detección de cambios respecto a snapshot anterior."""
    new_ports: List[int] = []
    closed_ports: List[int] = []
    modified_services: List[Dict] = []


class ReconSummary(BaseModel):
    """Resumen cuantitativo (M2). SIN severidades."""
    total_ports_open: int = 0
    total_ports_filtered: int = 0
    total_services_detected: int = 0
    total_subdomains: int = 0
    ssl_active: bool = False
    firewall_detected: bool = False
    scan_duration_seconds: float = 0.0


class ReconSnapshotSchema(BaseModel):
    """Schema principal de salida de M2."""
    snapshot_id: str        # cycle_id del DB
    target: str
    status: str
    created_at: datetime    # started_at del DB
    finished_at: Optional[datetime] = None

    reconnaissance: ReconData
    subdomains: List[str] = []
    change_detection: ChangeDetection = Field(default_factory=ChangeDetection)
    summary: ReconSummary
    webcheck: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True
