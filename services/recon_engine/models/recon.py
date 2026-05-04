"""
Reconnaissance Database Models
==============================
SQLAlchemy models — adaptados al schema real PostgreSQL.
ENS Alto [op.acc.1] - Trazabilidad y hechos técnicos.
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

ReconBase = declarative_base()

class ReconSnapshot(ReconBase):
    """
    Captura de superficie de ataque.
    M2: Solo hechos técnicos (reconocimiento).
    """
    __tablename__ = "recon_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cycle_id = Column(String(50), nullable=False, index=True)
    target = Column(String(255), nullable=False)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running")  # running, completed, error

    # OS Information (nuevas columnas)
    os_family = Column(String(100), nullable=True)
    os_version = Column(String(255), nullable=True)
    os_cpe = Column(String(255), nullable=True)
    os_confidence = Column(Float, nullable=True)

    # Host Information (nuevas columnas)
    mac_address = Column(String(50), nullable=True)
    mac_vendor = Column(String(255), nullable=True)
    latency_ms = Column(Float, nullable=True)

    # Relaciones
    findings = relationship("ReconFinding", back_populates="snapshot",
                            foreign_keys="ReconFinding.snapshot_id",
                            cascade="all, delete-orphan")
    subdomains = relationship("ReconSubdomain", back_populates="snapshot",
                              cascade="all, delete-orphan")


class ReconFinding(ReconBase):
    """
    Hallazgo de reconocimiento: puerto/servicio descubierto.
    M2: NO incluye severidades ni vulnerabilidades.
    """
    __tablename__ = "recon_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(Integer, ForeignKey("recon_snapshots.id"), nullable=False, index=True)
    host = Column(String(255), nullable=False, index=True)
    port = Column(String(20), nullable=True)
    service = Column(String(100), nullable=True)
    version = Column(String(255), nullable=True)
    state = Column(String(20), nullable=True)
    source = Column(String(20), nullable=True)
    first_seen_snapshot_id = Column(Integer, ForeignKey("recon_snapshots.id"), nullable=True)

    snapshot = relationship("ReconSnapshot", back_populates="findings",
                            foreign_keys=[snapshot_id])


class ReconSubdomain(ReconBase):
    """
    Subdominios descubiertos (US-2.2).
    """
    __tablename__ = "recon_subdomains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(Integer, ForeignKey("recon_snapshots.id"), nullable=False, index=True)
    subdomain = Column(String(255), nullable=False, index=True)
    source = Column(String(20), nullable=True, default="subfinder")

    snapshot = relationship("ReconSnapshot", back_populates="subdomains")