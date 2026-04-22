"""
Reconnaissance Models
=====================
SQLAlchemy models for surface snapshots and findings.
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, declarative_base
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

Base = declarative_base()

# SQLAlchemy Models

class ReconSnapshot(Base):
    __tablename__ = "recon_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cycle_id = Column(String(50), nullable=False, index=True)  # ej: "2026-W17"
    target = Column(String(255), nullable=False)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running")  # running/completed/failed

    # Relationships
    findings = relationship("ReconFinding", back_populates="snapshot", foreign_keys="ReconFinding.snapshot_id")
    subdomains = relationship("ReconSubdomain", back_populates="snapshot", cascade="all, delete-orphan")


class ReconFinding(Base):
    __tablename__ = "recon_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(Integer, ForeignKey("recon_snapshots.id"), nullable=False, index=True)
    host = Column(String(255), nullable=False, index=True)
    port = Column(String(20), nullable=True)  # "22/tcp"
    service = Column(String(100), nullable=True)
    version = Column(String(255), nullable=True)
    state = Column(String(20), nullable=True)  # "open", "filtered", "closed"
    source = Column(String(20), nullable=True)  # "nmap", "masscan", "subfinder"
    first_seen_snapshot_id = Column(Integer, ForeignKey("recon_snapshots.id"), nullable=True)

    # Relationships
    snapshot = relationship("ReconSnapshot", back_populates="findings", foreign_keys=[snapshot_id])
    first_seen_snapshot = relationship("ReconSnapshot", foreign_keys=[first_seen_snapshot_id])


class ReconSubdomain(Base):
    __tablename__ = "recon_subdomains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(Integer, ForeignKey("recon_snapshots.id"), nullable=False, index=True)
    subdomain = Column(String(255), nullable=False, index=True)
    source = Column(String(20), default="subfinder")  # "subfinder"

    # Relationships
    snapshot = relationship("ReconSnapshot", back_populates="subdomains")


# Pydantic Schemas for API

class ReconFindingSchema(BaseModel):
    id: Optional[int] = None
    snapshot_id: int
    host: str
    port: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None
    state: Optional[str] = None
    source: Optional[str] = None
    first_seen_snapshot_id: Optional[int] = None

    class Config:
        from_attributes = True


class ReconSubdomainSchema(BaseModel):
    id: Optional[int] = None
    snapshot_id: int
    subdomain: str
    source: str = "subfinder"

    class Config:
        from_attributes = True


class ReconSnapshotSchema(BaseModel):
    id: Optional[int] = None
    cycle_id: str
    target: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: str = "running"
    findings: Optional[List[ReconFindingSchema]] = []
    subdomains: Optional[List[ReconSubdomainSchema]] = []

    class Config:
        from_attributes = True


# Surface Change Schemas

class SurfaceChangeDetail(BaseModel):
    type: str  # "new_port", "closed_port", "new_host", etc.
    host: str
    port: Optional[str] = None
    service: Optional[str] = None
    severity: str  # "CRITICA", "ALTA", "MEDIA", "INFO"
    description: str
    medida_ens: Optional[str] = None


class SurfaceChangesSummary(BaseModel):
    new_ports: int = 0
    closed_ports: int = 0
    new_hosts: int = 0
    lost_hosts: int = 0
    new_subdomains: int = 0
    lost_subdomains: int = 0
    service_changes: int = 0
    state_changes: int = 0
    total_changes: int = 0
    max_severity: str = "INFO"


class SurfaceChanges(BaseModel):
    has_changes: bool = False
    summary: SurfaceChangesSummary
    details: List[SurfaceChangeDetail] = []