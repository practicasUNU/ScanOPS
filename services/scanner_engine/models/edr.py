"""
EDR SQLAlchemy Models
=====================
ORM representations of the three EDR tables created in migration 011.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    SmallInteger,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class BehavioralFinding(Base):
    """
    Anomalous process or behavioral indicator detected on a scanned asset.
    Populated by the Behavioral Detection module (FASE 2).
    """
    __tablename__ = 'behavioral_findings'

    id                   = Column(Integer, primary_key=True)
    asset_id             = Column(Integer, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_id              = Column(String(64), nullable=False, index=True)
    pid                  = Column(Integer, nullable=True)
    process_name         = Column(String(255), nullable=True)
    anomaly_type         = Column(String(50), nullable=False)
    severity             = Column(String(16), nullable=False, default='MEDIUM')
    confidence_score     = Column(SmallInteger, nullable=False, default=50)
    detection_method     = Column(String(50), nullable=True)
    indicators           = Column(JSON, nullable=True)
    mitre_attack_tactics = Column(JSON, nullable=True)
    remediation_suggested = Column(Text, nullable=True)
    status               = Column(String(20), nullable=False, default='open')
    created_at           = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at           = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ThreatIntelCache(Base):
    """
    Cached IOC reputation lookups from VirusTotal, CrowdSec and AlienVault OTX.
    TTL is set per-source at write time (VT: 30d, CrowdSec: 12h, OTX: 7d).
    """
    __tablename__ = 'threat_intel_cache'

    id              = Column(Integer, primary_key=True)
    ioc_value       = Column(String(512), nullable=False)
    ioc_type        = Column(String(20), nullable=False)
    vt_result       = Column(JSON, nullable=True)
    crowdsec_result = Column(JSON, nullable=True)
    otx_result      = Column(JSON, nullable=True)
    is_malicious    = Column(Boolean, nullable=False, default=False, index=True)
    malicious_votes = Column(SmallInteger, nullable=False, default=0)
    ttl_expires     = Column(DateTime, nullable=False, index=True)
    created_at      = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IncidentResponseLog(Base):
    """
    Audit trail for every response action executed against an asset.
    ENS op.exp.4: requires approval_token before status transitions to 'approved'.
    """
    __tablename__ = 'incident_response_log'

    id                    = Column(Integer, primary_key=True)
    asset_id              = Column(Integer, ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    behavioral_finding_id = Column(Integer, ForeignKey('behavioral_findings.id', ondelete='SET NULL'), nullable=True)
    action_type           = Column(String(50), nullable=False)
    target_detail         = Column(String(512), nullable=False)
    requested_by          = Column(String(100), nullable=False)
    approval_token        = Column(String(255), nullable=True)
    approved_by           = Column(String(100), nullable=True)
    approved_at           = Column(DateTime, nullable=True)
    executed_at           = Column(DateTime, nullable=True)
    status                = Column(String(20), nullable=False, default='pending', index=True)
    result_output         = Column(Text, nullable=True)
    rollback_capable      = Column(Boolean, nullable=False, default=False)
    execution_duration_ms = Column(Integer, nullable=True)
    created_at            = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at            = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
