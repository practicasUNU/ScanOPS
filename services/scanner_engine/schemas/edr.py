"""
EDR Pydantic Schemas
====================
Request / response models for the EDR endpoints.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, ConfigDict


# ── Enums ─────────────────────────────────────────────────────────────────────

class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class AnomalyTypeEnum(str, Enum):
    C2_CALLBACK      = "C2_CALLBACK"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    LATERAL_MOVEMENT  = "LATERAL_MOVEMENT"
    PRIVILEGE_ESC     = "PRIVILEGE_ESCALATION"
    PERSISTENCE       = "PERSISTENCE"
    DEFENSE_EVASION   = "DEFENSE_EVASION"
    SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS"
    YARA_MATCH        = "YARA_MATCH"
    UNKNOWN           = "UNKNOWN"


class DetectionMethodEnum(str, Enum):
    BEHAVIORAL_HEURISTIC = "behavioral_heuristic"
    YARA                 = "yara"
    C2_PATTERN           = "c2_pattern"
    NETWORK_ANOMALY      = "network_anomaly"
    PROCESS_HOLLOW       = "process_hollowing"
    STATIC_ANALYSIS      = "static_analysis"


class IOCTypeEnum(str, Enum):
    IP     = "ip"
    DOMAIN = "domain"
    HASH   = "hash"
    URL    = "url"


class ActionTypeEnum(str, Enum):
    QUARANTINE_FILE   = "quarantine_file"
    KILL_PROCESS      = "kill_process"
    BLOCK_IP          = "block_ip"
    ISOLATE_HOST      = "isolate_host"
    COLLECT_FORENSICS = "collect_forensics"


class FindingStatusEnum(str, Enum):
    OPEN           = "open"
    INVESTIGATING  = "investigating"
    RESOLVED       = "resolved"
    FALSE_POSITIVE = "false_positive"


class IRStatusEnum(str, Enum):
    PENDING   = "pending"
    APPROVED  = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    REJECTED  = "rejected"
    FAILED    = "failed"


# ── BehavioralFinding ─────────────────────────────────────────────────────────

class BehavioralScanRequest(BaseModel):
    """POST /edr/behavioral-scan — start a behavioral scan on an asset."""
    asset_id: int
    scan_id: Optional[str] = None
    techniques: Optional[List[str]] = Field(
        default=None,
        description="MITRE ATT&CK technique IDs to focus on, e.g. ['T1059','T1055']",
    )


class BehavioralFindingResponse(BaseModel):
    """Single behavioral finding."""
    id: int
    asset_id: int
    scan_id: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    anomaly_type: str
    severity: SeverityEnum
    confidence_score: int = Field(ge=0, le=100)
    detection_method: Optional[str] = None
    indicators: Optional[Dict[str, Any]] = None
    mitre_attack_tactics: Optional[List[str]] = None
    remediation_suggested: Optional[str] = None
    status: FindingStatusEnum
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class BehavioralFindingListResponse(BaseModel):
    total: int
    items: List[BehavioralFindingResponse]


# ── ThreatIntel ───────────────────────────────────────────────────────────────

class EnrichFindingsRequest(BaseModel):
    """POST /edr/enrich-findings — enrich behavioral findings with threat intel."""
    finding_ids: List[int] = Field(..., min_length=1, max_length=100)
    force_refresh: bool = Field(
        default=False,
        description="Bypass cache TTL and query APIs directly.",
    )


class EnrichedIOCResponse(BaseModel):
    """Single enriched IOC result."""
    ioc_value: str
    ioc_type: IOCTypeEnum
    is_malicious: bool
    malicious_votes: int
    vt_result: Optional[Dict[str, Any]] = None
    crowdsec_result: Optional[Dict[str, Any]] = None
    otx_result: Optional[Dict[str, Any]] = None
    ttl_expires: datetime
    cached: bool = False

    model_config = ConfigDict(from_attributes=True)


class EnrichFindingsResponse(BaseModel):
    enriched: int
    results: List[EnrichedIOCResponse]


# ── IncidentResponse ──────────────────────────────────────────────────────────

class ResponseActionRequest(BaseModel):
    """POST /edr/request-response-action — request a response action."""
    asset_id: int
    behavioral_finding_id: Optional[int] = None
    action_type: ActionTypeEnum
    target_detail: str = Field(..., min_length=1, max_length=512)
    requested_by: str = Field(..., min_length=1, max_length=100)
    justification: Optional[str] = Field(None, max_length=1000)

    @field_validator("target_detail")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class ResponseActionResponse(BaseModel):
    """Response action log entry."""
    id: int
    asset_id: int
    behavioral_finding_id: Optional[int] = None
    action_type: ActionTypeEnum
    target_detail: str
    requested_by: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    status: IRStatusEnum
    result_output: Optional[str] = None
    rollback_capable: bool
    execution_duration_ms: Optional[int] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ResponseActionListResponse(BaseModel):
    total: int
    items: List[ResponseActionResponse]


class ApproveActionRequest(BaseModel):
    """POST /edr/approve-action/{action_id} — approve a pending response action."""
    totp_code:   str = Field(..., min_length=6, max_length=8, description="6-digit TOTP code from authenticator app")
    pin:         str = Field(..., min_length=4, max_length=20, description="PIN set when the action was requested")
    approved_by: str = Field(..., min_length=1, max_length=100)


class ResponseActionCreateResponse(BaseModel):
    """Returned only on POST /edr/request-response-action (includes TOTP setup info)."""
    id:                   int
    asset_id:             int
    action_type:          ActionTypeEnum
    target_detail:        str
    requested_by:         str
    status:               IRStatusEnum
    created_at:           datetime
    totp_qr_base64:       str = Field(..., description="PNG QR code as base64, scan with authenticator app")
    totp_secret:          str = Field(..., description="TOTP secret for manual entry")
    approval_instructions: str


# ── Scan Launch ───────────────────────────────────────────────────────────────

class EDRScanLaunchResponse(BaseModel):
    """Immediate response when an EDR scan is queued."""
    task_id: str
    asset_id: int
    scan_id: str
    message: str
    queued_at: datetime
