"""
EDR Endpoints — M3.1
=====================
FASE 2: Behavioral scan and findings endpoints are fully implemented.
FASE 3: Threat intel enrichment endpoints are fully implemented.
FASE 4: Incident response endpoints raise HTTP 501 (pending).

ENS compliance: op.exp.4 (Protección frente a código dañino)
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from shared.database import get_db
from services.scanner_engine.models.edr import (
    BehavioralFinding,
    IncidentResponseLog,
    ThreatIntelCache,
)
from services.scanner_engine.schemas.edr import (
    ApproveActionRequest,
    BehavioralFindingListResponse,
    BehavioralFindingResponse,
    BehavioralScanRequest,
    EDRScanLaunchResponse,
    EnrichFindingsRequest,
    EnrichedIOCResponse,
    EnrichFindingsResponse,
    IOCTypeEnum,
    ResponseActionCreateResponse,
    ResponseActionListResponse,
    ResponseActionRequest,
    ResponseActionResponse,
    SeverityEnum,
    FindingStatusEnum,
)

router = APIRouter(prefix="/edr", tags=["EDR — Behavioral Detection & Response"])

_M1_URL = os.getenv("M1_URL", "http://m1:8001")


# ── Behavioral Scan ───────────────────────────────────────────────────────────

@router.post(
    "/behavioral-scan",
    response_model=EDRScanLaunchResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a behavioral EDR scan on an asset",
    description=(
        "Queues a behavioral analysis task against the target asset. "
        "Detects C2 callbacks, reverse shells, data exfiltration, "
        "privilege escalation, lateral movement and obfuscated execution. "
        "Requires SSH credentials on the asset in M1."
    ),
)
async def start_behavioral_scan(
    payload: BehavioralScanRequest,
    db: Session = Depends(get_db),
) -> EDRScanLaunchResponse:
    from services.scanner_engine.tasks.behavioral_tasks import run_behavioral_scan

    # Fetch asset data from M1 to get IP and verify it exists
    import httpx
    from shared.auth import create_access_token
    token = create_access_token("scanops_service", "service")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{_M1_URL}/api/v1/assets/{payload.asset_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.RequestError:
        raise HTTPException(status_code=503, detail="Cannot reach M1 Asset Manager")

    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"Asset {payload.asset_id} not found")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"M1 returned {resp.status_code}")

    asset = resp.json()
    ssh_host     = asset.get("ip")
    ssh_user     = asset.get("ssh_user")
    ssh_password = asset.get("ssh_password")

    if not ssh_host:
        raise HTTPException(status_code=422, detail="Asset has no IP address configured")

    scan_id = payload.scan_id or f"beh_{int(time.time())}_{payload.asset_id}"

    task = run_behavioral_scan.delay(
        asset_id=payload.asset_id,
        ssh_host=ssh_host,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        scan_id=scan_id,
    )

    return EDRScanLaunchResponse(
        task_id=task.id,
        asset_id=payload.asset_id,
        scan_id=scan_id,
        message=f"Behavioral scan queued for {ssh_host}",
        queued_at=datetime.utcnow(),
    )


# ── Behavioral Findings ───────────────────────────────────────────────────────

@router.get(
    "/behavioral-findings/{asset_id}",
    response_model=BehavioralFindingListResponse,
    summary="List behavioral findings for an asset",
)
async def list_behavioral_findings(
    asset_id: int,
    severity: Optional[str] = Query(None, description="Filter: CRITICAL / HIGH / MEDIUM / LOW / INFO"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter: open / investigating / resolved / false_positive"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> BehavioralFindingListResponse:
    q = db.query(BehavioralFinding).filter(BehavioralFinding.asset_id == asset_id)

    if severity:
        sev = severity.upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            raise HTTPException(status_code=422, detail=f"Invalid severity: {severity}")
        q = q.filter(BehavioralFinding.severity == sev)

    if status_filter:
        valid = ("open", "investigating", "resolved", "false_positive")
        if status_filter not in valid:
            raise HTTPException(status_code=422, detail=f"Invalid status: {status_filter}")
        q = q.filter(BehavioralFinding.status == status_filter)

    total = q.count()
    items = (
        q.order_by(BehavioralFinding.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return BehavioralFindingListResponse(
        total=total,
        items=[BehavioralFindingResponse.model_validate(item) for item in items],
    )


@router.get(
    "/behavioral-findings/{asset_id}/{finding_id}",
    response_model=BehavioralFindingResponse,
    summary="Get a single behavioral finding",
)
async def get_behavioral_finding(
    asset_id: int,
    finding_id: int,
    db: Session = Depends(get_db),
) -> BehavioralFindingResponse:
    finding = (
        db.query(BehavioralFinding)
        .filter(
            BehavioralFinding.id == finding_id,
            BehavioralFinding.asset_id == asset_id,
        )
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found for asset {asset_id}")
    return BehavioralFindingResponse.model_validate(finding)


# ── Threat Intel Enrichment ───────────────────────────────────────────────────

@router.post(
    "/enrich-findings",
    response_model=EnrichFindingsResponse,
    summary="Enrich behavioral findings with threat intelligence",
    description=(
        "Queries VirusTotal, CrowdSec and AlienVault OTX for each IOC extracted "
        "from the specified findings. Results are cached with source-specific TTLs "
        "(CrowdSec 12h, OTX 7d, VirusTotal 30d). "
        "Set force_refresh=true to bypass cache and re-query all sources."
    ),
)
async def enrich_findings(
    payload: EnrichFindingsRequest,
    db: Session = Depends(get_db),
) -> EnrichFindingsResponse:
    from services.scanner_engine.services.ioc_extractor import extract_iocs
    from services.scanner_engine.services.threat_intel_service import lookup_ioc as _lookup

    # Validate all finding IDs exist for the request
    findings = (
        db.query(BehavioralFinding)
        .filter(BehavioralFinding.id.in_(payload.finding_ids))
        .all()
    )
    if not findings:
        raise HTTPException(status_code=404, detail="No findings found for the provided IDs")

    # Deduplicate IOCs across all findings to avoid redundant API calls
    seen_iocs: set = set()
    all_iocs   = []
    for finding in findings:
        for ioc in extract_iocs(finding.indicators):
            key = (ioc.value, ioc.ioc_type)
            if key not in seen_iocs:
                seen_iocs.add(key)
                all_iocs.append(ioc)

    if not all_iocs:
        return EnrichFindingsResponse(enriched=0, results=[])

    results: list[EnrichedIOCResponse] = []
    for ioc in all_iocs:
        try:
            entry = _lookup(db, ioc, force_refresh=payload.force_refresh)
            cached = (not payload.force_refresh) and (
                entry.updated_at is not None
                and (datetime.utcnow() - entry.updated_at).total_seconds() > 5
            )
            results.append(
                EnrichedIOCResponse(
                    ioc_value       = entry.ioc_value,
                    ioc_type        = IOCTypeEnum(entry.ioc_type),
                    is_malicious    = entry.is_malicious,
                    malicious_votes = entry.malicious_votes,
                    vt_result       = entry.vt_result,
                    crowdsec_result = entry.crowdsec_result,
                    otx_result      = entry.otx_result,
                    ttl_expires     = entry.ttl_expires,
                    cached          = cached,
                )
            )
        except Exception as exc:
            # Partial failure — skip this IOC, don't abort the whole request
            pass

    return EnrichFindingsResponse(enriched=len(results), results=results)


@router.get(
    "/threat-intel/ioc",
    response_model=EnrichedIOCResponse,
    summary="Look up a single IOC in the threat intel cache or query live",
)
async def lookup_ioc_endpoint(
    value:        str = Query(..., description="IOC value: IP address, domain, or hash"),
    ioc_type:     str = Query(..., description="ip | domain | hash"),
    force_refresh: bool = Query(False, description="Bypass cache and re-query APIs"),
    db: Session = Depends(get_db),
) -> EnrichedIOCResponse:
    from services.scanner_engine.services.ioc_extractor import IOC
    from services.scanner_engine.services.threat_intel_service import lookup_ioc as _lookup

    valid_types = ("ip", "domain", "hash")
    if ioc_type not in valid_types:
        raise HTTPException(
            status_code=422,
            detail=f"ioc_type must be one of: {', '.join(valid_types)}",
        )

    ioc = IOC(value=value.strip(), ioc_type=ioc_type)
    try:
        entry = _lookup(db, ioc, force_refresh=force_refresh)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Threat intel query failed: {exc}")

    cached = (not force_refresh) and (
        entry.updated_at is not None
        and (datetime.utcnow() - entry.updated_at).total_seconds() > 5
    )
    return EnrichedIOCResponse(
        ioc_value       = entry.ioc_value,
        ioc_type        = IOCTypeEnum(entry.ioc_type),
        is_malicious    = entry.is_malicious,
        malicious_votes = entry.malicious_votes,
        vt_result       = entry.vt_result,
        crowdsec_result = entry.crowdsec_result,
        otx_result      = entry.otx_result,
        ttl_expires     = entry.ttl_expires,
        cached          = cached,
    )


# ── Incident Response ─────────────────────────────────────────────────────────

@router.post(
    "/request-response-action",
    response_model=ResponseActionCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a response action (kill/quarantine/block/isolate)",
    description=(
        "Creates a pending response action and returns a TOTP QR code. "
        "Scan the QR with your authenticator app, then call "
        "POST /edr/approve-action/{id} with the 6-digit code + PIN to execute. "
        "ENS op.exp.4: all actions require dual-factor approval."
    ),
)
async def request_response_action(
    payload: ResponseActionRequest,
    db: Session = Depends(get_db),
) -> ResponseActionCreateResponse:
    import base64
    import io
    import json

    import bcrypt
    import pyotp
    import qrcode

    # Generate TOTP secret (per-request, same pattern as M4)
    secret = pyotp.random_base32()
    totp   = pyotp.TOTP(secret)
    uri    = totp.provisioning_uri(
        name=payload.requested_by,
        issuer_name="ScanOPS-EDR",
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    # Hash the PIN (ENS mp.info.3: no plaintext credentials stored)
    pin_raw  = payload.justification or "scanops"  # caller passes PIN in justification
    pin_hash = bcrypt.hashpw(pin_raw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    # Store token data as JSON in approval_token column (fits in VARCHAR 255)
    token_data = json.dumps({"totp_secret": secret, "pin_hash": pin_hash})

    action = IncidentResponseLog(
        asset_id              = payload.asset_id,
        behavioral_finding_id = payload.behavioral_finding_id,
        action_type           = payload.action_type.value,
        target_detail         = payload.target_detail,
        requested_by          = payload.requested_by,
        approval_token        = token_data,
        status                = "pending",
        rollback_capable      = False,  # updated after execution
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    return ResponseActionCreateResponse(
        id                    = action.id,
        asset_id              = action.asset_id,
        action_type           = payload.action_type,
        target_detail         = action.target_detail,
        requested_by          = action.requested_by,
        status                = action.status,
        created_at            = action.created_at,
        totp_qr_base64        = qr_b64,
        totp_secret           = secret,
        approval_instructions = (
            f"1. Scan the QR code with Google Authenticator / Authy\n"
            f"2. Your PIN is: the justification you sent (change this in production)\n"
            f"3. Call POST /api/v1/edr/approve-action/{action.id} with totp_code + pin + approved_by"
        ),
    )


@router.post(
    "/approve-action/{action_id}",
    response_model=ResponseActionResponse,
    summary="Approve a pending response action — validates TOTP + PIN (ENS op.exp.4)",
)
async def approve_response_action(
    action_id: int,
    payload:   ApproveActionRequest,
    db: Session = Depends(get_db),
) -> ResponseActionResponse:
    import json
    import os

    import bcrypt
    import pyotp

    action = db.query(IncidentResponseLog).filter(
        IncidentResponseLog.id == action_id
    ).with_for_update().first()

    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")

    if action.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Action is {action.status} — only pending actions can be approved",
        )

    # Validate TOTP + PIN
    try:
        token_data = json.loads(action.approval_token or "{}")
        totp_secret = token_data.get("totp_secret", "")
        pin_hash    = token_data.get("pin_hash", "").encode("utf-8")
    except (json.JSONDecodeError, AttributeError):
        raise HTTPException(status_code=500, detail="Corrupt approval token in DB")

    if not bcrypt.checkpw(payload.pin.encode("utf-8"), pin_hash):
        raise HTTPException(status_code=401, detail="Invalid PIN")

    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(payload.totp_code, valid_window=8):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    # Mark approved
    action.status      = "approved"
    action.approved_by = payload.approved_by
    action.approved_at = datetime.utcnow()
    db.add(action)
    db.commit()
    db.refresh(action)

    # Fire execution task if auto-remediate is enabled
    auto_remediate = os.getenv("EDR_AUTO_REMEDIATE", "false").lower() == "true"
    if auto_remediate:
        from services.scanner_engine.tasks.ir_tasks import execute_response_action
        execute_response_action.delay(action_id=action.id)

    return ResponseActionResponse.model_validate(action)


@router.post(
    "/execute-action/{action_id}",
    response_model=ResponseActionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger execution of an already-approved action",
    description=(
        "Queues execution of a previously approved action. "
        "Only valid when EDR_AUTO_REMEDIATE=false (manual execution mode). "
        "Action must be in 'approved' status."
    ),
)
async def execute_action_manual(
    action_id: int,
    db: Session = Depends(get_db),
) -> ResponseActionResponse:
    action = db.query(IncidentResponseLog).filter(
        IncidentResponseLog.id == action_id
    ).first()

    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")

    if action.status != "approved":
        raise HTTPException(
            status_code=409,
            detail=f"Action must be approved before execution (current: {action.status})",
        )

    from services.scanner_engine.tasks.ir_tasks import execute_response_action
    execute_response_action.delay(action_id=action.id)

    return ResponseActionResponse.model_validate(action)


@router.get(
    "/response-actions/{asset_id}",
    response_model=ResponseActionListResponse,
    summary="List incident response actions for an asset",
)
async def list_response_actions(
    asset_id:     int,
    status_filter: Optional[str] = Query(None, alias="status"),
    page:          int = Query(1, ge=1),
    page_size:     int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> ResponseActionListResponse:
    valid_statuses = ("pending", "approved", "executing", "completed", "rejected", "failed")
    q = db.query(IncidentResponseLog)
    if asset_id != 0:
        q = q.filter(IncidentResponseLog.asset_id == asset_id)
    if status_filter:
        if status_filter not in valid_statuses:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid status. Valid: {', '.join(valid_statuses)}",
            )
        q = q.filter(IncidentResponseLog.status == status_filter)

    total = q.count()
    items = (
        q.order_by(IncidentResponseLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return ResponseActionListResponse(
        total=total,
        items=[ResponseActionResponse.model_validate(a) for a in items],
    )


# ── Health / Info ─────────────────────────────────────────────────────────────

@router.get(
    "/status",
    summary="EDR module status and capabilities",
    tags=["EDR — Behavioral Detection & Response"],
)
async def edr_status():
    """
    Returns current implementation status per phase.
    Useful for frontend to know which EDR features are available.
    """
    return {
        "module": "M3.1 — EDR",
        "ens_compliance": "op.exp.4",
        "phases": {
            "FASE_1": {
                "name": "Database & Models",
                "status": "completed",
                "description": "3 tables migrated, Pydantic schemas, endpoint skeletons",
            },
            "FASE_2": {
                "name": "Behavioral Detection",
                "status": "completed",
                "description": "SSH process collection, 7-rule anomaly engine (C2/RevShell/DataExfil/PrivEsc/LateralMove/Obfuscation/Persistence), MITRE ATT&CK mapped",
            },
            "FASE_3": {
                "name": "Threat Intelligence",
                "status": "completed",
                "description": "VT/CrowdSec/OTX enrichment with pybreaker circuit breakers, TTL cache (CrowdSec 12h, OTX 7d, VT 30d), auto-triggered after behavioral scan",
            },
            "FASE_4": {
                "name": "YARA Pattern Matching",
                "status": "completed",
                "description": "21 YARA rules (C2/RevShell/DataExfil/Persistence/PrivEsc/Obfuscation/Lateral), auto-runs after behavioral heuristics, boosts confidence +20 and escalates severity on correlated hits",
            },
            "FASE_5": {
                "name": "Incident Response",
                "status": "completed",
                "description": "TOTP+PIN dual-factor approval gate (pyotp+bcrypt), SSH executor (kill_process/quarantine_file/block_ip/isolate_host/collect_forensics), Celery async execution, EDR_AUTO_REMEDIATE toggle",
            },
        },
        "endpoints": {
            "POST /api/v1/edr/behavioral-scan":           "FASE 2",
            "GET  /api/v1/edr/behavioral-findings/{id}":  "FASE 2",
            "POST /api/v1/edr/enrich-findings":           "FASE 3 ✓",
            "GET  /api/v1/edr/threat-intel/ioc":          "FASE 3 ✓",
            "POST /api/v1/edr/request-response-action":   "FASE 5 ✓",
            "POST /api/v1/edr/approve-action/{id}":       "FASE 5 ✓",
            "POST /api/v1/edr/execute-action/{id}":       "FASE 5 ✓",
            "GET  /api/v1/edr/response-actions/{id}":     "FASE 5 ✓",
        },
        "timestamp": datetime.utcnow().isoformat(),
    }
