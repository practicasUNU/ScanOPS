"""
Recon API Endpoints
==================
FastAPI endpoints for M2 Recon Engine.
Focused exclusively on technical facts (reconnaissance).
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from uuid import uuid4

from shared.database import get_db
from ..models.recon import ReconSnapshot, ReconFinding, ReconSubdomain
from ..models.schemas import (
    ReconSnapshotSchema, ReconData, ReconSummary, 
    PortDiscovery, OSInformation, HostInformation
)
from ..services.scanner_network import perform_full_recon

router = APIRouter(
    prefix="/api/v1",
    tags=["Recon Engine (M2)"]
)

@router.post("/scan", response_model=ReconSnapshotSchema)
async def start_scan(
    target: str = Query(..., description="Target IP or hostname"),
    db: Session = Depends(get_db)
):
    """
    Inicia un escaneo de reconocimiento completo (M2).
    Captura puertos, servicios, versiones y SO.
    """
    snapshot_id = f"scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{str(uuid4())[:8]}"
    
    # Por ahora lo ejecutamos síncronamente para la demo/test, 
    # en prod debería ser una tarea de Celery.
    result = await perform_full_recon(snapshot_id, target, db)
    return result

@router.get("/snapshots/{snapshot_id}/findings", response_model=ReconSnapshotSchema)
async def get_snapshot_recon(snapshot_id: str, db: Session = Depends(get_db)):
    """
    Obtiene los datos de reconocimiento de un snapshot.
    Solo reconocimiento, sin vulnerabilidades.
    """
    # Buscar por cycle_id (string), no por id (integer)
    snapshot = db.query(ReconSnapshot).filter(
        ReconSnapshot.cycle_id == snapshot_id
    ).first()

    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    # Reconstruir puertos desde recon_findings
    findings = db.query(ReconFinding).filter(
        ReconFinding.snapshot_id == snapshot.id
    ).all()

    ports_discovered = [
        PortDiscovery(
            port=int(f.port) if f.port and f.port.isdigit() else 0,
            protocol="tcp",
            state=f.state or "open",
            service=f.service or "unknown",
            version=f.version or "unknown",
            product=None,
            confidence=0.9 if f.source == "nmap" else 0.7
        )
        for f in findings if f.port
    ]

    # Reconstruir OS info desde BD
    os_information = None
    if snapshot.os_family:
        os_information = OSInformation(
            detected_family=snapshot.os_family,
            detected_version=snapshot.os_version or "Unknown",
            cpe=snapshot.os_cpe,
            confidence=snapshot.os_confidence or 0.5
        )

    # Reconstruir host info desde BD
    host_information = None
    if snapshot.mac_address or snapshot.latency_ms:
        host_information = HostInformation(
            mac_address=snapshot.mac_address,
            vendor=snapshot.mac_vendor,
            latency_ms=snapshot.latency_ms
        )

    recon_data = ReconData(
        ports_discovered=ports_discovered,
        os_information=os_information,
        host_information=host_information
    )

    summary = ReconSummary(
        total_ports_open=len(ports_discovered),
        total_services_detected=len([p for p in ports_discovered if p.service != "unknown"]),
        scan_duration_seconds=0.0
    )

    # Subdominios
    subdomains_db = db.query(ReconSubdomain).filter(
        ReconSubdomain.snapshot_id == snapshot.id
    ).all()
    subdomains = [s.subdomain for s in subdomains_db]

    return ReconSnapshotSchema(
        snapshot_id=snapshot.cycle_id,
        target=snapshot.target,
        status=snapshot.status,
        created_at=snapshot.started_at,
        finished_at=snapshot.finished_at,
        reconnaissance=recon_data,
        subdomains=subdomains,
        summary=summary
    )

@router.get("/snapshots", response_model=List[dict])
async def list_snapshots(db: Session = Depends(get_db)):
    """Lista todos los snapshots de reconocimiento."""
    snapshots = db.query(ReconSnapshot).order_by(ReconSnapshot.started_at.desc()).all()
    return [
        {
            "snapshot_id": s.cycle_id,
            "target": s.target,
            "status": s.status,
            "created_at": s.started_at,
            "findings_count": db.query(ReconFinding).filter(ReconFinding.snapshot_id == s.id).count()
        } for s in snapshots
    ]

@router.get("/health")
async def health():
    """Health check for Recon API."""
    return {"status": "healthy", "service": "recon-engine", "module": "M2"}