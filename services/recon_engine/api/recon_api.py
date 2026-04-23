"""
Recon API Endpoints
==================
FastAPI endpoints for surface snapshot management and change queries.
"""
 
import os
import sys
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.orm import Session
 
from shared.database import get_db, create_tables
from ..models.recon import (
    ReconSnapshot, ReconFinding, ReconSubdomain,
    ReconSnapshotSchema, ReconFindingSchema, ReconSubdomainSchema,
    SurfaceChanges, SurfaceChangeDetail
)
from ..services.surface_diff import compare_snapshots, get_previous_snapshot_id
 
# ─── ROUTER (usado por main.py y tests) ─────────────────
router = APIRouter(
    prefix="/recon",
    tags=["Recon Engine (M2)"],
    responses={404: {"description": "Not found"}}
)
 
 
@router.get("/cycles/{cycle_id}/changes", response_model=SurfaceChanges)
async def get_surface_changes(
    cycle_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICA, ALTA, MEDIA, INFO"),
    db: Session = Depends(get_db)
):
    """
    Get surface changes for a specific cycle compared to the previous one.
    """
    # Find the snapshot for this cycle
    snapshot = db.query(ReconSnapshot).filter(
        ReconSnapshot.cycle_id == cycle_id,
        ReconSnapshot.status == "completed"
    ).first()
 
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"Snapshot not found for cycle {cycle_id}")
 
    # Get previous snapshot
    previous_snapshot_id = get_previous_snapshot_id(cycle_id, db)
 
    # Compare snapshots
    changes = compare_snapshots(snapshot.id, previous_snapshot_id, db)
 
    # Filter by severity if requested
    if severity:
        changes["details"] = [
            detail for detail in changes["details"]
            if detail["severity"] == severity
        ]
        # Recalculate summary
        changes["summary"]["total_changes"] = len(changes["details"])
        changes["has_changes"] = changes["summary"]["total_changes"] > 0
 
    return changes
 
 
@router.get("/cycles/{cycle_id}/snapshot", response_model=ReconSnapshotSchema)
async def get_snapshot(cycle_id: str, db: Session = Depends(get_db)):
    """
    Get snapshot details for a specific cycle.
    """
    snapshot = db.query(ReconSnapshot).filter(
        ReconSnapshot.cycle_id == cycle_id
    ).first()
 
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"Snapshot not found for cycle {cycle_id}")
 
    return snapshot
 
 
@router.get("/cycles", response_model=List[ReconSnapshotSchema])
async def list_cycles(
    status: Optional[str] = Query(None, description="Filter by status: running, completed, failed"),
    limit: int = Query(50, description="Maximum number of results"),
    db: Session = Depends(get_db)
):
    """
    List all recon cycles.
    """
    query = db.query(ReconSnapshot).order_by(ReconSnapshot.started_at.desc())
 
    if status:
        query = query.filter(ReconSnapshot.status == status)
 
    snapshots = query.limit(limit).all()
    return snapshots
 
 
@router.get("/snapshots/{snapshot_id}/findings", response_model=List[ReconFindingSchema])
async def get_snapshot_findings(
    snapshot_id: int,
    host: Optional[str] = Query(None, description="Filter by host"),
    port: Optional[str] = Query(None, description="Filter by port"),
    state: Optional[str] = Query(None, description="Filter by state: open, filtered, closed"),
    db: Session = Depends(get_db)
):
    """
    Get findings for a specific snapshot.
    """
    query = db.query(ReconFinding).filter(ReconFinding.snapshot_id == snapshot_id)
 
    if host:
        query = query.filter(ReconFinding.host == host)
    if port:
        query = query.filter(ReconFinding.port == port)
    if state:
        query = query.filter(ReconFinding.state == state)
 
    findings = query.all()
    return findings
 
 
@router.get("/snapshots/{snapshot_id}/subdomains", response_model=List[ReconSubdomainSchema])
async def get_snapshot_subdomains(snapshot_id: int, db: Session = Depends(get_db)):
    """
    Get subdomains for a specific snapshot.
    """
    subdomains = db.query(ReconSubdomain).filter(ReconSubdomain.snapshot_id == snapshot_id).all()
    return subdomains
 
 
@router.get("/changes/recent", response_model=SurfaceChanges)
async def get_recent_changes(
    limit: int = Query(10, description="Number of recent cycles to check"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    db: Session = Depends(get_db)
):
    """
    Get surface changes from the most recent completed cycle.
    """
    # Get the most recent completed snapshot
    recent_snapshot = db.query(ReconSnapshot).filter(
        ReconSnapshot.status == "completed"
    ).order_by(ReconSnapshot.started_at.desc()).first()
 
    if not recent_snapshot:
        raise HTTPException(status_code=404, detail="No completed snapshots found")
 
    # Get previous snapshot
    previous_snapshot_id = get_previous_snapshot_id(recent_snapshot.cycle_id, db)
 
    # Compare snapshots
    changes = compare_snapshots(recent_snapshot.id, previous_snapshot_id, db)
 
    # Filter by severity if requested
    if severity:
        changes["details"] = [
            detail for detail in changes["details"]
            if detail["severity"] == severity
        ]
        # Recalculate summary
        changes["summary"]["total_changes"] = len(changes["details"])
        changes["has_changes"] = changes["summary"]["total_changes"] > 0
 
    return changes
 
 
from ..tasks.scan_tasks import run_recon_complete
 
 
@router.post("/scan")
async def start_scan(target: str = "192.168.1.0/24"):
    """
    Lanza el escaneo asíncrono a través de Celery.
    """
    # .delay() envía la tarea al Redis y el Worker la pesca
    task = run_recon_complete.delay(target)
    return {
        "status": "Scan queued",
        "task_id": task.id,
        "target": target
    }
 
 
@router.get("/health")
async def health():
    """Health check for Recon API."""
    return {"status": "healthy", "service": "recon-engine"}
 
 
# ─── BACKWARDS COMPATIBILITY: app alias ─────────────────
# Para compatibilidad con código que importa 'app'
# Creamos una FastAPI app que incluye el router
from fastapi import FastAPI
app = FastAPI(title="ScanOPS Recon API", version="1.0.0")
app.include_router(router)
 
# Startup event para crear tablas
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    create_tables()