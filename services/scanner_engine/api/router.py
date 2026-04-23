import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from shared.database import get_db
from ..tasks.vuln_tasks import run_nuclei_task
from pydantic import BaseModel

from typing import List, Optional
from ..models.vulnerability import VulnerabilityFinding
from pydantic import BaseModel

router = APIRouter(prefix="/scanner", tags=["Scanner Engine (M3)"])

class ScanRequest(BaseModel):
    asset_id: int
    ip: str

@router.post("/nuclei")
async def trigger_nuclei_scan(data: ScanRequest):
    """Lanza escaneo de Nuclei para detección de Zero-days (US-3.2)."""
    task = run_nuclei_task.delay(data.asset_id, data.ip)
    return {
        "status": "Vulnerability scan queued",
        "task_id": task.id,
        "tool": "nuclei"
    }
    
class VulnerabilityResponse(BaseModel):
    id: int
    asset_id: int
    title: str
    severity: str
    tool_source: str
    cve_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

@router.get("/results/{asset_id}", response_model=List[VulnerabilityResponse])
async def get_vuln_results(asset_id: int, db: Session = Depends(get_db)):
    """Consulta los hallazgos normalizados para un activo."""
    results = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.asset_id == asset_id
    ).all()
    return results    