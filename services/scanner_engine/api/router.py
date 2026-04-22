from fastapi import APIRouter
from sqlalchemy.orm import Session
from shared.database import get_db
from ..tasks.vuln_tasks import run_nuclei_task
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