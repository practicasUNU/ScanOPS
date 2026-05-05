"""FastAPI endpoints for vulnerability scanning."""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends, Response
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from shared.database import get_db
import io
import logging
import httpx
import os

logger = logging.getLogger(__name__)

M1_BASE_URL = os.getenv("M1_URL", "http://scanops-asset-manager:8001")
M1_TOKEN = os.getenv("M1_TOKEN", "scanops_secret")

async def get_asset_from_m1(asset_id: int) -> dict:
    """
    Obtiene los datos del asset desde M1 (Asset Manager).
    Retorna dict con ip, hostname y demás campos.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(
                f"{M1_BASE_URL}/assets/{asset_id}",
                headers={"Authorization": f"Bearer {M1_TOKEN}"}
            )
            if response.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail=f"Asset {asset_id} not found in M1"
                )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"M1 returned {response.status_code} for asset {asset_id}"
                )
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"Error connecting to M1: {e}")
            raise HTTPException(
                status_code=503,
                detail=f"Could not connect to M1 Asset Manager"
            )

from services.scanner_engine.tasks.vuln_tasks import (
    scan_asset_parallel,
    run_nuclei_task, # Corregido de run_nuclei_scan a run_nuclei_task
)
from services.scanner_engine.services.export_results import (
    export_to_json,
    export_to_csv,
    export_to_pdf
)


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class ScanRequest(BaseModel):
    """Request to start a vulnerability scan."""
    scan_types: List[str] = Field(
        default=["openvas", "nuclei", "zap"],
        description="Scanners to run: openvas, nuclei, zap"
    )
    description: Optional[str] = None


class ScanResponse(BaseModel):
    """Response after initiating a scan."""
    task_id: str
    asset_id: int
    status: str
    scan_types: List[str]
    created_at: datetime


class ScanStatusResponse(BaseModel):
    """Current status of a scan task."""
    task_id: str
    asset_id: int
    status: str
    progress: int
    findings_count: int
    started_at: datetime
    completed_at: Optional[datetime] = None


class ScanResultsResponse(BaseModel):
    """Complete scan results for an asset."""
    asset_id: int
    total_findings: int
    findings_by_scanner: dict
    created_at: datetime
    completed_at: Optional[datetime] = None


class HealthResponse(BaseModel):
    """Health status of scanner engine."""
    status: str
    timestamp: datetime


class BatchScanResponse(BaseModel):
    """Response for batch scan initiation."""
    status: str
    count: int
    tasks: List[ScanResponse]
    created_at: datetime


# ============================================================================
# ROUTER SETUP
# ============================================================================

router = APIRouter(
    prefix="/scan",
    tags=["scanner-engine"],
    responses={
        404: {"description": "Not found"},
        500: {"description": "Internal server error"},
    },
)


# ============================================================================
# ENDPOINTS
# ============================================================================

@router.post("/asset/{asset_id}", response_model=ScanResponse)
async def start_asset_scan(
    asset_id: int,
    request: ScanRequest,
) -> ScanResponse:
    """Start a vulnerability scan for a specific asset."""
    try:
        # Obtener IP real del asset desde M1
        asset = await get_asset_from_m1(asset_id)
        asset_ip = asset["ip"]
        asset_name = asset.get("hostname") or f"Asset-{asset_id}"

        logger.info(f"→ Scan iniciado para asset {asset_id} ({asset_ip})")

        task = scan_asset_parallel.delay(
            asset_id=asset_id,
            asset_ip=asset_ip,        # ✅ IP real desde M1
            asset_name=asset_name,    # ✅ hostname real desde M1
            scan_types=request.scan_types,
        )

        return ScanResponse(
            task_id=task.id,
            asset_id=asset_id,
            status="PENDING",
            scan_types=request.scan_types,
            created_at=datetime.utcnow(),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"✗ Error iniciando scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


@router.get("/asset/{asset_id}/quick", response_model=ScanResponse)
async def quick_scan_asset(asset_id: int) -> ScanResponse:
    """Quick scan using only Nuclei (faster)."""
    try:
        # Obtener IP real del asset desde M1
        asset = await get_asset_from_m1(asset_id)
        asset_ip = asset["ip"]
        asset_name = asset.get("hostname") or f"Asset-{asset_id}"

        logger.info(f"→ Quick scan (Nuclei) iniciado para asset {asset_id} ({asset_ip})")

        task = run_nuclei_task.delay(
            asset_id,
            asset_ip
        )

        return ScanResponse(
            task_id=task.id,
            asset_id=asset_id,
            status="PENDING",
            scan_types=["nuclei"],
            created_at=datetime.utcnow(),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"✗ Error en quick scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start quick scan: {str(e)}")


@router.get("/status/{task_id}", response_model=ScanStatusResponse)
async def get_scan_status(task_id: str) -> ScanStatusResponse:
    """Get status of a scanning task."""
    try:
        from shared.celery_app import app
        from celery.result import AsyncResult

        result = AsyncResult(task_id, app=app)

        progress_map = {
            "PENDING": 0,
            "STARTED": 25,
            "RETRY": 50,
            "SUCCESS": 100,
            "FAILURE": 100,
        }

        progress = progress_map.get(result.state, 0)

        logger.debug(f"Status check: {task_id} -> {result.state}")

        return ScanStatusResponse(
            task_id=task_id,
            asset_id=0,
            status=result.state,
            progress=progress,
            findings_count=0,
            started_at=datetime.utcnow(),
            completed_at=None if result.state != "SUCCESS" else datetime.utcnow(),
        )

    except Exception as e:
        logger.error(f"✗ Error obteniendo status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")


@router.get("/results/{asset_id}", response_model=ScanResultsResponse)
async def get_scan_results(asset_id: int) -> ScanResultsResponse:
    from shared.database import SessionLocal
    from services.scanner_engine.models.vulnerability import VulnFinding
    db = SessionLocal()
    try:
        vulns = db.query(VulnFinding).filter(VulnFinding.asset_id == asset_id).all()
        findings_by_scanner = {}
        for v in vulns:
            if v.scanner_name not in findings_by_scanner:
                findings_by_scanner[v.scanner_name] = []
            findings_by_scanner[v.scanner_name].append({"title": v.title, "severity": v.severity, "cvss": v.cvss_v3_score, "cve": v.scanner_reference})
        return ScanResultsResponse(asset_id=asset_id, total_findings=len(vulns), findings_by_scanner=findings_by_scanner, created_at=datetime.utcnow(), completed_at=datetime.utcnow())
    finally:
        db.close()


@router.get("/assets/{asset_id}/ficha")
async def get_asset_ficha(asset_id: int):
    from shared.database import SessionLocal
    from services.asset_manager.models.asset import Asset
    from services.scanner_engine.models.vulnerability import VulnFinding
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        vulns = db.query(VulnFinding).filter(VulnFinding.asset_id == asset_id).all()
        return {"asset_id": asset_id, "m1_asset": {"ip": asset.ip, "hostname": asset.hostname, "criticidad": asset.criticidad, "tipo": asset.tipo}, "m3_vulnerabilities": [{"title": v.title, "severity": v.severity, "cve": v.scanner_reference, "scanner": v.scanner_name} for v in vulns], "total_findings": len(vulns)}
    finally:
        db.close()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Check health of scanner engine."""
    try:
        logger.debug("Health check")
        return HealthResponse(
            status="healthy",
            timestamp=datetime.utcnow(),
        )

    except Exception as e:
        logger.error(f"✗ Health check failed: {e}")
        return HealthResponse(
            status="disconnected",
            timestamp=datetime.utcnow(),
        )


@router.post("/batch", response_model=BatchScanResponse)
async def batch_scan_assets(
    asset_ids: List[int] = Query(...),
    scan_types: List[str] = Query(default=["openvas", "nuclei", "zap"]),
) -> BatchScanResponse:
    """Start batch scan for multiple assets."""
    try:
        logger.info(f"→ Batch scan para {len(asset_ids)} assets")

        tasks = []
        for asset_id in asset_ids:
            # Obtener IP real del asset desde M1
            try:
                asset = await get_asset_from_m1(asset_id)
                asset_ip = asset["ip"]
                asset_name = asset.get("hostname") or f"Asset-{asset_id}"

                task = scan_asset_parallel.delay(
                    asset_id=asset_id,
                    asset_ip=asset_ip,
                    asset_name=asset_name,
                    scan_types=scan_types,
                )
            except Exception as e:
                logger.error(f"Skipping asset {asset_id} in batch scan due to error: {e}")
                continue

            tasks.append(
                ScanResponse(
                    task_id=task.id,
                    asset_id=asset_id,
                    status="PENDING",
                    scan_types=scan_types,
                    created_at=datetime.utcnow(),
                )
            )

        logger.info(f"✓ {len(tasks)} scans iniciados")
        return BatchScanResponse(
            status="INITIATED",
            count=len(tasks),
            tasks=tasks,
            created_at=datetime.utcnow(),
        )

    except Exception as e:
        logger.error(f"✗ Batch scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export/{asset_id}/{format}")
async def export_scan_results(
    asset_id: int,
    format: str,
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Exporta los resultados de escaneo de un activo en el formato especificado.
    Formatos soportados: json, csv, pdf.
    """
    format = format.lower()
    
    try:
        if format == "json":
            content = export_to_json(db, asset_id, scan_id)
            return Response(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=results_{asset_id}.json"}
            )
            
        elif format == "csv":
            content_io = export_to_csv(db, asset_id, scan_id)
            return StreamingResponse(
                iter([content_io.getvalue()]),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=results_{asset_id}.csv"}
            )
            
        elif format == "pdf":
            content_io = export_to_pdf(db, asset_id, scan_id)
            return StreamingResponse(
                content_io,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=results_{asset_id}.pdf"}
            )
            
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
            
    except Exception as e:
        logger.error(f"✗ Error exportando resultados ({format}): {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


@router.post("/assets/{asset_id}/attack-vector", response_model=dict)
async def get_attack_vector(asset_id: int):
    """
    US-4.7: Sugiere vector de ataque para un activo.
    Combina datos de M1 + M3 y los pasa a M8 (AI Reasoning).
    """
    try:
        # 1. Obtener ficha del asset desde M1 y M3
        asset = await get_asset_from_m1(asset_id)

        # 2. Obtener vulnerabilidades de M3 desde BD
        from shared.database import SessionLocal
        from services.scanner_engine.models.vulnerability import VulnFinding
        db = SessionLocal()
        try:
            vulns = db.query(VulnFinding).filter(
                VulnFinding.asset_id == asset_id
            ).all()
        finally:
            db.close()

        # 3. Construir ficha_unica para M8
        open_services = f"SSH:22, HTTP:80, HTTPS:443 — hostname: {asset.get('hostname', 'N/A')}"

        confirmed_vulns = []
        for v in vulns:
            confirmed_vulns.append(
                f"- {v.title} (Severidad: {v.severity}, Scanner: {v.scanner_name})"
            )

        ficha_unica = {
            "asset_id": str(asset_id),
            "hostname": asset.get("hostname", "N/A"),
            "target_ip": asset.get("ip", "N/A"),
            "os": "Linux",
            "os_version": "Ubuntu (OpenSSH 9.6p1)",
            "ens_criticality": asset.get("criticidad", "MEDIO"),
            "exposure_level": "INTERNAL",
            "open_services": open_services,
            "confirmed_cves": "\n".join(confirmed_vulns) if confirmed_vulns else "Sin CVEs confirmados",
            "exploitation_history": "Sin historial previo",
            "maintenance_window": "No definida",
            "sandbox_available": "NO",
            "critical_services_no_touch": "SSH (acceso remoto principal)",
            "cve_id": None
        }

        # 4. Llamar a M8 - suggest_attack_vector via Celery task
        from services.ai_reasoning.tasks import suggest_attack_vector_task
        task = suggest_attack_vector_task.delay(ficha_unica)

        return {
            "task_id": task.id,
            "asset_id": asset_id,
            "status": "PENDING",
            "message": "US-4.7: Vector de ataque en proceso. Consulta /ai/attack-vector/status/{task_id}"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en attack-vector para asset {asset_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/assets/{asset_id}/attack-vector/result/{task_id}", response_model=dict)
async def get_attack_vector_result(asset_id: int, task_id: str):
    """
    US-4.7: Obtiene el resultado del vector de ataque sugerido por M8.
    """
    from shared.celery_app import app
    from celery.result import AsyncResult

    result = AsyncResult(task_id, app=app)

    if result.state == "PENDING":
        return {"task_id": task_id, "status": "PENDING", "result": None}
    elif result.state == "SUCCESS":
        return {"task_id": task_id, "status": "SUCCESS", "result": result.get()}
    elif result.state == "FAILURE":
        return {"task_id": task_id, "status": "FAILURE", "error": str(result.info)}
    else:
        return {"task_id": task_id, "status": result.state, "result": None}