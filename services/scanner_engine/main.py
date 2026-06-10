"""
Scanner Engine — Microservice M3
=================================
FastAPI application for vulnerability scanning orchestration.
Run: uvicorn services.scanner_engine.main:app --host 0.0.0.0 --port 8002
"""
 
import asyncio
import json
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
import logging
from typing import List, Optional
from sqlalchemy.orm import Session
 
from shared.database import engine, get_db
from shared.scan_logger import ScanLogger
from services.scanner_engine.endpoints.scan import router as scan_router
from services.scanner_engine.api.router import router as results_router
from services.scanner_engine.endpoints.hardening import router as hardening_router
from services.scanner_engine.models.vulnerability import Base as VulnerabilityBase
 
# ─── Logging Setup ─────────────────────────────
logger = ScanLogger(__name__)
 
 
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager.
    Startup: Initialize DB tables and log startup.
    Shutdown: Clean up resources.
    """
    # ─── STARTUP ───────────────────────────
    logger.info("🚀 Starting Scanner Engine (M3)...")
    try:
        # Create database tables
        VulnerabilityBase.metadata.create_all(bind=engine)
        logger.info("✓ Vulnerability tables initialized")
        logger.info("✓ Scanner Engine startup complete")
    except Exception as e:
        logger.error(f"✗ Startup failed: {str(e)}", exc_info=True)
        raise
 
    yield
 
    # ─── SHUTDOWN ──────────────────────────
    logger.info("🛑 Shutting down Scanner Engine (M3)...")
    try:
        logger.info("✓ Scanner Engine shutdown complete")
    except Exception as e:
        logger.error(f"✗ Shutdown error: {str(e)}", exc_info=True)
 
 
# ─── In-memory event buffer for SSE stream ──────────────────
_scan_events: deque = deque(maxlen=100)


def _push_event(level: str, message: str, module: str = "M3"):
    _scan_events.append({
        "timestamp": datetime.utcnow().isoformat(),
        "level": level,
        "message": message,
        "module": module,
    })


_push_event("INFO", "Scanner Engine (M3) iniciado — ENS op.exp.2")

# ─── FastAPI Instance ──────────────────────────
app = FastAPI(
    title="ScanOPS Scanner Engine (M3)",
    description="Vulnerability Scanning Orchestration — ENS Alto [op.exp.2] | OpenVAS + Nuclei + ZAP",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)
 
# ─── CORS Middleware ──────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://localhost:5173", "http://localhost:3000", "https://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
 
# ─── Include Routers ──────────────────────────
app.include_router(scan_router, prefix="/api/v1")
app.include_router(results_router, prefix="/api/v1")
app.include_router(hardening_router, prefix="/api/v1")
 
 
# ─── Root Endpoint ────────────────────────────
@app.get("/")
async def root():
    """
    Root endpoint with welcome message.
    """
    return {
        "message": "Welcome to ScanOPS Scanner Engine",
        "service": "M3 - Vulnerability Scanning Orchestration",
        "quick_links": {
            "api_docs": "/docs",
            "health": "/health",
            "info": "/info",
            "start_scan": "/api/v1/scan/asset/{asset_id}",
        },
        "scanners": ["openvas", "nuclei", "nikto"],
        "ens_compliance": "ENS Alto - op.exp.2",
    }
 
 
# ─── Health Check Endpoints ────────────────────
@app.get("/health")
async def healthcheck():
    """
    Health check endpoint.
    Returns service status and timestamp.
    """
    return {
        "status": "ok",
        "service": "scanner-engine",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }
 
 
@app.get("/health/ready")
async def readiness_check(db: Session = Depends(get_db)):
    """
    Readiness check endpoint.
    Verifies database connectivity.
    """
    try:
        db.execute("SELECT 1")
        return {
            "status": "ready",
            "service": "scanner-engine",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Service not ready: {str(e)}"
        )
 
 
@app.get("/health/live")
async def liveness_check():
    """
    Liveness check for Kubernetes.
    """
    return {
        "status": "alive",
        "service": "scanner-engine",
        "timestamp": datetime.utcnow().isoformat(),
    }
 
 
# ─── Info Endpoint ────────────────────────────
@app.get("/info")
async def get_service_info():
    """
    Get detailed service information including scanners and capabilities.
    """
    return {
        "name": "ScanOPS Scanner Engine",
        "module": "M3",
        "description": "Vulnerability scanning orchestration — ENS Alto",
        "version": "1.0.0",
        "scanners": {
            "openvas": {
                "name": "OpenVAS (GVM)",
                "capability": "Network vulnerability scanning",
                "scope": "Infrastructure",
            },
            "nuclei": {
                "name": "Nuclei",
                "capability": "Zero-day detection with templates",
                "scope": "Web & Infrastructure",
            },
            "nikto": {
                "name": "OWASP ZAP",
                "capability": "Web application scanning",
                "scope": "Web Applications",
            },
        },
        "endpoints": {
            "start_scan": "POST /api/v1/scan/asset/{asset_id}",
            "quick_scan": "GET /api/v1/scan/asset/{asset_id}/quick",
            "batch_scan": "POST /api/v1/scan/batch",
            "scan_status": "GET /api/v1/scan/status/{task_id}",
            "scan_results": "GET /api/v1/scan/results/{asset_id}",
            "asset_ficha": "GET /api/v1/scan/assets/{asset_id}/ficha",
        },
        "docs": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json",
        },
        "ens_compliance": "op.exp.2 - Evaluación de configuración de seguridad",
    }
 
 
# ─── Scanners Status Endpoint ──────────────────
@app.get("/scanners/status")
async def get_scanners_status():
    """
    Check availability of all scanning engines.
    """
    from services.scanner_engine.clients import OpenVASClient, NucleiClient, ZAPClient
    
    status = {}
    
    # OpenVAS Check
    try:
        openvas = OpenVASClient()
        status["openvas"] = {
            "available": True if openvas else False,
            "version": "GVM",
            "status": "ready",
        }
    except Exception as e:
        status["openvas"] = {
            "available": False,
            "error": str(e),
            "status": "unavailable",
        }
    
    # Nuclei Check
    try:
        nuclei = NucleiClient()
        status["nuclei"] = {
            "available": True if nuclei else False,
            "version": "3.1.8",
            "status": "ready",
        }
    except Exception as e:
        status["nuclei"] = {
            "available": False,
            "error": str(e),
            "status": "unavailable",
        }
    
    # ZAP Check
    try:
        zap = ZAPClient()
        status["nikto"] = {
            "available": True if zap else False,
            "version": "latest",
            "status": "ready",
        }
    except Exception as e:
        status["nikto"] = {
            "available": False,
            "error": str(e),
            "status": "unavailable",
        }
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "scanners": status,
    }
 
 
# ─── SSE Stream Endpoint ──────────────────────
@app.get("/stream/findings")
async def stream_findings():
    """SSE endpoint — streams scan findings in real time."""
    async def event_generator():
        for event in list(_scan_events):
            yield f"data: {json.dumps(event)}\n\n"
        last_len = len(_scan_events)
        while True:
            await asyncio.sleep(1)
            current_events = list(_scan_events)
            if len(current_events) > last_len:
                for event in current_events[last_len:]:
                    yield f"data: {json.dumps(event)}\n\n"
                last_len = len(current_events)
            else:
                yield f"data: {json.dumps({'type': 'ping', 'timestamp': datetime.utcnow().isoformat()})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


# ─── Error Handlers ────────────────────────────
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """
    Custom HTTP exception handler.
    """
    logger.warning(f"HTTP Exception: {exc.status_code} - {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code": exc.status_code,
            "detail": exc.detail,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )
 
 
@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """
    General exception handler for unhandled errors.
    """
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "status_code": 500,
            "detail": "Internal server error",
            "timestamp": datetime.utcnow().isoformat(),
        },
    )
 
 
# services/scanner_engine/main.py
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8002,  # <--- Cambiar de 8003 a 8002 para consistencia
        log_level="info",
        reload=True,
    )