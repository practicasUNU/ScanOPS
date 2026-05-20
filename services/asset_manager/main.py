"""
Asset Manager — Microservice M1
================================
FastAPI application for asset inventory management.
Run: uvicorn services.asset_manager.main:app --host 0.0.0.0 --port 8001
"""
 
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from datetime import datetime
 
from services.asset_manager.api.router import router as asset_router
from services.asset_manager.models.asset import Base
from shared.database import engine, get_db
from shared.auth import get_current_user
from shared.scan_logger import ScanLogger
from sqlalchemy.orm import Session
 
# Configure logging with ScanLogger
logger = ScanLogger(__name__)
 
 
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup and shutdown events.
    """
    # ─── STARTUP ───────────────────────────
    logger.info("🚀 Starting Asset Manager (M1)...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("✓ Database tables initialized")
    except Exception as e:
        logger.error(f"✗ Database initialization failed: {str(e)}")
        raise
    
    yield
    
    # ─── SHUTDOWN ──────────────────────────
    logger.info("🛑 Shutting down Asset Manager (M1)...")
 
 
# ─── FastAPI Instance ──────────────────────────
app = FastAPI(
    title="ScanOPS · M1 — Gestor de Activos",
    description="""
## ¿Qué hace este módulo?
**M1 es el registro central de activos de la organización.**
Antes de escanear cualquier servidor o dispositivo, debe estar registrado aquí.
El resto de módulos (M2, M3, M8) consultan M1 para obtener la IP y los metadatos del activo.

---
## Flujo de uso típico
1. **Registrar el activo** → `POST /api/v1/assets`
2. **Consultar el activo** → `GET /api/v1/assets/{id}`
3. **Ver ficha completa** → `GET /api/v1/assets/{id}/ficha` *(usada por M4 para explotar)*

---
## Cumplimiento ENS Alto
- `op.exp.1` — Inventario de activos
- `op.exp.5` — Registro de auditoría de cambios
- `mp.info.3` — Credenciales cifradas en HashiCorp Vault (nunca en base de datos)

---
## Autenticación
Todos los endpoints requieren cabecera:
`Authorization: Bearer scanops_secret`
""",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "Activos",
            "description": "Alta, consulta, modificación y baja de activos. Un activo es cualquier servidor, endpoint o dispositivo de red que se quiera analizar."
        },
        {
            "name": "Credenciales",
            "description": "Almacenamiento seguro de credenciales SSH/WinRM en HashiCorp Vault. Las contraseñas nunca se guardan en la base de datos."
        },
        {
            "name": "Auditoría",
            "description": "Registro inmutable de todas las acciones realizadas sobre activos. Requerido por ENS Alto op.exp.5."
        },
        {
            "name": "Discovery",
            "description": "Descubrimiento automático de dispositivos en red (Nmap). Detecta Shadow IT — dispositivos no registrados."
        },
        {
            "name": "Sistema",
            "description": "Health check y estado del servicio."
        }
    ]
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
app.include_router(asset_router, prefix="/api/v1")
 
 
# ─── Health Check ─────────────────────────────
@app.get("/health")
async def healthcheck():
    """
    Health check endpoint.
    Returns service status and version.
    """
    return {
        "status": "ok",
        "service": "asset-manager",
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
        # Simple query to test DB connection
        db.execute("SELECT 1")
        return {
            "status": "ready",
            "service": "asset-manager",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Service not ready: {str(e)}"
        )
 
 
@app.get("/info")
async def get_service_info():
    """
    Get detailed service information.
    """
    return {
        "name": "ScanOPS Asset Manager",
        "module": "M1",
        "description": "Inventory management module — ENS Alto",
        "version": "1.0.0",
        "endpoints": {
            "crud": "/api/v1/assets",
            "discovery": "/api/v1/assets/discovery",
            "sync": "/api/v1/assets/sync/external",
            "audit": "/api/v1/assets/{asset_id}/audit",
            "credentials": "/api/v1/assets/{asset_id}/credentials",
            "ficha": "/api/v1/assets/{asset_id}/ficha",
        },
        "docs": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json",
        },
    }
 
 
# ─── Root Endpoint ────────────────────────────
@app.get("/")
async def root():
    """
    Root endpoint with welcome message and quick links.
    """
    return {
        "message": "Welcome to ScanOPS Asset Manager",
        "service": "M1 - Asset Inventory Management",
        "quick_links": {
            "api_docs": "/docs",
            "health": "/health",
            "info": "/info",
            "assets_crud": "/api/v1/assets",
        },
        "ens_compliance": "ENS Alto - op.exp.1",
    }
 
 
# ─── Error Handlers ────────────────────────────
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """
    Custom HTTP exception handler.
    """
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
 
 
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        log_level="info",
        reload=True,
    )