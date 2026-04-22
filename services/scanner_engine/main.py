"""FastAPI application factory for Scanner Engine (M3)."""

from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.scan_logger import get_logger
from services.scanner_engine.endpoints.scan import router as scan_router

logger = get_logger(__name__)


# ============================================================================
# LIFESPAN CONTEXT MANAGER
# ============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager for startup/shutdown.
    
    Startup:
    - Initialize scanner clients
    - Test connectivity
    
    Shutdown:
    - Clean up resources
    """
    # STARTUP
    logger.info("Scanner Engine starting up...")
    try:
        # Could initialize clients here if needed
        logger.info("✓ Scanner Engine startup complete")
    except Exception as e:
        logger.error(f"Startup failed: {e}", exc_info=True)
        raise

    yield

    # SHUTDOWN
    logger.info("Scanner Engine shutting down...")
    try:
        # Cleanup code here
        logger.info("✓ Scanner Engine shutdown complete")
    except Exception as e:
        logger.error(f"Shutdown error: {e}", exc_info=True)


# ============================================================================
# APP FACTORY
# ============================================================================


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    
    app = FastAPI(
        title="ScanOPS Scanner Engine (M3)",
        description="Vulnerability Scanning Engine - ENS Alto [op.exp.2]",
        version="1.0.0",
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ========================================================================
    # MIDDLEWARE
    # ========================================================================

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ========================================================================
    # ROUTERS
    # ========================================================================

    app.include_router(scan_router)

    # ========================================================================
    # ROOT ENDPOINTS
    # ========================================================================

    @app.get("/", summary="Root endpoint")
    async def root():
        """Root endpoint."""
        return {
            "service": "ScanOPS Scanner Engine (M3)",
            "version": "1.0.0",
            "status": "running",
        }

    @app.get("/health", summary="Health check")
    async def health():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "scanner-engine",
        }

    @app.get("/readiness", summary="Readiness probe")
    async def readiness():
        """Kubernetes readiness probe."""
        return {
            "ready": True,
            "timestamp": datetime.utcnow().isoformat(),
        }

    @app.get("/liveness", summary="Liveness probe")
    async def liveness():
        """Kubernetes liveness probe."""
        return {
            "alive": True,
            "timestamp": datetime.utcnow().isoformat(),
        }

    logger.info("FastAPI app created successfully")
    return app


# Create singleton app instance
app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "services.scanner_engine.main:app",
        host="0.0.0.0",
        port=8003,
        reload=True,
        log_level="info",
    )