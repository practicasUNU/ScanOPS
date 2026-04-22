"""
Asset Manager — Microservice M1
================================
FastAPI application for asset inventory management.
Run: uvicorn services.asset_manager.main:app --port 8001
"""

from fastapi import FastAPI

from services.asset_manager.api.router import router as asset_router
from services.asset_manager.models.asset import Base
from shared.database import engine

app = FastAPI(
    title="ScanOPS Asset Manager (M1)",
    description="Inventario de activos — ENS Alto [op.exp.1]",
    version="1.0.0",
)

app.include_router(asset_router)


@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)


@app.get("/health")
async def healthcheck():
    return {"status": "ok", "service": "asset-manager"}
