from fastapi import FastAPI
from services.recon_engine.api.recon_api import app as recon_router
from services.recon_engine.models.recon import Base
from shared.database import engine

app = FastAPI(
    title="ScanOPS Recon Engine (M2)",
    description="Motor de Reconocimiento y Descubrimiento — ENS Alto [op.acc.1]",
    version="1.0.0",
)

app.mount("/api/v1", recon_router)

@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)

@app.get("/health")
async def healthcheck():
    return {"status": "ok", "service": "recon-engine"}