"""
ScanOPS Recon Engine (M2)
========================
Entry point for the M2 Reconnaissance service.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from services.recon_engine.api.recon_api import router as recon_router
from shared.database import engine
from services.recon_engine.models.recon import ReconBase

# NO recrear tablas — ya existen en PostgreSQL
# ReconBase.metadata.create_all(bind=engine)  ← ELIMINAR ESTA LÍNEA

app = FastAPI(
    title="ScanOPS Recon Engine (M2)",
    description="Motor de Reconocimiento Técnico — ENS Alto [op.acc.1]",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(recon_router)

@app.get("/health")
async def healthcheck():
    return {"status": "ok", "service": "recon-engine", "module": "M2"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)