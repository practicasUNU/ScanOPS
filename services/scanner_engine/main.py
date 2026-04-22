from fastapi import FastAPI
# Asegúrate de que la ruta de importación sea exactamente esta
from services.scanner_engine.api.router import router as scanner_router

app = FastAPI(
    title="ScanOPS Scanner Engine (M3)",
    description="Motor de Inteligencia de Vulnerabilidades — ENS Alto [op.exp.2]",
    version="1.0.0",
)

# ESTA LÍNEA ES LA QUE FALTA O ESTÁ MAL
app.include_router(scanner_router)

@app.get("/health")
async def healthcheck():
    return {"status": "ok", "service": "scanner-engine"}