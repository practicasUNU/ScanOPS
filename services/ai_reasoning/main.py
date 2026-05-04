from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from services.ai_reasoning.api.router import router as ai_router

app = FastAPI(
    title="ScanOPS AI Reasoning (M8)",
    description="Motor de Razonamiento IA — US-4.x",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ai_router)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "ai-reasoning", "module": "M8"}
