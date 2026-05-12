"""
US-6.8 — Cliente MISP reutilizable
"""
import os
import httpx
from shared.scan_logger import ScanLogger

logger = ScanLogger("siem_engine.misp")

MISP_URL = os.getenv("MISP_URL", "http://scanops-misp:80")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")

def misp_headers():
    return {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

def is_configured() -> bool:
    return bool(MISP_API_KEY)

async def misp_get(path: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(f"{MISP_URL}{path}", headers=misp_headers())
        r.raise_for_status()
        return r.json()

async def misp_post(path: str, body: dict) -> dict:
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{MISP_URL}{path}", headers=misp_headers(), json=body)
        r.raise_for_status()
        return r.json()