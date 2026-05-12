"""
M5 — SIEM Engine  |  Motor de Vigilancia Continua 24/7
ENS Alto RD 311/2022  |  op.exp.3 · op.exp.5 · op.exp.7
"""
import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime

import httpx
from fastapi import FastAPI, HTTPException
from shared.scan_logger import ScanLogger

from .db import create_siem_tables
from .wazuh_client import WAZUH_API, new_client, get_token
from .agents import router as agents_router
from .blocking import router as blocking_router, wazuh_alert_loop
from .emergency import router as emergency_router
from .alerting import router as alerting_router
from .suricata import router as suricata_router
from .honeypots import router as honeypots_router
from .correlation import router as correlation_router
from .misp_integration import router as misp_router
from .lucia_integration import router as lucia_router 

logger = ScanLogger("siem_engine")

WAZUH_AUTH = (os.getenv("WAZUH_USER", "wazuh"), os.getenv("WAZUH_PASSWORD", "wazuh"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        create_siem_tables()
        logger.info("[M5] Tablas SIEM creadas/verificadas")
    except Exception as e:
        logger.error(f"[M5] Error creando tablas: {e}")

    task = asyncio.create_task(wazuh_alert_loop())
    logger.info("[M5] Loop de alertas Wazuh iniciado")
    yield
    task.cancel()


app = FastAPI(
    title="ScanOPS SIEM Engine (M5)",
    description="Motor de Vigilancia Continua 24/7 — ENS Alto [op.exp.3 · op.exp.5 · op.exp.7]",
    version="2.0.0",
    lifespan=lifespan,
)

app.include_router(agents_router)
app.include_router(blocking_router)
app.include_router(emergency_router)
app.include_router(alerting_router)
app.include_router(suricata_router)
app.include_router(honeypots_router)
app.include_router(correlation_router)
app.include_router(misp_router)
app.include_router(lucia_router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "siem-engine",
        "module": "M5",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/siem/status")
async def get_siem_status():
    """Conexión real con Wazuh API (HTTPS) — ENS op.exp.5"""
    auth_url = f"{WAZUH_API}/security/user/authenticate"
    try:
        async with new_client() as client:
            logger.info(f"[ENS op.exp.5] Auth attempt → {auth_url} | user={WAZUH_AUTH[0]}")
            auth_resp = await client.get(auth_url, auth=WAZUH_AUTH)

            if auth_resp.status_code == 401:
                logger.warning(f"[ENS op.exp.5] 401 Unauthorized en {auth_url}")
                return {
                    "wazuh_status": "auth_error",
                    "http_code": 401,
                    "url_consultada": auth_url,
                    "detail": "Credenciales rechazadas.",
                    "action_required": "Ejecutar reset de volumen o script de contraseñas en el manager",
                }

            if auth_resp.status_code != 200:
                logger.error(f"[ENS op.exp.5] HTTP {auth_resp.status_code} en {auth_url}")
                return {
                    "wazuh_status": "auth_error",
                    "http_code": auth_resp.status_code,
                    "url_consultada": auth_url,
                    "detail": auth_resp.text,
                    "action_required": "Ejecutar reset de volumen o script de contraseñas en el manager",
                }

            token = auth_resp.json().get("data", {}).get("token")
            headers = {"Authorization": f"Bearer {token}"}

            info_resp = await client.get(f"{WAZUH_API}/manager/info", headers=headers)
            manager_info = info_resp.json().get("data", {}).get("affected_items", [{}])[0]

            agents_resp = await client.get(f"{WAZUH_API}/agents?limit=1", headers=headers)
            total_agents = agents_resp.json().get("data", {}).get("total_affected_items", 0)

            version = manager_info.get("version", "unknown")
            logger.info(f"[ENS op.exp.5] Conexión exitosa — version={version} agents={total_agents}")
            return {
                "wazuh_status": "connected",
                "connected": True,
                "manager_name": manager_info.get("path", "wazuh-manager"),
                "manager_version": version,
                "wazuh_version": version,
                "total_agents": total_agents,
                "ens_compliance": {
                    "op_exp_5": True,
                    "description": "Vigilancia operativa 24/7 — ENS Alto RD 311/2022",
                },
                "timestamp": datetime.utcnow().isoformat(),
            }
    except Exception as e:
        logger.error(f"[ENS op.exp.5] Excepción al contactar {auth_url}: {e}")
        raise HTTPException(
            status_code=500, detail=f"SIEM Offline (Probablemente arrancando): {e}"
        )
