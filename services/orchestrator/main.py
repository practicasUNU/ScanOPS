import asyncio
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from services.orchestrator.cycle_state import CycleStatus, get_cycle_status
from services.orchestrator.health_checker import check_all_modules
from shared.auth_router import router as auth_router

app = FastAPI(
    title="ScanOPS Orchestrator",
    description="Cycle status and module health — ENS Alto [op.exp.3]",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)

# In-memory state (for MVP — replace with Redis/DB later)
_kill_switch_active: bool = False
_paused: bool = False


@app.get("/health")
async def health():
    return {"status": "ok", "service": "orchestrator"}


@app.get("/orchestrator/cycle/status", response_model=CycleStatus)
async def get_cycle_status_endpoint():
    """
    Returns current weekly cycle state derived from current datetime.
    ENS: op.exp.3
    """
    status, module_health = await _gather_status_and_health()
    _enrich_with_health(status, module_health)
    return status


async def _gather_status_and_health():
    status = get_cycle_status(
        kill_switch_active=_kill_switch_active,
        paused=_paused,
    )
    module_health = await asyncio.wait_for(check_all_modules(), timeout=3.0)
    return status, module_health


def _enrich_with_health(status: CycleStatus, module_health: dict[str, str]) -> None:
    """Override module status with 'offline' if health check reports offline."""
    for phase in status.phases:
        for module in phase.modules:
            health = module_health.get(module.id)
            if health == "offline" and module.status in ("pending", "completed"):
                module.status = "offline"


@app.get("/orchestrator/modules/health")
async def get_modules_health():
    """Returns raw health check results for all modules."""
    results = await check_all_modules()
    return {
        "modules": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/orchestrator/cycle/pause")
async def pause_cycle():
    """Toggles _paused state."""
    global _paused
    _paused = not _paused
    return {"paused": _paused}


@app.post("/orchestrator/cycle/kill-switch")
async def activate_kill_switch(totp_code: str):
    """
    Activates kill switch.
    ENS: op.acc.5
    # TODO: replace with real TOTP validation from shared/auth.py
    """
    global _kill_switch_active
    # MVP: accept any 6-digit code
    if not (totp_code.isdigit() and len(totp_code) == 6):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="totp_code must be a 6-digit number")
    _kill_switch_active = True
    return {
        "kill_switch_active": True,
        "activated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/orchestrator/cycle/kill-switch/deactivate")
async def deactivate_kill_switch():
    """Deactivates kill switch."""
    global _kill_switch_active
    _kill_switch_active = False
    return {"kill_switch_active": False}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8009)
