import asyncio
import json
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

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

# In-memory log buffer — stores last 100 entries
# TODO: replace with Redis pub/sub for multi-instance support
_log_buffer: list[dict] = []
_log_subscribers: list[asyncio.Queue] = []


def _add_log_entry(level: str, message: str, module: str = "orchestrator") -> None:
    """Add a log entry to the buffer and notify all SSE subscribers."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,  # INFO | SUCCESS | WARN | ERROR
        "module": module,
        "message": message,
    }
    _log_buffer.append(entry)
    if len(_log_buffer) > 100:
        _log_buffer.pop(0)
    for q in _log_subscribers:
        try:
            q.put_nowait(entry)
        except asyncio.QueueFull:
            pass


@app.on_event("startup")
async def on_startup():
    _add_log_entry("SUCCESS", "Orchestrator started — ScanOps cycle manager ready", "orchestrator")
    _add_log_entry("INFO", "Weekly cycle schedule loaded — 5 phases, timezone: Europe/Madrid", "orchestrator")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "orchestrator"}


@app.get("/orchestrator/logs/stream")
async def stream_logs():
    """
    SSE endpoint — streams live log entries to the dashboard.
    Sends last 20 buffered entries on connect, then new entries as they arrive.
    ENS: op.exp.5 (activity logging)
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=50)
    _log_subscribers.append(queue)

    async def event_generator():
        try:
            for entry in _log_buffer[-20:]:
                yield f"data: {json.dumps(entry)}\n\n"
            while True:
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(entry)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            _log_subscribers.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/orchestrator/logs/add")
async def add_log_entry(level: str, message: str, module: str = "orchestrator"):
    """Add a log entry programmatically (used by other services or tests)."""
    _add_log_entry(level, message, module)
    return {"ok": True}


@app.get("/orchestrator/cycle/status", response_model=CycleStatus)
async def get_cycle_status_endpoint():
    """
    Returns current weekly cycle state derived from current datetime.
    ENS: op.exp.3
    """
    status, module_health = await _gather_status_and_health()
    _enrich_with_health(status, module_health)
    _add_log_entry("INFO", f"Cycle status queried — phase {status.current_phase}: {status.current_phase_name}", "orchestrator")
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
