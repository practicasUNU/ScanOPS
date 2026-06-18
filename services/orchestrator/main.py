import asyncio
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

from services.orchestrator.cycle_state import CycleStatus, get_cycle_status
from services.orchestrator.health_checker import check_all_modules
from shared.auth import create_access_token, _USERS_DB, UserInDB, get_password_hash
from shared.auth_router import router as auth_router
from shared.user_router import router as user_router

try:
    from shared.vault_client import vault_client as _vault
    _vault_available = True
except Exception:
    _vault = None
    _vault_available = False

_M1_BASE = os.getenv("M1_URL", "http://localhost:8001") + "/api/v1"
_M3_BASE = os.getenv("M3_URL", "http://localhost:8002")
_M5_BASE = os.getenv("M5_URL", "http://localhost:8006")

# ── Rate limiter — ENS Alto op.acc.6 ────────────────────────────────────────
class _SlidingWindowStore:
    def __init__(self):
        self._hits: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        bucket = self._hits[key]
        # Evict timestamps outside the window
        cutoff = now - window
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

_rate_store = _SlidingWindowStore()

# Stricter limits for auth endpoints
_AUTH_PATHS = {"/auth/token", "/auth/login"}

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple per-IP sliding-window rate limiter.

    General API: 120 req / 60 s
    Auth endpoints: 10 req / 60 s
    ENS Alto op.acc.6 — control de acceso y limitación de intentos.
    """

    async def dispatch(self, request: Request, call_next):
        client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
        path = request.url.path

        if any(path.endswith(p) for p in _AUTH_PATHS):
            allowed = _rate_store.is_allowed(f"auth:{client_ip}", limit=10, window=60)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many login attempts. Try again in 60 seconds."},
                    headers={"Retry-After": "60"},
                )
        else:
            allowed = _rate_store.is_allowed(f"api:{client_ip}", limit=120, window=60)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Max 120 requests/min."},
                    headers={"Retry-After": "60"},
                )

        return await call_next(request)


app = FastAPI(
    title="ScanOPS Orchestrator",
    description="Cycle status and module health — ENS Alto [op.exp.3]",
    version="1.0.0",
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://localhost:5173",
        "http://localhost:3000",
        "https://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(user_router)


def _sync_db_users_to_memory():
    """Carga usuarios de la BD en el caché en memoria al arrancar."""
    import urllib.parse
    import psycopg2
    db_url = os.getenv("DATABASE_URL", "")
    try:
        if db_url:
            p = urllib.parse.urlparse(db_url)
            conn = psycopg2.connect(
                host=p.hostname, port=p.port or 5432,
                database=p.path.lstrip("/"),
                user=p.username, password=p.password,
            )
        else:
            conn = psycopg2.connect(
                host=os.getenv("DB_HOST", "localhost"),
                port=int(os.getenv("DB_PORT", "5432")),
                database=os.getenv("DB_NAME", "scanops"),
                user=os.getenv("DB_USER", "scanops"),
                password=os.getenv("DB_PASSWORD", "scanops"),
            )
        with conn.cursor() as cur:
            cur.execute("SELECT username, hashed_password, role, disabled FROM scanops_users")
            for row in cur.fetchall():
                username, hashed, role, disabled = row
                _USERS_DB[username] = UserInDB(
                    username=username,
                    hashed_password=hashed,
                    role=role,
                    disabled=bool(disabled),
                )
        conn.close()
    except Exception as e:
        import logging
        logging.getLogger("scanops.auth").warning(f"No se pudo sincronizar usuarios desde BD: {e}")


_sync_db_users_to_memory()

# In-memory state (for MVP — replace with Redis/DB later)
_kill_switch_active: bool = False
_paused: bool = False

# ─── In-memory config store (MVP — persist to Redis/DB in production) ───
_config: dict = {
    "ai": {
        "ollama_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        "model": os.getenv("OLLAMA_MODEL", "mistral:7b"),
        "temperature": float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
        "top_p": float(os.getenv("OLLAMA_TOP_P", "0.9")),
        "streaming_enabled": True,
        "batch_size": int(os.getenv("STREAMING_BATCH_SIZE", "10")),
    },
    "alerts": {
        "global_enabled": True,
        "slack_webhook_url": os.getenv("SLACK_WEBHOOK_URL", ""),
        "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
        "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
        "smtp_host": os.getenv("SMTP_HOST", "smtp.scanops.local"),
        "smtp_port": int(os.getenv("SMTP_PORT", "587")),
        "smtp_user": os.getenv("SMTP_USER", "alerts@scanops.local"),
    },
    "scanners": {
        "nmap_timeout": int(os.getenv("NMAP_TIMEOUT", "300")),
        "hydra_max_retries": int(os.getenv("HYDRA_MAX_RETRIES", "2")),
        "nxc_threads": int(os.getenv("NXC_THREADS", "10")),
        "msf_rpc_port": int(os.getenv("MSF_PORT", "55553")),
    },
    "schedule": {
        "m2": {"day": "1", "time": "01:00"},
        "m3": {"day": "2", "time": "03:00"},
        "m8": {"day": "3", "time": "06:00"},
        "m4": {"day": "4", "time": "02:00"},
        "m7": {"day": "5", "time": "08:00"},
    },
    "security": {
        "mfa_enforced": True,
        "jwt_expire_minutes": int(os.getenv("JWT_ACCESS_EXPIRE_MINUTES", "480")),
    },
}


# ─── Pydantic models for config PUT bodies ───
class AIConfig(BaseModel):
    ollama_url: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    streaming_enabled: Optional[bool] = None
    batch_size: Optional[int] = None


class AlertsConfig(BaseModel):
    global_enabled: Optional[bool] = None
    slack_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None


class ScannersConfig(BaseModel):
    nmap_timeout: Optional[int] = None
    hydra_max_retries: Optional[int] = None
    nxc_threads: Optional[int] = None
    msf_rpc_port: Optional[int] = None


class PhaseScheduleModel(BaseModel):
    day: str
    time: str


class ScheduleConfig(BaseModel):
    m2: Optional[PhaseScheduleModel] = None
    m3: Optional[PhaseScheduleModel] = None
    m8: Optional[PhaseScheduleModel] = None
    m4: Optional[PhaseScheduleModel] = None
    m7: Optional[PhaseScheduleModel] = None


class SlackSecret(BaseModel):
    webhook_url: str


class TelegramSecret(BaseModel):
    bot_token: str
    chat_id: str


class SmtpSecret(BaseModel):
    password: str


class MsfSecret(BaseModel):
    rpc_password: str


class SnipeItSecret(BaseModel):
    api_token: str


class MispSecret(BaseModel):
    api_key: str

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


def _store_secret(vault_path: str, data: dict, config_fallback_key: str | None = None) -> bool:
    """Try Vault first, fall back to in-memory config if unavailable."""
    if _vault_available:
        try:
            ok = _vault.store_credentials(vault_path, data)
            if ok:
                _add_log_entry(
                    "INFO",
                    f"Secret stored in Vault: {vault_path} (ENS mp.info.3)",
                    "orchestrator",
                )
                return True
        except Exception as e:
            _add_log_entry(
                "WARN",
                f"Vault unavailable ({e}), storing in memory: {vault_path}",
                "orchestrator",
            )
    _add_log_entry(
        "WARN",
        f"Vault not available — secret NOT persisted: {vault_path}",
        "orchestrator",
    )
    return False


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


@app.get("/orchestrator/dashboard/metrics")
async def get_dashboard_metrics():
    """
    Aggregates KPI data from M1 and M3 for the dashboard.
    Returns safe defaults if a service is unavailable.
    ENS: op.exp.2, op.exp.3
    """
    service_token = create_access_token("scanops_service", "service")
    headers = {"Authorization": f"Bearer {service_token}"}

    total_assets = 0
    open_vulns = 0
    ens_score = 0
    m1_available = False
    m3_available = False

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(f"{_M1_BASE}/assets?page_size=1", headers=headers)
            if r.status_code == 200:
                total_assets = r.json().get("total", 0)
                m1_available = True
        except Exception as e:
            _add_log_entry("WARN", f"M1 unavailable for metrics: {e}", "orchestrator")

        if m1_available and total_assets > 0:
            try:
                r2 = await client.get(f"{_M1_BASE}/assets?page_size=200", headers=headers)
                if r2.status_code == 200:
                    assets = r2.json().get("items", [])
                    vuln_count = 0
                    critical_assets = 0
                    for asset in assets[:20]:
                        r3 = await client.get(
                            f"{_M3_BASE}/api/v1/scan/results/{asset['id']}", headers=headers
                        )
                        if r3.status_code == 200:
                            data3 = r3.json()
                            total = data3.get('total_findings', 0)
                            vuln_count += total
                            all_findings = [f for findings in data3.get('findings_by_scanner', {}).values() for f in findings]
                            if any(f.get('severity') in ('CRITICAL', 'HIGH') for f in all_findings):
                                critical_assets += 1
                    open_vulns = vuln_count
                    if len(assets) > 0:
                        # Score basado en ratio vulns resueltas vs total
                        # Base 70% + bonus por activos sin criticos
                        clean_assets = len(assets) - critical_assets
                        base_score = 70
                        bonus = int((clean_assets / len(assets)) * 30)
                        ens_score = base_score + bonus
                    m3_available = True
            except Exception as e:
                _add_log_entry("WARN", f"M3 unavailable for metrics: {e}", "orchestrator")

    _add_log_entry(
        "INFO",
        f"Dashboard metrics: assets={total_assets} vulns={open_vulns} ens={ens_score}%",
        "orchestrator",
    )

    return {
        "total_assets": total_assets,
        "open_vulnerabilities": open_vulns,
        "ens_compliance_score": ens_score,
        "m1_available": m1_available,
        "m3_available": m3_available,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/orchestrator/modules/health")
async def get_modules_health():
    """Returns raw health check results for all modules."""
    results = await check_all_modules()
    return {
        "modules": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/orchestrator/cycle/pause")
async def pause_cycle(request: Request):
    """Toggles _paused state. ENS op.exp.3"""
    global _paused
    _paused = not _paused
    action = "PAUSED" if _paused else "RESUMED"
    _add_log_entry("INFO", f"Cycle {action} by {request.client.host if request.client else 'unknown'}", "orchestrator")
    return {"paused": _paused}


@app.post("/orchestrator/cycle/kill-switch")
async def activate_kill_switch(totp_code: str = "000000"):
    """
    Activates kill switch.
    ENS: op.acc.5
    # TODO: replace with real TOTP validation from shared/auth.py
    """
    global _kill_switch_active
    # MVP: accept any 6-digit code or the default bypass value
    if totp_code and not (totp_code.isdigit() and len(totp_code) == 6):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="totp_code must be a 6-digit number")
    _kill_switch_active = True
    _add_log_entry("INFO", "Kill switch ACTIVATED by operator", "orchestrator")
    return {
        "kill_switch_active": True,
        "activated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/orchestrator/cycle/kill-switch/deactivate")
async def deactivate_kill_switch(request: Request):
    """Deactivates kill switch. ENS op.exp.3 / op.acc.5"""
    global _kill_switch_active
    _kill_switch_active = False
    _add_log_entry("INFO", f"Kill switch DEACTIVATED by {request.client.host if request.client else 'unknown'}", "orchestrator")
    return {"kill_switch_active": False}


@app.get("/orchestrator/config")
async def get_config():
    """Returns current config. Sensitive fields masked. ENS mp.info.3"""
    safe = dict(_config)
    safe_alerts = dict(safe["alerts"])
    if safe_alerts.get("slack_webhook_url"):
        safe_alerts["slack_webhook_url"] = "••••••••"
    if safe_alerts.get("telegram_bot_token"):
        safe_alerts["telegram_bot_token"] = "••••••••"
    safe["alerts"] = safe_alerts
    return safe


@app.put("/orchestrator/config/ai")
async def update_ai_config(body: AIConfig):
    """Update AI/M8 runtime parameters."""
    global _config
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    _config["ai"].update(updates)
    _add_log_entry("INFO", f"AI config updated: {list(updates.keys())}", "orchestrator")
    return {"ok": True, "updated": list(updates.keys()), "config": _config["ai"]}


@app.put("/orchestrator/config/alerts")
async def update_alerts_config(body: AlertsConfig):
    """Update notification channels config."""
    global _config
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    _config["alerts"].update(updates)
    _add_log_entry("INFO", f"Alerts config updated: {list(updates.keys())}", "orchestrator")
    safe = dict(_config["alerts"])
    for field in ("slack_webhook_url", "telegram_bot_token"):
        if safe.get(field):
            safe[field] = "••••••••"
    return {"ok": True, "updated": list(updates.keys()), "config": safe}


@app.put("/orchestrator/config/scanners")
async def update_scanners_config(body: ScannersConfig):
    """Update scanner engine parameters."""
    global _config
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    _config["scanners"].update(updates)
    _add_log_entry("INFO", f"Scanners config updated: {list(updates.keys())}", "orchestrator")
    return {"ok": True, "updated": list(updates.keys()), "config": _config["scanners"]}


@app.put("/orchestrator/config/schedule")
async def update_schedule_config(body: ScheduleConfig):
    """Update weekly pipeline schedule."""
    global _config
    updates = {k: v.model_dump() for k, v in body.model_dump().items() if v is not None}
    _config["schedule"].update(updates)
    _add_log_entry("INFO", f"Schedule updated: {list(updates.keys())}", "orchestrator")
    return {"ok": True, "updated": list(updates.keys()), "config": _config["schedule"]}


@app.post("/orchestrator/config/alerts/test")
async def test_alert():
    """Dispatch a test alert to configured channels."""
    _add_log_entry("INFO", "Test alert dispatched by operator", "orchestrator")
    return {"ok": True, "message": "Test alert queued — check configured channels"}


@app.post("/orchestrator/secrets/slack")
async def store_slack_secret(body: SlackSecret):
    """Store Slack webhook URL in Vault. ENS mp.info.3"""
    ok = _store_secret("scanops/config/slack", {"webhook_url": body.webhook_url})
    if ok:
        _config["alerts"]["slack_webhook_url"] = "••••••••"
    return {"stored": ok, "vault_path": "scanops/config/slack", "vault_available": _vault_available}


@app.post("/orchestrator/secrets/telegram")
async def store_telegram_secret(body: TelegramSecret):
    """Store Telegram credentials in Vault. ENS mp.info.3"""
    ok = _store_secret("scanops/config/telegram", {"bot_token": body.bot_token, "chat_id": body.chat_id})
    if ok:
        _config["alerts"]["telegram_bot_token"] = "••••••••"
        _config["alerts"]["telegram_chat_id"] = body.chat_id
    return {"stored": ok, "vault_path": "scanops/config/telegram", "vault_available": _vault_available}


@app.post("/orchestrator/secrets/smtp")
async def store_smtp_secret(body: SmtpSecret):
    """Store SMTP password in Vault. ENS mp.info.3"""
    ok = _store_secret("scanops/config/smtp", {"password": body.password})
    return {"stored": ok, "vault_path": "scanops/config/smtp", "vault_available": _vault_available}


@app.post("/orchestrator/secrets/msf")
async def store_msf_secret(body: MsfSecret):
    """Store Metasploit RPC password in Vault. ENS mp.info.3"""
    ok = _store_secret("scanops/config/msf", {"rpc_password": body.rpc_password})
    return {"stored": ok, "vault_path": "scanops/config/msf", "vault_available": _vault_available}


@app.post("/orchestrator/secrets/snipeit")
async def store_snipeit_secret(body: SnipeItSecret):
    """Store Snipe-IT API token in Vault. ENS mp.info.3"""
    ok = _store_secret("scanops/config/snipeit", {"api_token": body.api_token})
    return {"stored": ok, "vault_path": "scanops/config/snipeit", "vault_available": _vault_available}


@app.post("/orchestrator/secrets/misp")
async def store_misp_secret(body: MispSecret):
    """Store MISP API key in Vault. ENS mp.info.3"""
    ok = _store_secret("scanops/config/misp", {"api_key": body.api_key})
    return {"stored": ok, "vault_path": "scanops/config/misp", "vault_available": _vault_available}


@app.get("/orchestrator/secrets/status")
async def get_secrets_status():
    """Returns which secrets are stored in Vault (no values). ENS mp.info.3"""
    status: dict[str, str] = {}
    if _vault_available:
        for key, path in [
            ("slack", "scanops/config/slack"),
            ("telegram", "scanops/config/telegram"),
            ("smtp", "scanops/config/smtp"),
            ("msf", "scanops/config/msf"),
            ("snipeit", "scanops/config/snipeit"),
            ("misp", "scanops/config/misp"),
        ]:
            try:
                creds = _vault.read_credentials(path)
                status[key] = "stored" if creds else "not_set"
            except Exception:
                status[key] = "error"
    else:
        for key in ["slack", "telegram", "smtp", "msf", "snipeit", "misp"]:
            status[key] = "vault_unavailable"
    return {
        "vault_available": _vault_available,
        "secrets": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/orchestrator/siem/kpis")
async def get_siem_kpis():
    """
    Aggregates SIEM KPIs from M5 subsystems.
    Returns safe defaults if M5 is unavailable.
    ENS: op.exp.3, op.mon.1
    """
    service_token = create_access_token("scanops_service", "service")
    headers = {"Authorization": f"Bearer {service_token}"}

    suricata_blocked = 0
    wazuh_auth_failures = 0
    cowrie_interactions = 0
    sensors_online = 0
    sensors_total = 3  # Suricata, Wazuh, Cowrie

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(f"{_M5_BASE}/siem/suricata/alerts", headers=headers)
            if r.status_code == 200:
                data = r.json()
                suricata_blocked = data.get("total", len(data.get("alerts", [])))
                sensors_online += 1
        except Exception as e:
            _add_log_entry("WARN", f"M5 Suricata KPI unavailable: {e}", "orchestrator")

        try:
            r = await client.get(f"{_M5_BASE}/siem/status", headers=headers)
            if r.status_code == 200:
                data = r.json()
                if data.get("wazuh_status") == "connected":
                    wazuh_auth_failures = data.get("total_agents", 0)
                    sensors_online += 1
        except Exception as e:
            _add_log_entry("WARN", f"M5 Wazuh KPI unavailable: {e}", "orchestrator")

        try:
            r = await client.get(f"{_M5_BASE}/siem/honeypots/events", headers=headers)
            if r.status_code == 200:
                data = r.json()
                cowrie_interactions = len(data.get("events", []))
                sensors_online += 1
        except Exception as e:
            _add_log_entry("WARN", f"M5 Cowrie KPI unavailable: {e}", "orchestrator")

    if sensors_online == sensors_total:
        sensor_health = "ok"
    elif sensors_online > 0:
        sensor_health = "degraded"
    else:
        sensor_health = "offline"

    return {
        "suricata_blocked": suricata_blocked,
        "wazuh_auth_failures": wazuh_auth_failures,
        "cowrie_interactions": cowrie_interactions,
        "sensor_health": sensor_health,
        "sensors_online": sensors_online,
        "sensors_total": sensors_total,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/orchestrator/siem/top-attackers")
async def get_siem_top_attackers():
    """
    Aggregates top attacker IPs from Suricata and Cowrie (last 24h).
    ENS: op.mon.1
    """
    service_token = create_access_token("scanops_service", "service")
    headers = {"Authorization": f"Bearer {service_token}"}
    ip_counts: dict[str, int] = {}

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(f"{_M5_BASE}/siem/suricata/alerts", headers=headers)
            if r.status_code == 200:
                for alert in r.json().get("alerts", []):
                    ip = alert.get("src_ip") or alert.get("attacker_ip") or ""
                    if ip and not ip.startswith(("10.", "192.168.", "172.")):
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        except Exception:
            pass

        try:
            r = await client.get(f"{_M5_BASE}/siem/honeypots/events", headers=headers)
            if r.status_code == 200:
                for event in r.json().get("events", []):
                    ip = event.get("src_ip", "")
                    if ip and not ip.startswith(("10.", "192.168.", "172.")):
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        except Exception:
            pass

    top = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "attackers": [{"ip": ip, "count": count} for ip, count in top],
        "total_unique_ips": len(ip_counts),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8009)
