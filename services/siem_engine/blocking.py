"""
US-6.6 — Respuesta automática CrowdSec + Fail2Ban
ENS: op.exp.7

Loop de fondo: cada 60s consulta alertas Wazuh nivel >= 10
y banea IPs automáticamente.
"""
import os
import asyncio
import ipaddress
import subprocess
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from shared.scan_logger import ScanLogger
from .db import get_conn
from .wazuh_client import WAZUH_API, get_token, new_client

logger = ScanLogger("siem_engine.blocking")
router = APIRouter(tags=["US-6.6 CrowdSec Blocking"])

CROWDSEC_API = os.getenv("CROWDSEC_API_URL", "http://scanops-crowdsec:8080")
CROWDSEC_BOUNCER_KEY = os.getenv("CROWDSEC_BOUNCER_KEY", "")

# IPs privadas RFC-1918 / loopback — nunca se banean
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual"
    severity: str = "MEDIUM"
    source: str = "manual"


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


async def _crowdsec_block(ip: str, reason: str, duration: str = "24h") -> tuple[bool, str]:
    """Intenta bloquear via CrowdSec API; fallback a docker exec."""
    import httpx as _httpx

    # Intento 1: API local CrowdSec
    if CROWDSEC_BOUNCER_KEY:
        try:
            async with _httpx.AsyncClient(timeout=10) as c:
                resp = await c.post(
                    f"{CROWDSEC_API}/v1/decisions",
                    json=[{
                        "duration": duration,
                        "ip": ip,
                        "reason": reason,
                        "scenario": f"scanops/{reason}",
                        "type": "ban",
                    }],
                    headers={"X-Api-Key": CROWDSEC_BOUNCER_KEY},
                )
                if resp.status_code in (200, 201):
                    return True, resp.text[:50]
        except Exception as e:
            logger.warning(f"CrowdSec API failed para {ip}: {e}; intentando docker exec")

    # Intento 2: docker exec (requiere socket montado en M5)
    try:
        result = subprocess.run(
            [
                "docker", "exec", "scanops-crowdsec",
                "cscli", "decisions", "add",
                "--ip", ip,
                "--duration", duration,
                "--reason", reason,
            ],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return True, "docker_exec"
        logger.warning(f"docker exec cscli falló: {result.stderr[:200]}")
    except Exception as e:
        logger.warning(f"docker exec no disponible: {e}")

    # Si todo falla, lo registramos igual en BD (source of truth)
    return False, "crowdsec_unavailable"


def _persist_block(ip: str, reason: str, severity: str, source: str, decision_id: str | None) -> int:
    expires_at = datetime.utcnow() + timedelta(hours=24)
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO siem_blocks (ip, reason, severity, source, expires_at, crowdsec_decision_id)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (ip, reason, severity, source, expires_at, decision_id))
                row = cur.fetchone()
                return row[0] if row else -1
    finally:
        conn.close()


@router.post("/siem/block-ip")
async def block_ip(req: BlockRequest):
    """Banea una IP via CrowdSec y persiste el bloqueo."""
    if _is_private(req.ip):
        raise HTTPException(
            status_code=400,
            detail=f"No se pueden banear IPs privadas/RFC-1918: {req.ip}",
        )

    ok, method = await _crowdsec_block(req.ip, req.reason)
    block_id = _persist_block(req.ip, req.reason, req.severity, req.source, method if ok else None)

    logger.info(f"[US-6.6] IP {req.ip} bloqueada | method={method} | severity={req.severity}")
    return {
        "blocked": True,
        "ip": req.ip,
        "method": "crowdsec" if ok else "db_only",
        "crowdsec_ok": ok,
        "block_id": block_id,
        "expires_in": "24h",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/siem/blocks")
async def list_blocks():
    """Lista IPs baneadas activas."""
    conn = get_conn()
    try:
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, ip, reason, severity, source, blocked_at, expires_at, active
                FROM siem_blocks
                WHERE active = TRUE
                ORDER BY blocked_at DESC
                LIMIT 500
            """)
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("blocked_at"):
                    r["blocked_at"] = r["blocked_at"].isoformat()
                if r.get("expires_at"):
                    r["expires_at"] = r["expires_at"].isoformat()
        return {"total": len(rows), "blocks": rows}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Honeypot attack detection helper (US-6.4)
# ---------------------------------------------------------------------------

async def _check_honeypot_attacks() -> None:
    """Lee cowrie.json y banea IPs con 3+ intentos en los ultimos 60s."""
    import json as _json
    from pathlib import Path as _Path

    cowrie_log = _Path("/var/log/cowrie/cowrie.json")
    if not cowrie_log.exists():
        return

    try:
        lines = cowrie_log.read_text(errors="replace").splitlines()[-500:]
    except OSError:
        return

    cutoff = datetime.utcnow() - timedelta(seconds=60)
    ip_failures: dict[str, int] = {}

    for line in lines:
        if not line.strip():
            continue
        try:
            entry = _json.loads(line)
            if "login" not in str(entry.get("eventid", "")):
                continue
            src_ip = entry.get("src_ip", "")
            if not src_ip or _is_private(src_ip):
                continue
            ts_str = entry.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", ""))
                if ts < cutoff:
                    continue
            except (ValueError, AttributeError):
                pass
            ip_failures[src_ip] = ip_failures.get(src_ip, 0) + 1
        except (_json.JSONDecodeError, KeyError):
            continue

    for ip, count in ip_failures.items():
        if count >= 3:
            ok, method = await _crowdsec_block(ip, "honeypot_ssh_bruteforce", "24h")
            _persist_block(ip, "honeypot_ssh_bruteforce", "HIGH", "honeypot_auto", method if ok else None)
            logger.info(f"[US-6.4] Honeypot auto-blocked {ip} (attempts={count})")


# ---------------------------------------------------------------------------
# Loop de fondo — Wazuh alert → auto-block (US-6.6) + emergency scan (US-6.7)
# ---------------------------------------------------------------------------

_last_alert_check: str = ""


async def wazuh_alert_loop() -> None:
    """Tarea asyncio: cada 60s consulta alertas Wazuh nivel >= 10 y reacciona."""
    global _last_alert_check
    await asyncio.sleep(30)  # warmup inicial

    while True:
        try:
            await _process_wazuh_alerts()
        except Exception as e:
            logger.error(f"[loop] Error en ciclo de alertas: {e}")
        await asyncio.sleep(60)


async def _process_wazuh_alerts() -> None:
    global _last_alert_check

    now = datetime.utcnow()
    if not _last_alert_check:
        _last_alert_check = (now - timedelta(seconds=70)).strftime("%Y-%m-%dT%H:%M:%SZ")

    query_time = _last_alert_check
    _last_alert_check = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Consultar alertas vía OpenSearch (wazuh.indexer alias en red Docker)
    indexer_url = os.getenv("INDEXER_URL", "http://wazuh.indexer:9200")
    import httpx as _httpx
    try:
        async with _httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(
                f"{indexer_url}/wazuh-alerts-*/_search",
                json={
                    "size": 50,
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": {"rule.level": {"gte": 10}}},
                                {"range": {"@timestamp": {"gte": query_time}}},
                            ]
                        }
                    },
                    "_source": ["rule.level", "data.srcip", "agent.id", "agent.ip", "@timestamp"],
                },
            )
            if resp.status_code != 200:
                return
            hits = resp.json().get("hits", {}).get("hits", [])
    except Exception as e:
        logger.debug(f"[loop] OpenSearch no accesible: {e}")
        return

    for hit in hits:
        src = hit.get("_source", {})
        level = int(src.get("rule", {}).get("level", 0))
        src_ip = src.get("data", {}).get("srcip", "")
        agent_ip = src.get("agent", {}).get("ip", "")

        if src_ip and not _is_private(src_ip):
            severity = "CRITICAL" if level >= 13 else "HIGH"
            try:
                ok, method = await _crowdsec_block(src_ip, f"wazuh_level_{level}", "24h")
                _persist_block(src_ip, f"wazuh_level_{level}", severity, "wazuh_auto", method if ok else None)
                logger.info(f"[loop] Auto-blocked {src_ip} (level={level})")

                # Alerta automática si HIGH/CRITICAL
                from .alerting import send_alert
                await asyncio.to_thread(send_alert, {
                    "severity": severity,
                    "ip": src_ip,
                    "level": level,
                    "description": f"IP {src_ip} baneada automáticamente — Wazuh nivel {level}",
                    "timestamp": now.isoformat(),
                })
            except Exception as e:
                logger.warning(f"[loop] No se pudo bloquear {src_ip}: {e}")

        # Emergency scan si activo crítico
        if level >= 10 and agent_ip:
            try:
                from .emergency import _trigger_emergency_for_ip
                await _trigger_emergency_for_ip(
                    agent_ip,
                    f"wazuh_level_{level}",
                    f"wazuh_alert_{hit.get('_id', 'unknown')}",
                )
            except Exception as e:
                logger.debug(f"[loop] Emergency scan skip para {agent_ip}: {e}")

    # Check honeypot attacks every loop cycle
    try:
        await _check_honeypot_attacks()
    except Exception as e:
        logger.debug(f"[loop] Honeypot check skip: {e}")
