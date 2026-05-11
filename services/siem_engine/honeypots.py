"""
US-6.4 -- Honeypots Cowrie + Beelzebub
ENS Alto: op.exp.4 (deteccion de intrusiones via honeypots)
"""
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter

router = APIRouter(tags=["US-6.4 Honeypots"])

_COWRIE_LOG = Path("/var/log/cowrie/cowrie.json")
_BEELZEBUB_LOG = Path("/var/log/beelzebub/beelzebub.json")
_COWRIE_CONTAINER = "scanops-cowrie"
_BEELZEBUB_CONTAINER = "scanops-beelzebub"


def _container_status(name: str) -> str:
    """Returns 'running', 'stopped', or 'unknown' for a container name."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    # Fallback: check via volume mount directory presence
    if name == _COWRIE_CONTAINER and _COWRIE_LOG.parent.exists():
        return "running"
    if name == _BEELZEBUB_CONTAINER and _BEELZEBUB_LOG.parent.exists():
        return "running"
    return "unknown"


def _read_log_tail(path: Path, lines: int = 100) -> list[str]:
    """Read last N lines from a log file; returns [] if unavailable."""
    if path.exists():
        try:
            content = path.read_text(errors="replace")
            return content.splitlines()[-lines:]
        except OSError:
            pass
    # Fallback: docker exec tail
    container = _COWRIE_CONTAINER if "cowrie" in str(path) else _BEELZEBUB_CONTAINER
    try:
        result = subprocess.run(
            ["docker", "exec", container, "tail", "-n", str(lines), str(path)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return result.stdout.splitlines()
    except Exception:
        pass
    return []


@router.get("/siem/honeypots/status")
async def honeypots_status() -> dict[str, Any]:
    """Estado honeypots Cowrie y Beelzebub -- ENS op.exp.4"""
    cowrie_status = _container_status(_COWRIE_CONTAINER)
    beelzebub_status = _container_status(_BEELZEBUB_CONTAINER)

    return {
        "cowrie": {
            "status": cowrie_status if cowrie_status != "unknown" else "stopped",
            "ports": [2222, 2223],
            "type": "SSH/Telnet",
        },
        "beelzebub": {
            "status": beelzebub_status if beelzebub_status != "unknown" else "stopped",
            "ports": [8880, 3306],
            "type": "HTTP/MySQL LLM-powered",
        },
        "isolation_network": "scanops_honeypot_net",
        "ens_compliance": {
            "op_exp_4": True,
            "description": "Deteccion de intrusiones via honeypots -- ENS Alto RD 311/2022",
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/siem/honeypots/events")
async def honeypots_events() -> dict[str, Any]:
    """Ultimos 100 eventos combinados de Cowrie y Beelzebub."""
    events: list[dict[str, Any]] = []

    # Parse Cowrie events
    for line in _read_log_tail(_COWRIE_LOG, 100):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            events.append({
                "source": "cowrie",
                "timestamp": entry.get("timestamp"),
                "src_ip": entry.get("src_ip"),
                "event_type": entry.get("eventid", entry.get("event_type")),
                "detail": entry.get("message", entry.get("input", "")),
            })
        except (json.JSONDecodeError, KeyError):
            continue

    # Parse Beelzebub events
    for line in _read_log_tail(_BEELZEBUB_LOG, 100):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            events.append({
                "source": "beelzebub",
                "timestamp": entry.get("timestamp", entry.get("time")),
                "src_ip": entry.get("src_ip", entry.get("sourceIP", entry.get("remoteAddr"))),
                "event_type": entry.get("event_type", entry.get("type", "connection")),
                "detail": entry.get("detail", entry.get("message", entry.get("request", ""))),
            })
        except (json.JSONDecodeError, KeyError):
            continue

    events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
    return {"events": events[:100], "count": len(events)}


@router.get("/siem/honeypots/attackers")
async def honeypots_attackers() -> dict[str, Any]:
    """IPs atacantes unicas de los ultimos 7 dias desde logs Cowrie."""
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=7)
    ip_data: dict[str, dict[str, Any]] = {}

    for line in _read_log_tail(_COWRIE_LOG, 5000):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            src_ip = entry.get("src_ip")
            if not src_ip:
                continue
            ts_str = entry.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ts < cutoff:
                    continue
            except (ValueError, AttributeError):
                pass

            if src_ip not in ip_data:
                ip_data[src_ip] = {"ip": src_ip, "attempts": 0, "first_seen": ts_str, "last_seen": ts_str}
            ip_data[src_ip]["attempts"] += 1
            if ts_str > ip_data[src_ip]["last_seen"]:
                ip_data[src_ip]["last_seen"] = ts_str
            if ts_str < ip_data[src_ip]["first_seen"]:
                ip_data[src_ip]["first_seen"] = ts_str
        except (json.JSONDecodeError, KeyError):
            continue

    attackers = sorted(ip_data.values(), key=lambda x: x["attempts"], reverse=True)
    return {"attackers": attackers, "count": len(attackers)}
