"""
US-6.4 -- Honeypots Cowrie + Beelzebub
ENS Alto: op.exp.4 (deteccion de intrusiones via honeypots)
"""
import http.client
import json
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter


_DOCKER_SOCKET = "/var/run/docker.sock"


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection over a Unix domain socket (used to call the Docker API)."""
    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost")
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self._socket_path)
        self.sock = sock


def _docker_logs_via_socket(container: str, tail: int = 300) -> list[str]:
    """Read container stdout+stderr logs via Docker Unix socket without the docker CLI."""
    try:
        conn = _UnixHTTPConnection(_DOCKER_SOCKET)
        conn.request("GET", f"/containers/{container}/logs?stdout=1&stderr=1&tail={tail}")
        resp = conn.getresponse()
        if resp.status != 200:
            return []
        raw = resp.read()
        # Docker multiplexed log format: 8-byte header [type(1), 0,0,0, size(4 BE)] + payload
        lines: list[str] = []
        i = 0
        while i + 8 <= len(raw):
            size = int.from_bytes(raw[i + 4: i + 8], "big")
            payload = raw[i + 8: i + 8 + size]
            lines.append(payload.decode("utf-8", errors="replace").rstrip("\n"))
            i += 8 + size
        return lines
    except Exception:
        return []

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
    # Fallback: docker exec tail (works for containers with shell/coreutils)
    container = _COWRIE_CONTAINER if "cowrie" in str(path) else _BEELZEBUB_CONTAINER
    try:
        result = subprocess.run(
            ["docker", "exec", container, "tail", "-n", str(lines), str(path)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.splitlines()
    except Exception:
        pass
    # Last resort: Docker socket API (works for distroless containers without shell/CLI)
    socket_lines = _docker_logs_via_socket(container, tail=lines * 3)
    if socket_lines:
        return socket_lines[-lines:]
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

    # Parse Beelzebub events — logs use a nested {"event": {...}, "msg": "New Event"} structure
    for line in _read_log_tail(_BEELZEBUB_LOG, 100):
        if not line.strip():
            continue
        try:
            outer = json.loads(line)
            # Skip startup lines (no nested event object)
            if outer.get("msg") != "New Event":
                continue
            ev = outer.get("event", {})
            src_ip = ev.get("SourceIp") or ev.get("sourceIP") or ""
            # Normalize "ip:port" → just ip
            if src_ip and ":" in src_ip:
                src_ip = src_ip.rsplit(":", 1)[0]
            protocol = ev.get("Protocol", "HTTP")
            uri = ev.get("RequestURI", "")
            method = ev.get("HTTPMethod", "")
            desc = ev.get("Description", "")
            event_type = f"{protocol} {method} {uri}".strip() if uri else f"{protocol} {ev.get('Msg', 'connection')}"
            detail_parts = []
            if uri:
                detail_parts.append(f"{method} {uri}")
            if ev.get("Body"):
                detail_parts.append(f"Body: {ev['Body']}")
            if ev.get("UserAgent"):
                detail_parts.append(f"UA: {ev['UserAgent']}")
            if desc and not uri:
                detail_parts.append(desc)
            events.append({
                "source": "beelzebub",
                "timestamp": ev.get("DateTime", outer.get("time")),
                "src_ip": src_ip or None,
                "event_type": event_type,
                "detail": " | ".join(detail_parts) if detail_parts else ev.get("Msg", ""),
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
