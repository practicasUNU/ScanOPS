"""
US-6.4 -- Honeypots Cowrie + Beelzebub
Run: pytest services/siem_engine/tests/test_us64.py -v
"""
import json
import os
import socket as _socket
import pytest
import httpx

M5_BASE = os.getenv("M5_URL", "http://localhost:8006")


def _docker_containers() -> list[dict]:
    """Query Docker daemon via Unix socket to get running containers."""
    try:
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect("/var/run/docker.sock")
        request = b"GET /containers/json HTTP/1.0\r\nHost: localhost\r\n\r\n"
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk
        sock.close()
        body = response.split(b"\r\n\r\n", 1)[1]
        # Strip chunked encoding if present
        lines = body.decode(errors="replace").splitlines()
        json_start = next((i for i, l in enumerate(lines) if l.startswith("[")), 0)
        return json.loads("\n".join(lines[json_start:]))
    except Exception:
        return []


def _container_names() -> list[str]:
    containers = _docker_containers()
    return [n for c in containers for n in c.get("Names", [])]


def _container_networks(container_name: str) -> list[str]:
    """Return list of network names a container is attached to via Docker socket API."""
    # Strip leading slash from container name
    cname = container_name.lstrip("/")
    try:
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect("/var/run/docker.sock")
        path = f"/containers/{cname}/json"
        request = f"GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode()
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk
        sock.close()
        body = response.split(b"\r\n\r\n", 1)[1]
        lines = body.decode(errors="replace").splitlines()
        json_start = next((i for i, l in enumerate(lines) if l.startswith("{")), 0)
        data = json.loads("\n".join(lines[json_start:]))
        networks = data.get("NetworkSettings", {}).get("Networks", {})
        return list(networks.keys())
    except Exception:
        return []


def test_cowrie_running():
    """scanops-cowrie aparece en docker ps Up."""
    names = _container_names()
    running = any("scanops-cowrie" in n for n in names)
    if not running:
        # Fallback: status endpoint
        try:
            r = httpx.get(f"{M5_BASE}/siem/honeypots/status", timeout=10)
            if r.status_code == 200:
                running = r.json().get("cowrie", {}).get("status") == "running"
        except Exception:
            pass
    assert running, "scanops-cowrie no detectado como running"


def test_beelzebub_running():
    """scanops-beelzebub aparece en docker ps Up."""
    names = _container_names()
    running = any("scanops-beelzebub" in n for n in names)
    if not running:
        # Fallback: status endpoint
        try:
            r = httpx.get(f"{M5_BASE}/siem/honeypots/status", timeout=10)
            if r.status_code == 200:
                running = r.json().get("beelzebub", {}).get("status") == "running"
        except Exception:
            pass
    assert running, "scanops-beelzebub no detectado como running"


def test_honeypots_status_endpoint():
    """GET /siem/honeypots/status devuelve 200 con cowrie y beelzebub."""
    r = httpx.get(f"{M5_BASE}/siem/honeypots/status", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "cowrie" in body, f"Falta campo 'cowrie': {body}"
    assert "beelzebub" in body, f"Falta campo 'beelzebub': {body}"
    assert "status" in body["cowrie"], f"cowrie sin 'status': {body}"
    assert "status" in body["beelzebub"], f"beelzebub sin 'status': {body}"


def test_honeypots_events_endpoint():
    """GET /siem/honeypots/events devuelve 200 con lista."""
    r = httpx.get(f"{M5_BASE}/siem/honeypots/events", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "events" in body, f"Falta campo 'events': {body}"
    assert isinstance(body["events"], list), f"'events' no es lista: {body}"
    assert "count" in body, f"Falta campo 'count': {body}"


def test_honeypots_attackers_endpoint():
    """GET /siem/honeypots/attackers devuelve 200 con lista."""
    r = httpx.get(f"{M5_BASE}/siem/honeypots/attackers", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "attackers" in body, f"Falta campo 'attackers': {body}"
    assert isinstance(body["attackers"], list), f"'attackers' no es lista: {body}"


def test_network_isolation_cowrie():
    """docker inspect scanops-cowrie NO muestra scanops_network."""
    networks = _container_networks("scanops-cowrie")
    assert networks, "No se pudo obtener redes de scanops-cowrie via Docker socket"
    assert "scanops" not in networks, (
        f"scanops-cowrie esta en scanops_network (violacion de aislamiento): {networks}"
    )


def test_network_isolation_beelzebub():
    """docker inspect scanops-beelzebub NO muestra scanops_network."""
    networks = _container_networks("scanops-beelzebub")
    assert networks, "No se pudo obtener redes de scanops-beelzebub via Docker socket"
    assert "scanops" not in networks, (
        f"scanops-beelzebub esta en scanops_network (violacion de aislamiento): {networks}"
    )


def test_ens_compliance():
    """Respuesta status incluye ens_compliance.op_exp_4: true."""
    r = httpx.get(f"{M5_BASE}/siem/honeypots/status", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    compliance = body.get("ens_compliance", {})
    assert compliance.get("op_exp_4") is True, (
        f"ens_compliance.op_exp_4 no es True: {compliance}"
    )
