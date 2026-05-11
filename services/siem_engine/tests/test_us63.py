"""
US-6.3 -- Suricata IDS
Run: pytest services/siem_engine/tests/test_us63.py -v
"""
import subprocess
import os
import pytest
import httpx

M5_BASE = os.getenv("M5_URL", "http://localhost:8006")


def test_suricata_container_running():
    """scanops-suricata esta corriendo (verificado via Docker socket o status endpoint)."""
    container_found = False

    # Metodo 1: Docker Unix socket API (disponible desde M5 via volumen)
    try:
        import socket as _socket
        import json as _json
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
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
        containers = _json.loads(body)
        names = [n for c in containers for n in c.get("Names", [])]
        container_found = any("scanops-suricata" in n for n in names)
    except Exception:
        pass

    # Metodo 2: fallback via status endpoint
    if not container_found:
        r = httpx.get(f"{M5_BASE}/siem/suricata/status", timeout=10)
        if r.status_code == 200:
            container_found = r.json().get("status") == "running"

    assert container_found, "scanops-suricata no detectado como running"


def test_suricata_status_endpoint():
    """GET /siem/suricata/status devuelve 200 con campo status."""
    r = httpx.get(f"{M5_BASE}/siem/suricata/status", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "status" in body, f"Falta campo 'status': {body}"
    assert body["status"] in ("running", "stopped"), f"Valor inesperado: {body['status']}"


def test_suricata_alerts_endpoint():
    """GET /siem/suricata/alerts devuelve 200 con lista (puede estar vacia)."""
    r = httpx.get(f"{M5_BASE}/siem/suricata/alerts", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "alerts" in body, f"Falta campo 'alerts': {body}"
    assert isinstance(body["alerts"], list), f"'alerts' no es lista: {body}"
    assert "count" in body, f"Falta campo 'count': {body}"


def test_suricata_stats_endpoint():
    """GET /siem/suricata/stats devuelve 200 con campo stats."""
    r = httpx.get(f"{M5_BASE}/siem/suricata/stats", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "stats" in body, f"Falta campo 'stats': {body}"
    stats = body["stats"]
    assert "packets_captured" in stats, f"Falta packets_captured: {stats}"
    assert "alerts" in stats, f"Falta alerts: {stats}"
    assert "drops" in stats, f"Falta drops: {stats}"


def test_ens_compliance_field():
    """GET /siem/suricata/status incluye ens_compliance.op_exp_4: true."""
    r = httpx.get(f"{M5_BASE}/siem/suricata/status", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    compliance = body.get("ens_compliance", {})
    assert compliance.get("op_exp_4") is True, (
        f"ens_compliance.op_exp_4 no es True: {compliance}"
    )
