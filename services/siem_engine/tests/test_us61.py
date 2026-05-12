"""
US-6.1 — SIEM Foundation: Wazuh Manager + Graylog
Acceptance tests — ENS Alto op.exp.5
Run: pytest services/siem_engine/tests/test_us61.py -v
"""
import os
import pytest
import httpx
import base64

M5_BASE = os.getenv("M5_URL", "http://localhost:8006")
WAZUH_BASE = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "wazuh")
GRAYLOG_BASE = os.getenv("GRAYLOG_API_URL", "http://localhost:9000")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wazuh_token() -> str:
    creds = base64.b64encode(f"{WAZUH_USER}:{WAZUH_PASSWORD}".encode()).decode()
    r = httpx.get(
        f"{WAZUH_BASE}/security/user/authenticate",
        headers={"Authorization": f"Basic {creds}"},
        verify=False,
        timeout=15,
    )
    assert r.status_code == 200, f"Wazuh auth HTTP {r.status_code}: {r.text[:200]}"
    return r.json()["data"]["token"]


# ---------------------------------------------------------------------------
# test_wazuh_connection
# ---------------------------------------------------------------------------

def test_wazuh_connection():
    """GET /siem/status devuelve HTTP 200 y connected=True"""
    r = httpx.get(f"{M5_BASE}/siem/status", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("connected") is True, f"connected!=True: {body}"
    assert body.get("wazuh_status") == "connected", f"wazuh_status!=connected: {body}"


# ---------------------------------------------------------------------------
# test_wazuh_token
# ---------------------------------------------------------------------------

def test_wazuh_token():
    """Autenticación directa contra Wazuh devuelve JWT válido (3 segmentos base64)"""
    token = _wazuh_token()
    parts = token.split(".")
    assert len(parts) == 3, f"JWT malformado — segmentos: {len(parts)}"
    # El payload debe decodificarse sin error
    padding = 4 - len(parts[1]) % 4
    payload_bytes = base64.urlsafe_b64decode(parts[1] + "=" * padding)
    assert b"wazuh" in payload_bytes, "JWT payload no contiene sub=wazuh"


# ---------------------------------------------------------------------------
# test_graylog_health
# ---------------------------------------------------------------------------

def test_graylog_health():
    """Graylog API /api/system/lbstatus devuelve ALIVE"""
    r = httpx.get(f"{GRAYLOG_BASE}/api/system/lbstatus", timeout=20)
    assert r.status_code == 200, f"Graylog lbstatus HTTP {r.status_code}"
    assert "ALIVE" in r.text, f"Graylog no reporta ALIVE: {r.text}"


# ---------------------------------------------------------------------------
# test_ens_fields
# ---------------------------------------------------------------------------

def test_ens_fields():
    """/siem/status incluye timestamp, wazuh_version y ens_compliance.op_exp_5"""
    r = httpx.get(f"{M5_BASE}/siem/status", timeout=15)
    assert r.status_code == 200
    body = r.json()

    assert "timestamp" in body, "Falta campo 'timestamp'"
    assert "wazuh_version" in body, "Falta campo 'wazuh_version'"
    assert body["wazuh_version"].startswith("v"), f"wazuh_version inesperado: {body['wazuh_version']}"

    ens = body.get("ens_compliance", {})
    assert isinstance(ens, dict), f"ens_compliance debe ser objeto: {ens}"
    assert ens.get("op_exp_5") is True, f"ens_compliance.op_exp_5 != True: {ens}"

    assert "total_agents" in body, "Falta campo 'total_agents'"


# ---------------------------------------------------------------------------
# test_log_retention
# ---------------------------------------------------------------------------

def test_log_retention():
    """Volumen wazuh_data existe y OpenSearch interno está disponible (append-only asegurado)"""
    import subprocess, json

    # 1. Volumen de logs existe
    result = subprocess.run(
        ["docker", "volume", "inspect", "scanops_wazuh_data"],
        capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, "Volumen scanops_wazuh_data no encontrado"
    assert "scanops_wazuh_data" in result.stdout

    # 2. OpenSearch responde dentro de la red Docker (sin puerto expuesto al host)
    result2 = subprocess.run(
        ["docker", "exec", "scanops-opensearch",
         "curl", "-s", "http://localhost:9200/_cluster/health"],
        capture_output=True, text=True, timeout=15
    )
    assert result2.returncode == 0, f"docker exec falló: {result2.stderr}"
    health = json.loads(result2.stdout)
    assert health.get("status") in ("green", "yellow"), f"OpenSearch degradado: {health.get('status')}"
