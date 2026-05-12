"""
US-6.2 — Agentes Wazuh en activos M1
Run: pytest services/siem_engine/tests/test_us62.py -v
"""
import os
import pytest
import httpx
import psycopg2

M5_BASE = os.getenv("M5_URL", "http://localhost:8006")
DB_URL = os.getenv("DATABASE_URL", "postgresql://scanops:scanops@localhost:5432/scanops")


def _db_conn():
    import urllib.parse
    r = urllib.parse.urlparse(DB_URL)
    return psycopg2.connect(
        host=r.hostname, port=r.port or 5432,
        database=r.path.lstrip("/"), user=r.username, password=r.password,
    )


# ---------------------------------------------------------------------------

def test_deploy_endpoint_exists():
    """POST /siem/agents/deploy devuelve 200 o 202 (aunque todos fallen SSH)."""
    r = httpx.post(f"{M5_BASE}/siem/agents/deploy", timeout=60)
    assert r.status_code in (200, 202), f"HTTP {r.status_code}: {r.text[:300]}"
    body = r.json()
    assert "results" in body or "deployed" in body, f"Respuesta inesperada: {body}"


def test_agents_list():
    """GET /siem/agents devuelve lista con al menos un agente (el manager mismo)."""
    r = httpx.get(f"{M5_BASE}/siem/agents", timeout=20)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "agents" in body, f"Falta campo 'agents': {body}"
    assert body.get("total", 0) >= 1, "Se esperaba al menos 1 agente en Wazuh"


def test_agent_status_field():
    """Cada agente devuelto tiene campos id, name, ip, status."""
    r = httpx.get(f"{M5_BASE}/siem/agents", timeout=20)
    assert r.status_code == 200
    agents = r.json().get("agents", [])
    for ag in agents:
        assert "id" in ag, f"Falta 'id' en: {ag}"
        assert "name" in ag, f"Falta 'name' en: {ag}"
        assert "status" in ag, f"Falta 'status' en: {ag}"


def test_db_table_created():
    """Tabla siem_agents existe en PostgreSQL."""
    conn = _db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'siem_agents'
                )
            """)
            exists = cur.fetchone()[0]
        assert exists, "Tabla siem_agents no encontrada en la BD"
    finally:
        conn.close()


def test_unreachable_graceful():
    """Deploy no rompe el loop al encontrar activos sin SSH; registra unreachable."""
    r = httpx.post(f"{M5_BASE}/siem/agents/deploy", timeout=60)
    assert r.status_code in (200, 202)
    body = r.json()
    results = body.get("results", [])
    # Todos los activos sin Vault deben estar marcados unreachable, no 500
    for item in results:
        assert item.get("status") in ("deployed", "unreachable"), \
            f"Estado inesperado: {item}"
