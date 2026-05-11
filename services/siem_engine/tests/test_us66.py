"""
US-6.6 — Respuesta automática CrowdSec + Fail2Ban
Run: pytest services/siem_engine/tests/test_us66.py -v
"""
import os
import subprocess
import pytest
import httpx
import psycopg2

M5_BASE = os.getenv("M5_URL", "http://localhost:8006")
DB_URL = os.getenv("DATABASE_URL", "postgresql://scanops:scanops@localhost:5432/scanops")

_TEST_IP = "1.2.3.4"


def _db_conn():
    import urllib.parse
    r = urllib.parse.urlparse(DB_URL)
    return psycopg2.connect(
        host=r.hostname, port=r.port or 5432,
        database=r.path.lstrip("/"), user=r.username, password=r.password,
    )


# ---------------------------------------------------------------------------

def test_block_ip_endpoint():
    """POST /siem/block-ip con IP pública devuelve 200 y blocked=true."""
    r = httpx.post(
        f"{M5_BASE}/siem/block-ip",
        json={"ip": _TEST_IP, "reason": "brute_force", "severity": "HIGH", "source": "test"},
        timeout=20,
    )
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("blocked") is True, f"blocked!=True: {body}"
    assert body.get("ip") == _TEST_IP


def test_blocks_list():
    """GET /siem/blocks devuelve lista (puede estar vacía, nunca 500)."""
    r = httpx.get(f"{M5_BASE}/siem/blocks", timeout=10)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "blocks" in body, f"Falta campo 'blocks': {body}"
    assert isinstance(body["blocks"], list)


def test_crowdsec_container():
    """scanops-crowdsec aparece en docker ps."""
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=10,
    )
    assert "scanops-crowdsec" in result.stdout, \
        f"scanops-crowdsec no encontrado en docker ps:\n{result.stdout}"


def test_db_blocks_table():
    """Tabla siem_blocks existe en PostgreSQL."""
    conn = _db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'siem_blocks'
                )
            """)
            assert cur.fetchone()[0], "Tabla siem_blocks no encontrada"
    finally:
        conn.close()


def test_private_ip_rejected():
    """IPs privadas devuelven 400, no se banean."""
    for ip in ("192.168.1.100", "10.0.0.1", "172.16.5.5"):
        r = httpx.post(
            f"{M5_BASE}/siem/block-ip",
            json={"ip": ip, "reason": "test", "severity": "LOW", "source": "test"},
            timeout=10,
        )
        assert r.status_code == 400, f"IP privada {ip} no rechazada: HTTP {r.status_code}"
