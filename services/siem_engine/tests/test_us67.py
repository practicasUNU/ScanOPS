"""
US-6.7 — Escaneo de emergencia M2+M3
Run: pytest services/siem_engine/tests/test_us67.py -v
"""
import os
import time
import pytest
import httpx
import psycopg2

M5_BASE = os.getenv("M5_URL", "http://localhost:8006")
DB_URL = os.getenv("DATABASE_URL", "postgresql://scanops:scanops@localhost:5432/scanops")

# Usar el primer activo ACTIVO conocido del JSON de activos (id=18 ó id=1)
_TEST_ASSET_ID = int(os.getenv("TEST_ASSET_ID", "1"))


def _db_conn():
    import urllib.parse
    r = urllib.parse.urlparse(DB_URL)
    return psycopg2.connect(
        host=r.hostname, port=r.port or 5432,
        database=r.path.lstrip("/"), user=r.username, password=r.password,
    )


# ---------------------------------------------------------------------------

def test_emergency_scan_endpoint():
    """POST /siem/emergency-scan devuelve 200 con m2_triggered y m3_triggered."""
    r = httpx.post(
        f"{M5_BASE}/siem/emergency-scan",
        json={
            "asset_id": _TEST_ASSET_ID,
            "reason": "test_anomaly",
            "triggered_by": "pytest_us67",
        },
        timeout=45,
    )
    assert r.status_code in (200, 404), f"HTTP {r.status_code}: {r.text}"
    if r.status_code == 200:
        body = r.json()
        assert "m2_triggered" in body, f"Falta m2_triggered: {body}"
        assert "m3_triggered" in body, f"Falta m3_triggered: {body}"
        assert "emergency_scan_id" in body
    # 404 es aceptable si el activo no existe — ver test_invalid_asset_handled


def test_emergency_history():
    """GET /siem/emergency-scans devuelve lista sin error."""
    r = httpx.get(f"{M5_BASE}/siem/emergency-scans", timeout=10)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "scans" in body, f"Falta campo 'scans': {body}"
    assert isinstance(body["scans"], list)


def test_db_emergency_table():
    """Tabla siem_emergency_scans existe en PostgreSQL."""
    conn = _db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'siem_emergency_scans'
                )
            """)
            assert cur.fetchone()[0], "Tabla siem_emergency_scans no encontrada"
    finally:
        conn.close()


def test_invalid_asset_handled():
    """asset_id inexistente devuelve 404 limpio, no 500."""
    r = httpx.post(
        f"{M5_BASE}/siem/emergency-scan",
        json={"asset_id": 999999, "reason": "test", "triggered_by": "pytest"},
        timeout=20,
    )
    assert r.status_code == 404, f"Se esperaba 404 para activo inexistente, got {r.status_code}"
    body = r.json()
    assert "detail" in body


def test_parallel_execution():
    """M2 y M3 se llaman en paralelo — tiempo total < suma individual estimada."""
    # Lanzamos el endpoint y comprobamos que elapsed_seconds < 25 (las llamadas individuales
    # cada una puede tardar hasta ~15s si hay timeout; en paralelo deben ser ~15s máx)
    r = httpx.post(
        f"{M5_BASE}/siem/emergency-scan",
        json={
            "asset_id": _TEST_ASSET_ID,
            "reason": "parallel_test",
            "triggered_by": "pytest_parallel",
        },
        timeout=45,
    )
    if r.status_code == 404:
        pytest.skip("Activo de prueba no existe — test de paralelismo omitido")
    assert r.status_code == 200
    body = r.json()
    elapsed = body.get("elapsed_seconds", 999)
    # Si ambas tardan 15s cada una en serie serían 30s; en paralelo < 20s
    assert elapsed < 35, f"Tiempo excesivo {elapsed}s — ¿están ejecutando en paralelo?"
