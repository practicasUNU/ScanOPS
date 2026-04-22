"""
Test fixtures for Asset Manager — US-1.8
=========================================
Provides:
  - SQLite in-memory DB for fast unit tests
  - PostgreSQL testcontainer for integration tests (optional)
  - FastAPI TestClient with auth override
  - Mock Vault client

FIX: The key issue was that `main.py` startup event calls
     `Base.metadata.create_all(bind=engine)` using the PRODUCTION engine.
     We must override `shared.database.engine` so that both the dependency
     injection (get_db) AND the startup event use the same test engine.
"""

import os
import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from services.asset_manager.models.asset import Base


# ─── Database Fixtures ────────────────────────────────────

@pytest.fixture
def test_engine():
    """Create a SQLite in-memory engine and tables."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def test_db(test_engine):
    """In-memory SQLite session for fast unit tests."""
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def pg_db():
    """
    PostgreSQL database for integration tests.
    Requires SCANOPS_TEST_DB_URL env var or a running PostgreSQL on localhost.
    Skip if not available.
    """
    db_url = os.getenv(
        "SCANOPS_TEST_DB_URL",
        "postgresql://scanops:scanops@localhost:5432/scanops_test",
    )
    try:
        from sqlalchemy import text
        engine = create_engine(db_url, echo=False)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available — set SCANOPS_TEST_DB_URL")

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestSession()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


# ─── Vault Mock ───────────────────────────────────────────

@pytest.fixture
def mock_vault():
    """Mock Vault client so tests don't need a running Vault server."""
    _store = {}

    mock = MagicMock()
    mock.is_connected = True

    def _store_creds(path, credentials, metadata=None):
        _store[path] = credentials
        return True

    def _read_creds(path):
        return _store.get(path)

    mock.store_credentials = MagicMock(side_effect=_store_creds)
    mock.read_credentials = MagicMock(side_effect=_read_creds)
    mock.connect = MagicMock(return_value=True)
    mock._store = _store

    with patch("services.asset_manager.services.asset_service.vault_client", mock):
        yield mock


# ─── Auth Override ────────────────────────────────────────

def _fake_current_user():
    """Simulated authenticated user for tests."""
    return {"user": "test_user", "role": "resp_sistema"}


# ─── FastAPI TestClient ──────────────────────────────────

@pytest.fixture
def client(test_engine, test_db, mock_vault):
    """
    FastAPI TestClient with:
      - SQLite test engine patched into shared.database
        (so the startup event creates tables on the TEST engine)
      - SQLite test DB session injected via get_db
      - Auth bypassed (returns test_user)
      - Vault mocked
    """
    from shared.auth import get_current_user
    from shared.database import get_db

    # Import app AFTER we have the engine ready
    from services.asset_manager.main import app

    # Override get_db to return our test session
    def _override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _fake_current_user

    # Patch the shared.database.engine so that the startup event
    # (Base.metadata.create_all(bind=engine)) uses our test engine
    with patch("services.asset_manager.main.engine", test_engine):
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c

    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers():
    """Bearer token header for authenticated requests."""
    return {"Authorization": "Bearer scanops_secret"}


# ─── Sample Data ──────────────────────────────────────────

@pytest.fixture
def sample_asset_data():
    """Valid asset data dict for creating test assets (model-level)."""
    return {
        "ip": "10.202.15.100",
        "hostname": "srv-auditoria-01",
        "criticidad": "ALTA",
        "tipo": "SERVER",
        "responsable": "Equipo SOC",
        "departamento": "Seguridad",
        "ubicacion": "CPD Principal",
        "tags_ens": ["op.exp.1", "op.acc.6"],
        "os_family": "linux",
        "os_version": "Ubuntu 22.04 LTS",
    }


@pytest.fixture
def sample_api_payload():
    """Valid JSON payload for POST /assets."""
    return {
        "ip": "10.202.15.100",
        "hostname": "srv-auditoria-01",
        "criticidad": "ALTA",
        "tipo": "SERVER",
        "responsable": "Equipo SOC",
        "departamento": "Seguridad",
        "ubicacion": "CPD Principal",
        "tags_ens": ["op.exp.1", "op.acc.6"],
        "os_family": "linux",
        "os_version": "Ubuntu 22.04 LTS",
    }


@pytest.fixture
def created_asset(client, sample_api_payload, auth_headers):
    """Helper: creates one asset via API and returns the response dict."""
    resp = client.post("/assets", json=sample_api_payload, headers=auth_headers)
    assert resp.status_code == 201, f"Failed to create asset: {resp.text}"
    return resp.json()
