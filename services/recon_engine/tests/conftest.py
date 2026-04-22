"""
Pytest configuration for Recon Engine tests.

Provides fixtures and configuration for testing the reconnaissance engine.
"""

import pytest
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Add services and shared to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'services'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'shared'))

from services.recon_engine.models.recon import ReconBase


@pytest.fixture(scope="session")
def test_engine():
    """Create in-memory SQLite engine for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    ReconBase.metadata.create_all(bind=engine)
    return engine


@pytest.fixture(scope="function")
def test_session(test_engine):
    """Create a new database session for each test."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def cleanup_database(test_session):
    """Clean up database after each test."""
    yield
    # Clean up all tables
    test_session.execute("DELETE FROM recon_subdomains")
    test_session.execute("DELETE FROM recon_findings")
    test_session.execute("DELETE FROM recon_snapshots")
    test_session.commit()
