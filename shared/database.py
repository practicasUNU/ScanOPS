"""Shared database helpers for ScanOPS microservices."""

import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

logger = logging.getLogger(__name__)

# Intentar importar psycopg2 de forma opcional
try:
    import psycopg2
    PSYCOPG2_AVAILABLE = True
except ImportError:
    # psycopg2 not available, will fallback to sqlite if needed
    PSYCOPG2_AVAILABLE = False
    logger.warning("psycopg2 no está instalado. PostgreSQL no estará disponible.")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://scanops:scanops@localhost:5432/scanops"
)

# Lógica de fallback para TESTS o falta de driver
is_testing = os.getenv("TESTING", "false").lower() == "true"

if not PSYCOPG2_AVAILABLE or is_testing or "sqlite" in DATABASE_URL:
    if not DATABASE_URL.startswith("sqlite"):
        logger.info("Cambiando a SQLite para tests o por falta de psycopg2")
        DATABASE_URL = "sqlite:///./scanops_local.db"

# Configuración específica según el dialecto
engine_kwargs = {"echo": False}
if DATABASE_URL.startswith("sqlite"):
    # Necesario para SQLite en aplicaciones multihilo (FastAPI)
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """Yields a database session for FastAPI dependencies."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables(metadata):
    """Create tables for a given metadata object."""
    metadata.create_all(bind=engine)


def drop_tables(metadata):
    """Drop tables for a given metadata object."""
    metadata.drop_all(bind=engine)
