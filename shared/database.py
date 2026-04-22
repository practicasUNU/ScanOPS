"""Shared database helpers for ScanOPS microservices."""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://scanops:scanops@localhost:5432/scanops"
)

engine = create_engine(DATABASE_URL, echo=False)
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
