"""Shared utilities and base modules for ScanOPS microservices."""

from .auth import get_current_user
from .scan_logger import ScanLogger

try:
    from .database import engine, SessionLocal, get_db, create_tables, drop_tables
except Exception:
    engine = SessionLocal = get_db = create_tables = drop_tables = None  # type: ignore

try:
    from .config import settings
except Exception:
    settings = None  # type: ignore

try:
    from .vault_client import vault_client
except Exception:
    vault_client = None  # type: ignore

__all__ = [
    "engine",
    "SessionLocal",
    "get_db",
    "create_tables",
    "drop_tables",
    "ScanLogger",
    "get_current_user",
    "settings",
    "vault_client",
]
