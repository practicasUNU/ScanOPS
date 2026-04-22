"""Configuration for Scanner Engine (M3)."""

import os
from pydantic_settings import BaseSettings


class ScannerConfig(BaseSettings):
    """Scanner Engine configuration."""

    # OpenVAS Configuration
    OPENVAS_HOST: str = os.getenv("OPENVAS_HOST", "openvas")
    OPENVAS_PORT: int = int(os.getenv("OPENVAS_PORT", 9392))
    OPENVAS_USER: str = os.getenv("OPENVAS_USER", "admin")
    OPENVAS_PASSWORD: str = os.getenv("OPENVAS_PASSWORD", "admin")
    OPENVAS_VERIFY_SSL: bool = os.getenv("OPENVAS_VERIFY_SSL", "False").lower() == "true"
    OPENVAS_TIMEOUT: int = int(os.getenv("OPENVAS_TIMEOUT", 3600))
    OPENVAS_MAX_RETRIES: int = int(os.getenv("OPENVAS_MAX_RETRIES", 3))

    # Nuclei Configuration
    NUCLEI_TEMPLATES_PATH: str = os.getenv(
        "NUCLEI_TEMPLATES_PATH", "/app/templates/nuclei"
    )
    NUCLEI_TIMEOUT: int = int(os.getenv("NUCLEI_TIMEOUT", 1800))
    NUCLEI_MAX_RETRIES: int = int(os.getenv("NUCLEI_MAX_RETRIES", 2))

    # ZAP Configuration
    ZAP_HOST: str = os.getenv("ZAP_HOST", "zap")
    ZAP_PORT: int = int(os.getenv("ZAP_PORT", 8080))
    ZAP_TIMEOUT: int = int(os.getenv("ZAP_TIMEOUT", 1800))
    ZAP_MAX_RETRIES: int = int(os.getenv("ZAP_MAX_RETRIES", 2))

    # Concurrency & Performance
    MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", 5))
    SCAN_TIMEOUT: int = int(os.getenv("SCAN_TIMEOUT", 3600))
    TASK_TIMEOUT: int = int(os.getenv("TASK_TIMEOUT", 7200))

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql://scanops:password@localhost:5432/scanops_db"
    )

    # Redis (for Celery)
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Vault
    VAULT_ADDR: str = os.getenv("VAULT_ADDR", "http://localhost:8200")
    VAULT_TOKEN: str = os.getenv("VAULT_TOKEN", "dev-token")
    VAULT_SECRETS_PATH: str = os.getenv("VAULT_SECRETS_PATH", "secret/data/scanops")

    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    class Config:
        env_file = ".env"
        case_sensitive = True


config = ScannerConfig()
