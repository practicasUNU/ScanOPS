import os
from typing import Optional, List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Configuración centralizada — ScanOPS M1/M2.
    Cumple con ENS Alto [op.exp.3] para la gestión segura de parámetros.
    """

    # --- Base de Datos ---
    database_url: str = Field(
        default="postgresql://scanops:scanops@localhost:5432/scanops"
    )

    # --- HashiCorp Vault [mp.info.3] ---
    vault_addr: str = Field(default="http://localhost:8200")
    vault_token: Optional[str] = Field(default=None)
    vault_mount_point: str = Field(default="secret")
    vault_timeout: int = Field(default=30)

    # --- Seguridad y JWT ---
    jwt_secret_key: str = Field(default="your-secret-key-at-least-32-chars-long-ens-alto")
    jwt_algorithm: str = Field(default="HS256")

    # --- Redis & Celery (Broker para M1 Tasks) ---
    redis_url: str = Field(default="redis://localhost:6379/0")

    # --- API Configuration (Campos que causaban el error) ---
    api_host: str = Field(default="0.0.0.0")
    redis_url: str = Field(default="redis://localhost:6380/0")

    # --- Logging ---
    log_level: str = Field(default="INFO")

    # --- Pydantic Config ---
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"  # Permite variables en .env que no estén en esta clase
    )

    @field_validator('database_url')
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith(('postgresql://', 'postgresql+psycopg2://')):
            raise ValueError('Database URL debe ser una cadena de conexión válida de PostgreSQL')
        return v

    @field_validator('vault_addr')
    @classmethod
    def validate_vault_addr(cls, v: str) -> str:
        if not v.startswith(('http://', 'https://')):
            raise ValueError('Vault address debe empezar con http:// o https://')
        return v

settings = Settings()