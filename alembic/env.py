import os
import sys
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool, MetaData
from alembic import context

# 1. Asegurar que los servicios sean importables [cite: 327]
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

# Configuración de Alembic [cite: 306]
config = context.config



# 3. IMPORTACIÓN DE MODELOS (US-1.1, US-2.1, US-3.5) [cite: 337, 358, 533, 757]
try:
    from services.recon_engine.models.recon import Base as ReconBase
    from services.asset_manager.models.asset import Base as AssetBase
    from services.scanner_engine.models.vulnerability import Base as VulnerabilityBase
except ImportError as e:
    print(f"ERROR DE IMPORTACIÓN: {e}")
    sys.exit(1)

# 4. UNIFICACIÓN DE METADATA (ENS Alto: Integridad de BD) 
target_metadata = MetaData()

def merge_metadata(base):
    for table in base.metadata.tables.values():
        table.to_metadata(target_metadata)

merge_metadata(ReconBase)
merge_metadata(AssetBase)
merge_metadata(VulnerabilityBase)

def run_migrations_offline() -> None:
    """Modo offline: genera SQL sin conectar a la DB."""
    url = os.getenv("DATABASE_URL", config.get_main_option("sqlalchemy.url"))
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Modo online: se conecta a PostgreSQL y aplica cambios."""
    # Priorizamos la variable de entorno de Docker 
    database_url = os.getenv(
        "DATABASE_URL", 
        "postgresql://scanops:scanops@postgres:5432/scanops"
    )

    connectable = engine_from_config(
        {"sqlalchemy.url": database_url},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()