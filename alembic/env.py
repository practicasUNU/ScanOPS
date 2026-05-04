import os
import sys
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# 1. Asegurar que los servicios sean importables
# Agregamos la raíz del proyecto al sys.path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

# 2. Configuración de Alembic
config = context.config

# 3. Configuración de Logging
# Interpretamos el archivo de configuración para el logging.
# Esto es lo que causaba el KeyError: 'formatter_generic' si la sección faltaba.
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# 4. Importación de Metadatos
# Importamos el Base de los modelos para autogeneración
try:
    from services.asset_manager.models.asset import Base as AssetBase
    target_metadata = AssetBase.metadata
except ImportError as e:
    print(f"Advertencia: No se pudieron importar los modelos: {e}")
    target_metadata = None

def run_migrations_offline() -> None:
    """Modo offline: genera SQL sin conectar a la DB."""
    url = config.get_main_option("sqlalchemy.url")
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
    # Priorizamos la URL de la configuración o variable de entorno
    database_url = os.getenv(
        "DATABASE_URL", 
        config.get_main_option("sqlalchemy.url")
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