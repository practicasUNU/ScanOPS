"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-04-28 14:15:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE criticidadenum AS ENUM ('BAJA', 'MEDIA', 'ALTA', 'PENDIENTE_CLASIFICAR');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;

        DO $$ BEGIN
            CREATE TYPE tipoactivoenum AS ENUM ('ENDPOINT', 'SERVER', 'RED', 'APLICACION', 'IOT', 'OTRO');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;

        DO $$ BEGIN
            CREATE TYPE assetstatusenum AS ENUM ('ACTIVO', 'BAJA', 'MANTENIMIENTO', 'PENDIENTE_ALTA', 'BLOQUEADA');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;

        CREATE TABLE IF NOT EXISTS assets (
            id          SERIAL PRIMARY KEY,
            ip          VARCHAR(45)  NOT NULL,
            hostname    VARCHAR(255),
            nombre      VARCHAR(255),
            dominio     VARCHAR(255),
            mac_address VARCHAR(17),
            criticidad  criticidadenum  NOT NULL DEFAULT 'PENDIENTE_CLASIFICAR',
            tipo        tipoactivoenum  NOT NULL DEFAULT 'OTRO',
            status      assetstatusenum NOT NULL DEFAULT 'ACTIVO',
            responsable    VARCHAR(255) NOT NULL DEFAULT '',
            departamento   VARCHAR(255),
            ubicacion      VARCHAR(255),
            tags_ens       JSON,
            notas          TEXT,
            vault_path     VARCHAR(500),
            ssh_user       VARCHAR(255),
            ssh_password   VARCHAR(255),
            external_id    VARCHAR(255),
            external_source VARCHAR(50),
            discovered_by  VARCHAR(50),
            network_range  VARCHAR(50),
            os_family      VARCHAR(50),
            os_version     VARCHAR(100),
            created_at     TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at     TIMESTAMP NOT NULL DEFAULT NOW(),
            deleted_at     TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS ix_assets_ip          ON assets (ip);
        CREATE INDEX IF NOT EXISTS ix_assets_hostname     ON assets (hostname);
        CREATE INDEX IF NOT EXISTS ix_assets_status       ON assets (status);
        CREATE INDEX IF NOT EXISTS ix_assets_criticidad   ON assets (criticidad);
        CREATE INDEX IF NOT EXISTS ix_assets_external_id  ON assets (external_id);
    """)


def downgrade():
    op.execute("""
        DROP TABLE IF EXISTS assets;
        DROP TYPE IF EXISTS criticidadenum;
        DROP TYPE IF EXISTS tipoactivoenum;
        DROP TYPE IF EXISTS assetstatusenum;
    """)
