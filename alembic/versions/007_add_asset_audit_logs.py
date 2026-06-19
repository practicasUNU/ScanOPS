"""add asset_audit_logs table

Revision ID: 007
Revises: 006
Create Date: 2026-06-12
"""
from alembic import op
import sqlalchemy as sa

revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE auditactionenum AS ENUM (
                'CREATE', 'UPDATE', 'DELETE', 'RESTORE', 'CREDENTIAL_ACCESS'
            );
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;

        CREATE TABLE IF NOT EXISTS asset_audit_logs (
            id              SERIAL PRIMARY KEY,
            asset_id        INTEGER NOT NULL REFERENCES assets(id),
            action          auditactionenum NOT NULL,
            user_id         VARCHAR(255) NOT NULL,
            user_role       VARCHAR(100),
            timestamp       TIMESTAMP NOT NULL DEFAULT NOW(),
            changes         JSON,
            snapshot_before JSON,
            snapshot_after  JSON,
            ip_origin       VARCHAR(45),
            reason          TEXT
        );

        CREATE INDEX IF NOT EXISTS ix_asset_audit_logs_asset_id  ON asset_audit_logs (asset_id);
        CREATE INDEX IF NOT EXISTS ix_audit_asset_action          ON asset_audit_logs (asset_id, action);
        CREATE INDEX IF NOT EXISTS ix_audit_user                  ON asset_audit_logs (user_id);
        CREATE INDEX IF NOT EXISTS ix_asset_audit_logs_timestamp  ON asset_audit_logs (timestamp);
    """)


def downgrade():
    op.execute("""
        DROP TABLE IF EXISTS asset_audit_logs;
        DROP TYPE IF EXISTS auditactionenum;
    """)
