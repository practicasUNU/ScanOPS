"""add M2 recon tables

Revision ID: 008
Revises: 007
Create Date: 2026-06-12
"""
from alembic import op
import sqlalchemy as sa

revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS recon_snapshots (
            id            SERIAL PRIMARY KEY,
            cycle_id      VARCHAR(50)  NOT NULL,
            target        VARCHAR(255) NOT NULL,
            started_at    TIMESTAMP    NOT NULL DEFAULT NOW(),
            finished_at   TIMESTAMP,
            status        VARCHAR(20)  DEFAULT 'running',
            os_family     VARCHAR(100),
            os_version    VARCHAR(255),
            os_cpe        VARCHAR(255),
            os_confidence FLOAT,
            mac_address   VARCHAR(50),
            mac_vendor    VARCHAR(255),
            latency_ms    FLOAT,
            webcheck_data JSON
        );

        CREATE INDEX IF NOT EXISTS ix_recon_snapshots_cycle_id ON recon_snapshots (cycle_id);
        CREATE INDEX IF NOT EXISTS ix_recon_snapshots_target   ON recon_snapshots (target);

        CREATE TABLE IF NOT EXISTS recon_findings (
            id                   SERIAL PRIMARY KEY,
            snapshot_id          INTEGER NOT NULL REFERENCES recon_snapshots(id) ON DELETE CASCADE,
            host                 VARCHAR(255) NOT NULL,
            port                 VARCHAR(20),
            service              VARCHAR(100),
            version              VARCHAR(255),
            state                VARCHAR(20),
            source               VARCHAR(20),
            first_seen_snapshot_id INTEGER REFERENCES recon_snapshots(id)
        );

        CREATE INDEX IF NOT EXISTS ix_recon_findings_snapshot_id ON recon_findings (snapshot_id);
        CREATE INDEX IF NOT EXISTS ix_recon_findings_host        ON recon_findings (host);

        CREATE TABLE IF NOT EXISTS recon_subdomains (
            id          SERIAL PRIMARY KEY,
            snapshot_id INTEGER NOT NULL REFERENCES recon_snapshots(id) ON DELETE CASCADE,
            subdomain   VARCHAR(255) NOT NULL,
            source      VARCHAR(20) DEFAULT 'subfinder'
        );

        CREATE INDEX IF NOT EXISTS ix_recon_subdomains_snapshot_id ON recon_subdomains (snapshot_id);
        CREATE INDEX IF NOT EXISTS ix_recon_subdomains_subdomain   ON recon_subdomains (subdomain);
    """)


def downgrade():
    op.execute("""
        DROP TABLE IF EXISTS recon_subdomains;
        DROP TABLE IF EXISTS recon_findings;
        DROP TABLE IF EXISTS recon_snapshots;
    """)
