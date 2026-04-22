"""Initial migration - Create recon tables

Revision ID: 001_initial
Revises:
Create Date: 2026-04-20 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create recon_snapshots table
    op.create_table('recon_snapshots',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('cycle_id', sa.String(length=50), nullable=False),
        sa.Column('target', sa.String(length=255), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.Index('ix_recon_snapshots_cycle_id', 'cycle_id'),
        sa.Index('ix_recon_snapshots_status', 'status')
    )

    # Create recon_findings table
    op.create_table('recon_findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('snapshot_id', sa.Integer(), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('port', sa.String(length=20), nullable=True),
        sa.Column('service', sa.String(length=100), nullable=True),
        sa.Column('version', sa.String(length=255), nullable=True),
        sa.Column('state', sa.String(length=20), nullable=True),
        sa.Column('source', sa.String(length=20), nullable=True),
        sa.Column('first_seen_snapshot_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['first_seen_snapshot_id'], ['recon_snapshots.id'], ),
        sa.ForeignKeyConstraint(['snapshot_id'], ['recon_snapshots.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.Index('ix_recon_findings_snapshot_id', 'snapshot_id'),
        sa.Index('ix_recon_findings_host', 'host')
    )

    # Create recon_subdomains table
    op.create_table('recon_subdomains',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('snapshot_id', sa.Integer(), nullable=False),
        sa.Column('subdomain', sa.String(length=255), nullable=False),
        sa.Column('source', sa.String(length=20), nullable=True),
        sa.ForeignKeyConstraint(['snapshot_id'], ['recon_snapshots.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.Index('ix_recon_subdomains_snapshot_id', 'snapshot_id'),
        sa.Index('ix_recon_subdomains_subdomain', 'subdomain')
    )


def downgrade() -> None:
    op.drop_table('recon_subdomains')
    op.drop_table('recon_findings')
    op.drop_table('recon_snapshots')