"""add nombre to assets

Revision ID: 004
Revises: 003
Create Date: 2026-05-21
"""
from alembic import op
import sqlalchemy as sa

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE assets ADD COLUMN nombre VARCHAR(255);
        EXCEPTION WHEN duplicate_column THEN NULL;
        END $$;
    """)


def downgrade():
    op.drop_column('assets', 'nombre')
