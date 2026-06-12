"""add execution_result and executed_at to m4_approvals

Revision ID: 009
Revises: 008
Create Date: 2026-06-12
"""
from alembic import op
import sqlalchemy as sa

revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE m4_approvals
            ADD COLUMN IF NOT EXISTS execution_result JSONB,
            ADD COLUMN IF NOT EXISTS executed_at      TIMESTAMP;
    """)


def downgrade():
    op.execute("""
        ALTER TABLE m4_approvals
            DROP COLUMN IF EXISTS execution_result,
            DROP COLUMN IF EXISTS executed_at;
    """)
