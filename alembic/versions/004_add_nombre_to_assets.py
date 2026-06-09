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
    op.add_column('assets', sa.Column('nombre', sa.String(255), nullable=True))


def downgrade():
    op.drop_column('assets', 'nombre')
