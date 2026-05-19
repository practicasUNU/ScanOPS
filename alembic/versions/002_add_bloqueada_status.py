# Comandos para aplicar:
#   docker compose stop m1
#   docker compose build m1 --no-cache
#   docker compose up m1 -d
#   # Si M1 no aplica la migración automáticamente al arrancar:
#   docker exec scanops-m1 alembic -c alembic/alembic.ini upgrade head

"""add BLOQUEADA to assetstatusenum

Revision ID: 002
Revises: 001
Create Date: 2026-05-19 10:00:00.000000
"""
from alembic import op

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TYPE assetstatusenum ADD VALUE IF NOT EXISTS 'BLOQUEADA'")


def downgrade():
    # PostgreSQL no permite eliminar valores de un enum directamente
    # Se requiere recrear el tipo — omitido por complejidad
    pass
