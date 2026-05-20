"""fix ip partial index for soft deletes

Revision ID: 003
Revises: 002
Create Date: 2026-05-19 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None

def upgrade():
    # 1. Eliminar la constraint de unicidad estricta (si existe)
    op.execute("ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_ip_key;")
    
    # 2. Eliminar el índice clásico (si existe)
    op.execute("DROP INDEX IF EXISTS ix_assets_ip;")
    
    # 3. Crear el nuevo índice parcial único (Solo aplica a activos NO borrados)
    # ENS Alto op.exp.1: Permite mantener el historial inmutable de activos borrados
    op.execute("CREATE UNIQUE INDEX ix_assets_ip ON assets (ip) WHERE deleted_at IS NULL;")

def downgrade():
    # Revertir los cambios (por si necesitas hacer rollback)
    op.execute("DROP INDEX IF EXISTS ix_assets_ip;")
    op.execute("CREATE INDEX ix_assets_ip ON assets (ip);")
    op.execute("ALTER TABLE assets ADD CONSTRAINT assets_ip_key UNIQUE (ip);")