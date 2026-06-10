"""add dedup unique index on vuln_findings

Revision ID: 006
Revises: 005
Create Date: 2026-06-10
"""
from alembic import op
import sqlalchemy as sa

revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    # Eliminar duplicados existentes, conservando el más reciente por grupo
    conn.execute(sa.text("""
        DELETE FROM vuln_findings
        WHERE id IN (
            SELECT id FROM (
                SELECT id,
                       ROW_NUMBER() OVER (
                           PARTITION BY asset_id,
                                        vulnerability_id,
                                        scanner_name,
                                        COALESCE(affected_port, -1)
                           ORDER BY created_at DESC
                       ) AS rn
                FROM vuln_findings
            ) ranked
            WHERE rn > 1
        )
    """))

    # Índice funcional único — ON CONFLICT lo necesita para resolver por clave natural
    conn.execute(sa.text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uix_vuln_findings_dedup
        ON vuln_findings (
            asset_id,
            vulnerability_id,
            scanner_name,
            COALESCE(affected_port, -1)
        )
    """))


def downgrade():
    op.drop_index('uix_vuln_findings_dedup', table_name='vuln_findings')
