"""Asset Manager migration - Create asset tables

Revision ID: 002_asset_manager
Revises: 001_initial
Create Date: 2026-04-21 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '002_asset_manager'
down_revision = '001_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enums
    criticidad_enum = sa.Enum('BAJA', 'MEDIA', 'ALTA', 'PENDIENTE_CLASIFICAR', name='criticidadenum')
    tipo_activo_enum = sa.Enum('ENDPOINT', 'SERVER', 'RED', 'APLICACION', 'IOT', 'OTRO', name='tipoactivoenum')
    asset_status_enum = sa.Enum('ACTIVO', 'BAJA', 'MANTENIMIENTO', 'PENDIENTE_ALTA', name='assetstatusenum')
    audit_action_enum = sa.Enum('CREATE', 'UPDATE', 'DELETE', 'RESTORE', 'CREDENTIAL_ACCESS', name='auditactionenum')

    criticidad_enum.create(op.get_bind(), checkfirst=True)
    tipo_activo_enum.create(op.get_bind(), checkfirst=True)
    asset_status_enum.create(op.get_bind(), checkfirst=True)
    audit_action_enum.create(op.get_bind(), checkfirst=True)

    # Create assets table
    op.create_table('assets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('dominio', sa.String(length=255), nullable=True),
        sa.Column('mac_address', sa.String(length=17), nullable=True),
        sa.Column('criticidad', criticidad_enum, nullable=False),
        sa.Column('tipo', tipo_activo_enum, nullable=False),
        sa.Column('status', asset_status_enum, nullable=False),
        sa.Column('responsable', sa.String(length=255), nullable=False),
        sa.Column('departamento', sa.String(length=255), nullable=True),
        sa.Column('ubicacion', sa.String(length=255), nullable=True),
        sa.Column('tags_ens', sa.JSON(), nullable=True),
        sa.Column('notas', sa.Text(), nullable=True),
        sa.Column('vault_path', sa.String(length=500), nullable=True),
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('external_source', sa.String(length=50), nullable=True),
        sa.Column('discovered_by', sa.String(length=50), nullable=True),
        sa.Column('network_range', sa.String(length=50), nullable=True),
        sa.Column('os_family', sa.String(length=50), nullable=True),
        sa.Column('os_version', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.Index('ix_assets_ip', 'ip'),
        sa.Index('ix_assets_hostname', 'hostname'),
        sa.Index('ix_assets_criticidad', 'criticidad'),
        sa.Index('ix_assets_tipo', 'tipo'),
        sa.Index('ix_assets_status', 'status'),
        sa.Index('ix_assets_external_id', 'external_id'),
        sa.Index('ix_assets_ip_status', 'ip', 'status'),
        sa.Index('ix_assets_criticidad_tipo', 'criticidad', 'tipo'),
        sa.Index('ix_assets_external', 'external_source', 'external_id')
    )

    # Create asset_audit_logs table
    op.create_table('asset_audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('action', audit_action_enum, nullable=False),
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('user_role', sa.String(length=100), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('changes', sa.JSON(), nullable=True),
        sa.Column('snapshot_before', sa.JSON(), nullable=True),
        sa.Column('snapshot_after', sa.JSON(), nullable=True),
        sa.Column('ip_origin', sa.String(length=45), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.Index('ix_audit_asset_id', 'asset_id'),
        sa.Index('ix_audit_timestamp', 'timestamp'),
        sa.Index('ix_audit_asset_action', 'asset_id', 'action'),
        sa.Index('ix_audit_user', 'user_id')
    )


def downgrade() -> None:
    # Drop tables
    op.drop_table('asset_audit_logs')
    op.drop_table('assets')

    # Drop enums
    op.execute("DROP TYPE IF EXISTS criticidadenum")
    op.execute("DROP TYPE IF EXISTS tipoactivoenum")
    op.execute("DROP TYPE IF EXISTS assetstatusenum")
    op.execute("DROP TYPE IF EXISTS auditactionenum")
