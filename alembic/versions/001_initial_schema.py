"""initial schema

Revision ID: 001
Revises: 
Create Date: 2026-04-28 14:15:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # 1. Crear tipos ENUM (ENS Alto: Consistencia de datos)
    conn = op.get_bind()
    
    # Check if types exist
    for type_name, values in [
        ('criticidadenum', ('BAJA', 'MEDIA', 'ALTA', 'PENDIENTE_CLASIFICAR')),
        ('tipoactivoenum', ('ENDPOINT', 'SERVER', 'RED', 'APLICACION', 'IOT', 'OTRO')),
        ('assetstatusenum', ('ACTIVO', 'BAJA', 'MANTENIMIENTO', 'PENDIENTE_ALTA'))
    ]:
        exists = conn.execute(sa.text(f"SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = '{type_name}')")).scalar()
        if not exists:
            op.execute(f"CREATE TYPE {type_name} AS ENUM {values}")

    # 2. Crear tabla 'assets'
    op.create_table(
        'assets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        
        # Identidad
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('dominio', sa.String(length=255), nullable=True),
        sa.Column('mac_address', sa.String(length=17), nullable=True),
        
        # Clasificación
        sa.Column('criticidad', sa.Enum('BAJA', 'MEDIA', 'ALTA', 'PENDIENTE_CLASIFICAR', name='criticidadenum'), nullable=False, server_default='PENDIENTE_CLASIFICAR'),
        sa.Column('tipo', sa.Enum('ENDPOINT', 'SERVER', 'RED', 'APLICACION', 'IOT', 'OTRO', name='tipoactivoenum'), nullable=False, server_default='OTRO'),
        sa.Column('status', sa.Enum('ACTIVO', 'BAJA', 'MANTENIMIENTO', 'PENDIENTE_ALTA', name='assetstatusenum'), nullable=False, server_default='ACTIVO'),
        
        # Propiedad
        sa.Column('responsable', sa.String(length=255), nullable=False),
        sa.Column('departamento', sa.String(length=255), nullable=True),
        sa.Column('ubicacion', sa.String(length=255), nullable=True),
        
        # Tags y Notas
        sa.Column('tags_ens', sa.JSON(), nullable=True),
        sa.Column('notas', sa.Text(), nullable=True),
        
        # Integración Vault
        sa.Column('vault_path', sa.String(length=500), nullable=True),
        
        # Sincronización Externa
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('external_source', sa.String(length=50), nullable=True),
        
        # Descubrimiento
        sa.Column('discovered_by', sa.String(length=50), nullable=True),
        sa.Column('network_range', sa.String(length=50), nullable=True),
        
        # Sistema Operativo
        sa.Column('os_family', sa.String(length=50), nullable=True),
        sa.Column('os_version', sa.String(length=100), nullable=True),
        
        # Timestamps
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # 3. Crear índices (ENS Alto: Performance y trazabilidad)
    op.create_index('ix_assets_ip', 'assets', ['ip'], unique=False)
    op.create_index('ix_assets_hostname', 'assets', ['hostname'], unique=False)
    op.create_index('ix_assets_status', 'assets', ['status'], unique=False)
    op.create_index('ix_assets_criticidad', 'assets', ['criticidad'], unique=False)
    op.create_index('ix_assets_external_id', 'assets', ['external_id'], unique=False)

def downgrade():
    op.drop_table('assets')
    op.execute("DROP TYPE IF EXISTS criticidadenum")
    op.execute("DROP TYPE IF EXISTS tipoactivoenum")
    op.execute("DROP TYPE IF EXISTS assetstatusenum")
