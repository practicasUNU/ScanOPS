"""add users and departments tables

Revision ID: 010
Revises: 009
Create Date: 2026-06-12
"""
from alembic import op
import bcrypt

revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None

_DEFAULTS = [
    ("admin",           "scanops_admin_2026", "system_manager",   "Administrador ScanOPS",  "admin@scanops.local"),
    ("resp_seguridad",  "scanops_sec_2026",   "security_officer", "Responsable Seguridad",   "sec@scanops.local"),
    ("auditor",         "scanops_audit_2026", "auditor",          "Auditor ENS",             "auditor@scanops.local"),
]


def _hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            id          SERIAL PRIMARY KEY,
            name        VARCHAR(100) NOT NULL UNIQUE,
            description TEXT,
            created_at  TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS scanops_users (
            id              SERIAL  PRIMARY KEY,
            username        VARCHAR(100)  NOT NULL UNIQUE,
            hashed_password VARCHAR(255)  NOT NULL,
            role            VARCHAR(50)   NOT NULL DEFAULT 'auditor',
            full_name       VARCHAR(255),
            email           VARCHAR(255),
            disabled        BOOLEAN       DEFAULT FALSE,
            created_at      TIMESTAMP     DEFAULT NOW(),
            updated_at      TIMESTAMP     DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS user_departments (
            user_id       INTEGER NOT NULL REFERENCES scanops_users(id) ON DELETE CASCADE,
            department_id INTEGER NOT NULL REFERENCES departments(id)   ON DELETE CASCADE,
            PRIMARY KEY (user_id, department_id)
        );

        INSERT INTO departments (name, description) VALUES
            ('Seguridad',  'Equipo de ciberseguridad'),
            ('Sistemas',   'Administración de sistemas'),
            ('Auditoría',  'Auditoría interna ENS'),
            ('Servicios',  'Cuentas de servicio interno')
        ON CONFLICT (name) DO NOTHING;
    """)

    for username, password, role, full_name, email in _DEFAULTS:
        hashed = _hash(password)
        op.execute(f"""
            INSERT INTO scanops_users (username, hashed_password, role, full_name, email)
            VALUES ('{username}', '{hashed}', '{role}', '{full_name}', '{email}')
            ON CONFLICT (username) DO NOTHING;
        """)


def downgrade():
    op.execute("""
        DROP TABLE IF EXISTS user_departments;
        DROP TABLE IF EXISTS scanops_users;
        DROP TABLE IF EXISTS departments;
    """)
