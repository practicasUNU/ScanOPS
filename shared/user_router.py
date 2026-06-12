"""
User and Department management API — admin only.
ENS: op.acc.1, op.acc.4
"""
import os
import urllib.parse
from datetime import datetime
from typing import List, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from shared.auth import (
    _USERS_DB,
    UserInDB,
    get_password_hash,
    require_role,
)

router = APIRouter(prefix="/users", tags=["User Management"])

VALID_ROLES = ["system_manager", "security_officer", "auditor"]


# ── DB connection ─────────────────────────────────────────────────────────────

def _db():
    url = os.getenv("DATABASE_URL", "")
    if url:
        p = urllib.parse.urlparse(url)
        return psycopg2.connect(
            host=p.hostname, port=p.port or 5432,
            database=p.path.lstrip("/"),
            user=p.username, password=p.password,
        )
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=os.getenv("DB_NAME", "scanops"),
        user=os.getenv("DB_USER", "scanops"),
        password=os.getenv("DB_PASSWORD", "scanops"),
    )


# ── Schemas ───────────────────────────────────────────────────────────────────

class DepartmentCreate(BaseModel):
    name: str
    description: Optional[str] = None


class UserCreate(BaseModel):
    username: str
    password: str
    role: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    department_ids: List[int] = []


class UserUpdate(BaseModel):
    role: Optional[str] = None
    full_name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    disabled: Optional[bool] = None
    department_ids: Optional[List[int]] = None


# ── Departments ───────────────────────────────────────────────────────────────

@router.get("/departments")
def list_departments(_: dict = Depends(require_role("system_manager"))):
    conn = _db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM departments ORDER BY name")
            return {"departments": [dict(r) for r in cur.fetchall()]}
    finally:
        conn.close()


@router.post("/departments", status_code=201)
def create_department(body: DepartmentCreate, _: dict = Depends(require_role("system_manager"))):
    conn = _db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "INSERT INTO departments (name, description) VALUES (%s, %s) RETURNING *",
                (body.name.strip(), body.description),
            )
            row = dict(cur.fetchone())
            conn.commit()
            return row
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(409, f"Departamento '{body.name}' ya existe")
    finally:
        conn.close()


@router.delete("/departments/{dept_id}", status_code=204)
def delete_department(dept_id: int, _: dict = Depends(require_role("system_manager"))):
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM departments WHERE id = %s", (dept_id,))
            conn.commit()
    finally:
        conn.close()


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/")
def list_users(_: dict = Depends(require_role("system_manager"))):
    conn = _db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT u.id, u.username, u.role, u.full_name, u.email,
                       u.disabled, u.created_at,
                       COALESCE(
                           json_agg(
                               json_build_object('id', d.id, 'name', d.name)
                           ) FILTER (WHERE d.id IS NOT NULL),
                           '[]'
                       ) AS departments
                FROM scanops_users u
                LEFT JOIN user_departments ud ON ud.user_id = u.id
                LEFT JOIN departments d       ON d.id = ud.department_id
                GROUP BY u.id
                ORDER BY u.created_at
            """)
            users = []
            for row in cur.fetchall():
                r = dict(row)
                if r.get("created_at"):
                    r["created_at"] = r["created_at"].isoformat()
                users.append(r)
            return {"users": users}
    finally:
        conn.close()


@router.post("/", status_code=201)
def create_user(body: UserCreate, _: dict = Depends(require_role("system_manager"))):
    if body.role not in VALID_ROLES:
        raise HTTPException(400, f"Rol inválido. Opciones: {VALID_ROLES}")
    if len(body.password) < 8:
        raise HTTPException(400, "La contraseña debe tener al menos 8 caracteres")

    hashed = get_password_hash(body.password)
    conn = _db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO scanops_users (username, hashed_password, role, full_name, email)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, username, role, full_name, email, disabled, created_at
            """, (body.username.strip(), hashed, body.role, body.full_name, body.email))
            user = dict(cur.fetchone())

            for dept_id in body.department_ids:
                cur.execute(
                    "INSERT INTO user_departments (user_id, department_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (user["id"], dept_id),
                )
            conn.commit()

        # Sync al caché en memoria para que el login funcione inmediatamente
        _USERS_DB[body.username] = UserInDB(
            username=body.username,
            hashed_password=hashed,
            role=body.role,
        )
        if user.get("created_at"):
            user["created_at"] = user["created_at"].isoformat()
        return user
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(409, f"El usuario '{body.username}' ya existe")
    finally:
        conn.close()


@router.put("/{username}")
def update_user(username: str, body: UserUpdate, _: dict = Depends(require_role("system_manager"))):
    if username == "admin" and body.disabled is True:
        raise HTTPException(400, "No se puede deshabilitar la cuenta admin")

    conn = _db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM scanops_users WHERE username = %s", (username,))
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(404, f"Usuario '{username}' no encontrado")

            fields: dict = {}
            if body.role is not None:
                if body.role not in VALID_ROLES:
                    raise HTTPException(400, "Rol inválido")
                fields["role"] = body.role
            if body.full_name is not None:
                fields["full_name"] = body.full_name
            if body.email is not None:
                fields["email"] = body.email
            if body.disabled is not None:
                fields["disabled"] = body.disabled
            if body.password:
                if len(body.password) < 8:
                    raise HTTPException(400, "La contraseña debe tener al menos 8 caracteres")
                fields["hashed_password"] = get_password_hash(body.password)

            if fields:
                fields["updated_at"] = datetime.now()
                set_sql = ", ".join(f"{k} = %s" for k in fields)
                cur.execute(
                    f"UPDATE scanops_users SET {set_sql} WHERE username = %s",
                    [*fields.values(), username],
                )

            if body.department_ids is not None:
                user_id = existing["id"]
                cur.execute("DELETE FROM user_departments WHERE user_id = %s", (user_id,))
                for dept_id in body.department_ids:
                    cur.execute(
                        "INSERT INTO user_departments (user_id, department_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                        (user_id, dept_id),
                    )

            conn.commit()

        # Sync caché
        if username in _USERS_DB:
            u = _USERS_DB[username]
            _USERS_DB[username] = UserInDB(
                username=username,
                hashed_password=fields.get("hashed_password", u.hashed_password),
                role=fields.get("role", u.role),
                disabled=fields.get("disabled", u.disabled),
            )

        return {"message": "Usuario actualizado correctamente"}
    finally:
        conn.close()


@router.delete("/{username}", status_code=204)
def delete_user(username: str, _: dict = Depends(require_role("system_manager"))):
    if username == "admin":
        raise HTTPException(400, "No se puede eliminar la cuenta admin")
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM scanops_users WHERE username = %s", (username,))
            conn.commit()
        _USERS_DB.pop(username, None)
    finally:
        conn.close()
