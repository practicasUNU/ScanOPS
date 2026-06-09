"""
Shared authentication utilities for ScanOPS services.
ENS Alto: op.acc.1, op.acc.4, op.acc.5
"""

import collections as _collections
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt as _bcrypt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

logger = logging.getLogger("scanops.auth")

_LOGIN_BUFFER: _collections.deque = _collections.deque(maxlen=500)


def record_login_event(
    username: str,
    role: str,
    success: bool,
    ip_origin: str | None = None,
    user_agent: str | None = None,
    reason: str | None = None,
) -> None:
    from datetime import datetime, timezone
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "role": role if success else None,
        "success": success,
        "ip_origin": ip_origin,
        "user_agent": user_agent,
        "reason": reason,
    }
    _LOGIN_BUFFER.appendleft(event)


def get_login_events(limit: int = 100) -> list[dict]:
    return list(_LOGIN_BUFFER)[:limit]

# --- Config ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_32_CHARS_MIN")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_EXPIRE_MINUTES", "480"))  # 8h
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_EXPIRE_DAYS", "7"))

VALID_ROLES = {"system_manager", "security_officer", "auditor", "service"}

security = HTTPBearer(auto_error=False)


# --- Models ---
class TokenData(BaseModel):
    sub: str
    role: str
    exp: Optional[int] = None
    token_type: str = "access"


class UserInDB(BaseModel):
    username: str
    hashed_password: str
    role: str
    disabled: bool = False


# --- Static users for MVP ---
# Passwords (plaintext for reference — stored bcrypt-hashed):
#   admin            → scanops_admin_2026
#   resp_seguridad   → scanops_sec_2026
#   auditor          → scanops_audit_2026
#   scanops_service  → scanops_secret
# TODO: replace with DB-backed user store (ENS op.acc.1)
_USERS_DB: dict[str, UserInDB] = {}


def _init_users() -> None:
    import json
    users_json = os.getenv("JWT_USERS")
    if users_json:
        try:
            raw = json.loads(users_json)
            for u in raw:
                _USERS_DB[u["username"]] = UserInDB(**u)
            return
        except Exception as e:
            logger.warning(f"JWT_USERS parse error: {e}")

    defaults = [
        ("admin", "scanops_admin_2026", "system_manager"),
        ("resp_seguridad", "scanops_sec_2026", "security_officer"),
        ("auditor", "scanops_audit_2026", "auditor"),
        ("scanops_service", "scanops_secret", "service"),
    ]
    for username, password, role in defaults:
        _USERS_DB[username] = UserInDB(
            username=username,
            hashed_password=_bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode(),
            role=role,
        )


_init_users()


# --- Core functions ---
def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


def get_password_hash(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()


def get_user(username: str) -> Optional[UserInDB]:
    return _USERS_DB.get(username)


def authenticate_user(username: str, password: str, ip_origin: str | None = None, user_agent: str | None = None) -> Optional[UserInDB]:
    """Validates username + password. Returns UserInDB or None. ENS op.acc.5"""
    user = get_user(username)
    if not user or user.disabled:
        record_login_event(username, "", False, ip_origin, user_agent, "Usuario no existe o deshabilitado")
        logger.warning(f"[ENS_EVIDENCE] Failed login attempt for user: {username}")
        return None
    if not verify_password(password, user.hashed_password):
        record_login_event(username, "", False, ip_origin, user_agent, "Contraseña incorrecta")
        logger.warning(f"[ENS_EVIDENCE] Failed login attempt for user: {username}")
        return None
    record_login_event(username, user.role, True, ip_origin, user_agent)
    logger.info(f"[ENS_EVIDENCE] Successful authentication: {username} (role: {user.role})")
    return user


def create_access_token(username: str, role: str) -> str:
    """Creates a signed JWT access token. ENS op.acc.5"""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "token_type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(username: str, role: str) -> str:
    """Creates a signed JWT refresh token with longer expiry."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "token_type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> TokenData:
    """Decodes and validates a JWT token. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role", "service")
        token_type: str = payload.get("token_type", "access")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token: missing subject")
        if role not in VALID_ROLES:
            raise HTTPException(status_code=403, detail=f"Invalid role: {role}")
        return TokenData(sub=username, role=role, token_type=token_type)
    except JWTError as e:
        logger.warning(f"[ENS_EVIDENCE] JWT validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )


# --- FastAPI dependencies ---
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> dict:
    """
    FastAPI dependency. Drop-in replacement for the old API-key stub.
    Returns dict with 'user' and 'role' keys — same shape as before.
    ENS: op.acc.5
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Unauthorized — Bearer token required")
    token_data = decode_token(credentials.credentials)
    if token_data.token_type != "access":
        raise HTTPException(status_code=401, detail="Refresh token not valid for API access")
    user = get_user(token_data.sub)
    if user and user.disabled:
        raise HTTPException(status_code=403, detail="User account disabled")
    logger.info(f"[ENS_EVIDENCE] API access: {token_data.sub} (role: {token_data.role})")
    return {"user": token_data.sub, "role": token_data.role}


def require_role(*roles: str):
    """
    FastAPI dependency factory for role-based access control.
    Usage: Depends(require_role("system_manager", "security_officer"))
    The 'service' role bypasses all role checks for backward compatibility.
    ENS: op.acc.4
    """
    def _check(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user["role"] != "service" and current_user["role"] not in roles:
            logger.warning(
                f"[ENS_EVIDENCE] Unauthorized access attempt: {current_user['user']} "
                f"(role: {current_user['role']}) tried to access endpoint requiring {roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acceso denegado — rol requerido: {', '.join(roles)}",
            )
        return current_user
    return _check
