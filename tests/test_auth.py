"""Tests for shared/auth.py — ENS op.acc.5"""
import pytest
from fastapi import HTTPException
from jose import jwt

from shared.auth import (
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    authenticate_user,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    get_password_hash,
    require_role,
    verify_password,
)


# --- Password hashing ---

def test_password_hash_and_verify():
    hashed = get_password_hash("test_password")
    assert verify_password("test_password", hashed)
    assert not verify_password("wrong_password", hashed)


# --- authenticate_user ---

def test_authenticate_user_valid():
    user = authenticate_user("admin", "scanops_admin_2026")
    assert user is not None
    assert user.role == "system_manager"


def test_authenticate_user_security_officer():
    user = authenticate_user("resp_seguridad", "scanops_sec_2026")
    assert user is not None
    assert user.role == "security_officer"


def test_authenticate_user_auditor():
    user = authenticate_user("auditor", "scanops_audit_2026")
    assert user is not None
    assert user.role == "auditor"


def test_authenticate_user_wrong_password():
    assert authenticate_user("admin", "wrong_password") is None


def test_authenticate_user_nonexistent():
    assert authenticate_user("nobody", "any") is None


# --- JWT creation and decoding ---

def test_create_and_decode_access_token():
    token = create_access_token("admin", "system_manager")
    data = decode_token(token)
    assert data.sub == "admin"
    assert data.role == "system_manager"
    assert data.token_type == "access"


def test_create_and_decode_refresh_token():
    token = create_refresh_token("admin", "system_manager")
    data = decode_token(token)
    assert data.sub == "admin"
    assert data.role == "system_manager"
    assert data.token_type == "refresh"


def test_expired_token_raises_401():
    from datetime import datetime, timezone, timedelta
    payload = {
        "sub": "admin",
        "role": "system_manager",
        "token_type": "access",
        "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
    }
    expired_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    with pytest.raises(HTTPException) as exc:
        decode_token(expired_token)
    assert exc.value.status_code == 401


def test_tampered_token_raises_401():
    token = create_access_token("admin", "system_manager")
    with pytest.raises(HTTPException) as exc:
        decode_token(token + "tampered")
    assert exc.value.status_code == 401


def test_invalid_role_in_token_raises_403():
    payload = {
        "sub": "admin",
        "role": "superuser",  # not in VALID_ROLES
        "token_type": "access",
    }
    from datetime import datetime, timezone, timedelta
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=1)
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    with pytest.raises(HTTPException) as exc:
        decode_token(token)
    assert exc.value.status_code == 403


# --- require_role ---

def test_require_role_allows_correct_role():
    checker = require_role("system_manager")
    result = checker({"user": "admin", "role": "system_manager"})
    assert result["role"] == "system_manager"


def test_require_role_allows_multiple_roles():
    checker = require_role("system_manager", "security_officer")
    result = checker({"user": "resp_seguridad", "role": "security_officer"})
    assert result["role"] == "security_officer"


def test_require_role_blocks_wrong_role():
    checker = require_role("system_manager")
    with pytest.raises(HTTPException) as exc:
        checker({"user": "auditor", "role": "auditor"})
    assert exc.value.status_code == 403


def test_require_role_blocks_security_officer_from_manager_only():
    checker = require_role("system_manager")
    with pytest.raises(HTTPException) as exc:
        checker({"user": "resp_seguridad", "role": "security_officer"})
    assert exc.value.status_code == 403


def test_service_role_bypasses_all_checks():
    checker = require_role("system_manager")
    result = checker({"user": "scanops_service", "role": "service"})
    assert result["role"] == "service"


def test_service_role_bypasses_security_officer_check():
    checker = require_role("security_officer")
    result = checker({"user": "scanops_service", "role": "service"})
    assert result["role"] == "service"
