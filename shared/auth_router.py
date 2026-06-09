"""
Auth router — provides /auth/token, /auth/refresh, and /auth/me endpoints.
Include this router in any service that needs user login.
ENS: op.acc.1, op.acc.5
"""

from fastapi import APIRouter, HTTPException, Depends, Security, Request
from fastapi.security import OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from shared.auth import (
    authenticate_user,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_user,
    get_login_events,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    require_role,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
_security = HTTPBearer(auto_error=False)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    expires_in: int  # seconds


@router.post("/token", response_model=TokenResponse)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 password flow login.
    Returns access + refresh tokens.
    ENS: op.acc.5
    """
    ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else None)
    ua = request.headers.get("User-Agent")
    user = authenticate_user(form_data.username, form_data.password, ip_origin=ip, user_agent=ua)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    return TokenResponse(
        access_token=create_access_token(user.username, user.role),
        refresh_token=create_refresh_token(user.username, user.role),
        role=user.role,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Security(_security)):
    """Exchanges a valid refresh token for a new access + refresh token pair."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Refresh token required")
    token_data = decode_token(credentials.credentials)
    if token_data.token_type != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")
    return TokenResponse(
        access_token=create_access_token(token_data.sub, token_data.role),
        refresh_token=create_refresh_token(token_data.sub, token_data.role),
        role=token_data.role,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me")
async def get_me(credentials: HTTPAuthorizationCredentials = Security(_security)):
    """Returns current user info from access token."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Bearer token required")
    token_data = decode_token(credentials.credentials)
    user = get_user(token_data.sub)
    return {
        "username": token_data.sub,
        "role": token_data.role,
        "disabled": user.disabled if user else False,
    }


@router.get("/login-events")
async def get_login_events_endpoint(
    limit: int = 100,
    current_user: dict = Depends(require_role("system_manager", "auditor")),
):
    """Historial de eventos de inicio de sesión. ENS: op.acc.1, op.exp.5"""
    events = get_login_events(limit=min(limit, 500))
    return {"total": len(events), "events": events}
