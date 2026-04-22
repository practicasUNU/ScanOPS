"""Shared authentication utilities for ScanOPS services."""

import os
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer(auto_error=False)

class AuthService:
    """Stub authentication service for shared ScanOPS logic."""

    def __init__(self):
        self._api_key = os.getenv("SCANOPS_API_KEY", "scanops_secret")

    def validate_token(self, credentials: HTTPAuthorizationCredentials | None):
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Unauthorized")
        if credentials.credentials != self._api_key:
            raise HTTPException(status_code=403, detail="Forbidden")
        return {"user": "scanops_service", "role": "service"}


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    auth = AuthService()
    return auth.validate_token(credentials)
