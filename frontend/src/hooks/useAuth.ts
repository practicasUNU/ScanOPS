import { useState, useCallback } from 'react';
import { API_BASE } from '../config/api';

export interface AuthUser {
  username: string;
  role: 'system_manager' | 'security_officer' | 'auditor' | 'service';
  access_token: string;
  refresh_token: string;
  expires_at: number; // Unix timestamp ms
}

const TOKEN_KEY = 'scanops_auth';

function saveAuth(auth: AuthUser) {
  sessionStorage.setItem(TOKEN_KEY, JSON.stringify(auth));
}

function loadAuth(): AuthUser | null {
  try {
    const raw = sessionStorage.getItem(TOKEN_KEY);
    if (!raw) return null;
    const auth = JSON.parse(raw) as AuthUser;
    if (Date.now() > auth.expires_at) {
      sessionStorage.removeItem(TOKEN_KEY);
      return null;
    }
    return auth;
  } catch {
    return null;
  }
}

export function useAuth() {
  const [user, setUser] = useState<AuthUser | null>(loadAuth);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const login = useCallback(async (username: string, password: string): Promise<AuthUser> => {
    /**
     * POST /auth/token with OAuth2 form data.
     * Stores tokens in sessionStorage (not localStorage — ENS mp.info.3).
     * Returns AuthUser on success, throws on failure.
     */
    setLoading(true);
    setError(null);
    try {
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);

      const response = await fetch(`${API_BASE}/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString(),
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail ?? `Error ${response.status}`);
      }

      const data = await response.json();
      const auth: AuthUser = {
        username,
        role: data.role,
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_at: Date.now() + data.expires_in * 1000,
      };
      saveAuth(auth);
      setUser(auth);
      return auth;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Error de conexión';
      setError(msg);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    sessionStorage.removeItem(TOKEN_KEY);
    setUser(null);
  }, []);

  const getToken = useCallback((): string | null => {
    const auth = loadAuth();
    return auth?.access_token ?? null;
  }, []);

  return { user, loading, error, login, logout, getToken };
}

// Standalone helper for use outside React components (hooks, fetch calls)
export function getStoredToken(): string | null {
  try {
    const raw = sessionStorage.getItem(TOKEN_KEY);
    if (!raw) return null;
    const auth = JSON.parse(raw) as AuthUser;
    if (Date.now() > auth.expires_at) return null;
    return auth.access_token;
  } catch {
    return null;
  }
}

export function getStoredRole(): string | null {
  try {
    const raw = sessionStorage.getItem(TOKEN_KEY);
    if (!raw) return null;
    return (JSON.parse(raw) as AuthUser).role;
  } catch {
    return null;
  }
}
