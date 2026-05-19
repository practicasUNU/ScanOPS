import { Navigate } from 'react-router';
import { getStoredToken } from '../../hooks/useAuth';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string[];
}

export function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps) {
  const token = getStoredToken();

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole) {
    const role = (() => {
      try {
        const raw = sessionStorage.getItem('scanops_auth');
        return raw ? JSON.parse(raw).role : null;
      } catch { return null; }
    })();
    if (!role || !requiredRole.includes(role)) {
      return <Navigate to="/dashboard" replace />;
    }
  }

  return <>{children}</>;
}
