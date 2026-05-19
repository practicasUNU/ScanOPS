import { Shield, Lock, Key, AlertCircle, User } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { useAuth } from '../../hooks/useAuth';

export function LoginPage() {
  const navigate = useNavigate();
  const { login, loading, error } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  // TODO: validate TOTP server-side when MFA endpoint is implemented (ENS op.acc.5)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await login(username, password);
      navigate('/dashboard');
    } catch {
      // error is set by useAuth
    }
  };

  return (
    <div className="min-h-screen bg-[#0f1117] flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-[#00d4ff] to-[#0099cc] rounded-2xl mb-4">
            <Shield className="w-9 h-9 text-[#0f1117]" />
          </div>
          <h1 className="text-3xl font-semibold text-white mb-2">ScanOps</h1>
          <p className="text-[#9ca3af]">Penetration Testing & ENS Alto Compliance</p>
        </div>

        <div className="bg-[#1a1d27] border border-[#1e2530] rounded-lg p-8">
          <form onSubmit={handleLogin} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
                Usuario
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#9ca3af]" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-10 pr-4 py-2.5 text-white placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] focus:ring-1 focus:ring-[#00d4ff] transition-colors"
                  placeholder="admin"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#9ca3af]" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-10 pr-4 py-2.5 text-white placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] focus:ring-1 focus:ring-[#00d4ff] transition-colors"
                  placeholder="••••••••••"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
                TOTP Code
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#9ca3af]" />
                <input
                  type="text"
                  value={totp}
                  onChange={(e) => setTotp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full bg-[#0f1117] border border-[#1e2530] rounded-lg pl-10 pr-4 py-2.5 text-white placeholder:text-[#6b7280] focus:outline-none focus:border-[#00d4ff] focus:ring-1 focus:ring-[#00d4ff] transition-colors font-mono tracking-widest"
                  placeholder="000000"
                  maxLength={6}
                />
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 rounded-lg px-3 py-2.5 text-sm text-[#ff3b3b]">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-[#00d4ff] hover:bg-[#00b8e6] disabled:opacity-60 disabled:cursor-not-allowed text-[#0f1117] font-semibold py-2.5 rounded-lg transition-colors shadow-lg shadow-[#00d4ff]/20"
            >
              {loading ? 'Verificando...' : 'Acceder'}
            </button>

            <div className="text-center">
              <button type="button" className="text-sm text-[#00d4ff] hover:text-[#00b8e6] transition-colors">
                Use FIDO2 key instead
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
