import { useEffect } from 'react';
import { useNavigate } from 'react-router';
import { AlertTriangle, X } from 'lucide-react';
import type { CriticalAlert } from '../../hooks/useCriticalAlerts';

interface Props {
  toasts: CriticalAlert[];
  onDismiss: (id: string) => void;
}

const AUTO_DISMISS_MS = 8000;

export function CriticalToast({ toasts, onDismiss }: Props) {
  const navigate = useNavigate();

  // Auto-dismiss el toast más reciente tras 8s
  useEffect(() => {
    if (toasts.length === 0) return;
    const latest = toasts[toasts.length - 1];
    const timer = setTimeout(() => onDismiss(latest.id), AUTO_DISMISS_MS);
    return () => clearTimeout(timer);
  }, [toasts, onDismiss]);

  if (toasts.length === 0) return null;

  const toast = toasts[toasts.length - 1];

  return (
    <div className="fixed bottom-6 right-6 z-[9999] w-80">
      <div className="bg-[#111318] border border-[#ff3b3b]/50 rounded-xl shadow-2xl overflow-hidden">
        {/* Barra roja superior */}
        <div className="h-1 bg-gradient-to-r from-[#ff3b3b] to-[#ff6b6b]" />

        <div className="p-4">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 bg-[#ff3b3b]/15 rounded-lg flex items-center justify-center shrink-0 mt-0.5">
              <AlertTriangle className="w-4 h-4 text-[#ff3b3b]" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[10px] font-bold text-[#ff3b3b] uppercase tracking-wider">
                  CRITICAL
                </span>
                <span className="text-[9px] text-[#334155] font-mono">
                  {new Date(toast.timestamp).toLocaleTimeString('es-ES', {
                    hour: '2-digit', minute: '2-digit',
                  })}
                </span>
              </div>
              <p className="text-xs font-semibold text-white truncate">{toast.title}</p>
              <p className="text-[10px] text-[#64748B] mt-0.5 line-clamp-2">{toast.message}</p>
            </div>
            <button
              onClick={() => onDismiss(toast.id)}
              className="text-[#334155] hover:text-white transition-colors cursor-pointer shrink-0"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="flex items-center gap-2 mt-3">
            <button
              onClick={() => { navigate(toast.link); onDismiss(toast.id); }}
              className="flex-1 text-[10px] font-medium text-[#ff3b3b] border border-[#ff3b3b]/30
                         hover:bg-[#ff3b3b]/10 rounded-lg py-1.5 transition-colors cursor-pointer"
            >
              Ver detalle →
            </button>
            <button
              onClick={() => onDismiss(toast.id)}
              className="text-[10px] text-[#334155] hover:text-white transition-colors cursor-pointer px-2"
            >
              Ignorar
            </button>
          </div>

          {/* Barra de progreso auto-dismiss */}
          <div className="mt-2 h-0.5 bg-[#1C2030] rounded-full overflow-hidden">
            <div
              className="h-full bg-[#ff3b3b]/40 rounded-full"
              style={{ animation: `scanops-shrink ${AUTO_DISMISS_MS}ms linear forwards` }}
            />
          </div>
        </div>
      </div>

      {toasts.length > 1 && (
        <div className="mt-2 text-center">
          <span className="text-[9px] text-[#ff3b3b] bg-[#ff3b3b]/10 border border-[#ff3b3b]/20
                           px-2 py-0.5 rounded-full font-mono">
            +{toasts.length - 1} alertas CRITICAL más
          </span>
        </div>
      )}
    </div>
  );
}
