import { useState, useEffect, useRef, useCallback } from 'react';
import { ScrollArea } from '@/app/components/ui/scroll-area';
import { Wifi, WifiOff } from 'lucide-react';

const SSE_URL = '/api/m3/stream/findings';
const MAX_LINES = 200;

/** Maps a JSON finding to a formatted terminal line. */
function formatLine(entry) {
  const ts = entry.timestamp
    ? new Date(entry.timestamp).toLocaleTimeString('es-ES')
    : new Date().toLocaleTimeString('es-ES');
  const level = (entry.level ?? entry.severity ?? 'INFO').toUpperCase();
  const msg = entry.message ?? entry.finding ?? JSON.stringify(entry);
  return { ts, level, msg, raw: entry };
}

/** Returns the Tailwind color class for a log level/severity. */
function levelColor(level) {
  switch (level) {
    case 'CRITICAL': return 'text-red-500';
    case 'HIGH':     return 'text-red-400';
    case 'ERROR':    return 'text-red-400';
    case 'WARN':
    case 'WARNING':
    case 'MEDIUM':   return 'text-amber-400';
    case 'SUCCESS':  return 'text-green-400';
    case 'LOW':
    case 'INFO':     return 'text-green-400';
    default:         return 'text-slate-400';
  }
}

/**
 * LivePipelineTerminal — streams findings from M3 over SSE (GET /stream/findings).
 * Auto-reconnects every 5s on error.
 */
export function LivePipelineTerminal() {
  const [lines, setLines] = useState([
    { ts: '--:--:--', level: 'INFO', msg: 'Conectando con el pipeline…' },
  ]);
  const [connected, setConnected] = useState(false);
  const esRef = useRef(null);
  const bottomRef = useRef(null);

  /** Auto-scroll to bottom when new lines arrive. */
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  const connect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
    }

    const es = new EventSource(SSE_URL);
    esRef.current = es;

    es.onopen = () => {
      setConnected(true);
      setLines(prev => [
        ...prev,
        { ts: new Date().toLocaleTimeString('es-ES'), level: 'SUCCESS', msg: 'SSE conectado — escuchando hallazgos en tiempo real' },
      ]);
    };

    es.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'ping') return;
        const line = formatLine(payload);
        setLines(prev => [...prev, line].slice(-MAX_LINES));
      } catch {
        // Ignore malformed frames
      }
    };

    es.onerror = () => {
      setConnected(false);
      es.close();
      setLines(prev => [
        ...prev,
        { ts: new Date().toLocaleTimeString('es-ES'), level: 'WARN', msg: 'SSE desconectado — reintentando en 5s…' },
      ]);
      setTimeout(connect, 5000);
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      esRef.current?.close();
    };
  }, [connect]);

  const handleClear = () => setLines([]);

  return (
    <div className="flex flex-col h-full bg-[#0a0c12] border border-[#1C2030] rounded-lg overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-[#1C2030] bg-[#111318]">
        <div className="flex items-center gap-2">
          <span className="text-[#64748B] text-xs font-mono">pipeline@scanops:~$</span>
          <span className="text-[#334155] text-xs font-mono">sse/findings</span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleClear}
            className="text-[#334155] hover:text-[#64748B] text-xs font-mono transition-colors"
          >
            clear
          </button>
          <div className="flex items-center gap-1.5 text-xs font-mono">
            {connected ? (
              <>
                <Wifi className="w-3 h-3 text-green-400" />
                <span className="text-green-400">LIVE</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3 h-3 text-[#475569]" />
                <span className="text-[#475569]">OFFLINE</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Terminal body */}
      <ScrollArea className="flex-1 h-[520px]">
        <div className="p-4 font-mono text-xs space-y-0.5">
          {lines.map((line, i) => (
            <div key={i} className="flex gap-2 leading-5">
              <span className="text-[#334155] shrink-0 select-none">{line.ts}</span>
              <span className={`shrink-0 w-14 ${levelColor(line.level)}`}>{line.level}</span>
              <span className="text-[#d1d5db] break-all">{line.msg}</span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      </ScrollArea>
    </div>
  );
}
