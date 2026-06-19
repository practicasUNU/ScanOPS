import { useState, useEffect, useRef } from 'react';
import { ENDPOINTS } from '../config/api';

export interface LogEntry {
  timestamp: string;
  level: 'INFO' | 'SUCCESS' | 'WARN' | 'ERROR';
  module: string;
  message: string;
}

const MAX_ENTRIES = 50;

export function useLogStream() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const url = ENDPOINTS.logStream;
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => {
      setConnected(true);
      setError(null);
    };

    es.onmessage = (event) => {
      try {
        const entry: LogEntry = JSON.parse(event.data);
        setEntries(prev => {
          const updated = [...prev, entry];
          return updated.slice(-MAX_ENTRIES);
        });
      } catch {
        // ignore malformed entries
      }
    };

    es.onerror = () => {
      setConnected(false);
      setError('Log stream desconectado — reconectando...');
      // EventSource reconnects automatically
    };

    return () => {
      es.close();
      esRef.current = null;
      setConnected(false);
    };
  }, []);

  return { entries, connected, error };
}
