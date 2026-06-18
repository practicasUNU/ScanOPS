import { Component, type ReactNode, type ErrorInfo } from 'react';

interface Props {
  children: ReactNode;
  label?: string;
}

interface State {
  error: Error | null;
}

/**
 * Captura cualquier error de render/hooks de sus hijos y muestra el detalle
 * en pantalla en vez de dejar el árbol en blanco/negro.
 */
export class RouteErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Visible en la consola del navegador para diagnóstico
    console.error(`[${this.props.label ?? 'Route'} crash]`, error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex h-screen bg-[#0f1117] items-center justify-center p-8">
          <div className="max-w-3xl w-full bg-[#1a1d27] border border-[#ff3b3b]/30 rounded-xl p-6">
            <h2 className="text-[#ff3b3b] font-bold text-lg mb-1">
              Error al renderizar {this.props.label ?? 'la vista'}
            </h2>
            <p className="text-[#9ca3af] text-xs mb-4">
              Se ha capturado una excepción de React. Detalle técnico:
            </p>
            <pre className="text-[#f59e0b] text-xs font-mono whitespace-pre-wrap break-all bg-[#0f1117] p-4 rounded-lg max-h-[60vh] overflow-auto">
              {this.state.error.message}
              {'\n\n'}
              {this.state.error.stack}
            </pre>
            <button
              onClick={() => location.reload()}
              className="mt-4 px-4 py-2 rounded-lg text-sm font-semibold bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] hover:bg-[#00d4ff]/20 cursor-pointer"
            >
              Recargar
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
