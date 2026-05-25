import { useState, useEffect, useCallback } from 'react';

const M1_ASSETS_URL = 'http://localhost:8001/api/v1/assets?page_size=100';
const BASE_RESULTS_URL = 'http://localhost:8002/api/v1/scan/results';
const TOKEN_KEY = 'scanops_auth';

/** Reads the stored JWT from sessionStorage (ENS mp.info.3). */
function getToken() {
  try {
    const raw = sessionStorage.getItem(TOKEN_KEY);
    if (!raw) return null;
    return JSON.parse(raw)?.access_token ?? null;
  } catch {
    return null;
  }
}

/**
 * Fetches the active asset list from M1, dynamically triggers concurrent
 * scan results from M3 for all discovered hosts, and consolidates them in hot-time.
 * Returns { data, loading, error, refetch }.
 */
export function useScanData() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = getToken();
      const headers = token ? { Authorization: `Bearer ${token}` } : {};

      // ─── PASO 1: CONSULTAR EL INVENTARIO REAL DE ACTIVOS (M1) ───
      const assetsRes = await fetch(M1_ASSETS_URL, { headers });
      if (!assetsRes.ok) {
        if (assetsRes.status === 401) {
          throw new Error('Token expirado — vuelve a iniciar sesión');
        }
        throw new Error(`M1 no disponible (HTTP ${assetsRes.status})`);
      }
      const assetsData = await assetsRes.json();
      
      // Filtramos únicamente los activos que están operativos en producción
      const activeAssets = (assetsData.items ?? []).filter(a => a.status === 'ACTIVO');

      if (activeAssets.length === 0) {
        setData({ findings: [], severity_counts: {}, top_ports: [], tool_breakdown: [], top_assets: [] });
        return;
      }

      // ─── PASO 2: LANZAR CONSULTAS CONCURRENTES DINÁMICAS (M3) ───
      const reports = await Promise.all(
        activeAssets.map(async (asset) => {
          try {
            const res = await fetch(`${BASE_RESULTS_URL}/${asset.id}`, { headers });
            if (res.ok) {
              const report = await res.json();
              return { asset, report };
            }
          } catch (e) {
            console.warn(`[ScanData] No se pudieron obtener resultados para el activo ID ${asset.id} (${asset.ip})`, e);
          }
          // Fallback seguro si el activo no ha sido escaneado aún
          return { asset, report: { findings_by_scanner: {} } };
        })
      );

      // ─── PASO 3: AGREGACIÓN Y CONSOLIDACIÓN DE DATOS ───
      const compiledFindings = [];
      const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      const toolMap = {};
      const portMap = {};
      const assetCounts = {};

      // Inicializamos el contador dinámico de vulnerabilidades por IP activa
      activeAssets.forEach(a => {
        assetCounts[a.ip] = 0;
      });

      // Procesador interno de reportes normalizados
      const processAssetReport = (assetReport, ip) => {
        const scanners = assetReport.findings_by_scanner || {};
        
        Object.entries(scanners).forEach(([scannerKey, list]) => {
          if (!Array.isArray(list)) return;
          
          list.forEach((finding, index) => {
            const severity = (finding.severity || 'INFO').toUpperCase();
            const toolName = scannerKey.charAt(0).toUpperCase() + scannerKey.slice(1).toLowerCase();

            // 1. Métricas globales de severidad
            if (severity in severityCounts) {
              severityCounts[severity]++;
            } else {
              severityCounts['INFO']++;
            }

            // 2. Incrementar métricas por activo real
            if (ip in assetCounts) {
              assetCounts[ip]++;
            }

            // 3. Desglose analítico por herramientas
            if (!toolMap[toolName]) {
              toolMap[toolName] = { name: toolName, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
            }
            if (severity in toolMap[toolName]) {
              toolMap[toolName][severity]++;
            }

            // 4. Identificación heurística de puertos
            let parsedPort = "80/tcp";
            const titleLower = finding.title.toLowerCase();
            if (titleLower.includes("22") || titleLower.includes("ssh")) parsedPort = "22/tcp";
            else if (titleLower.includes("443") || titleLower.includes("https")) parsedPort = "443/tcp";
            else if (titleLower.includes("445") || titleLower.includes("smb")) parsedPort = "445/tcp";
            else if (titleLower.includes("3389") || titleLower.includes("rdp")) parsedPort = "3389/tcp";
            else if (titleLower.includes("8080")) parsedPort = "8080/tcp";
            
            portMap[parsedPort] = (portMap[parsedPort] || 0) + 1;

            // 5. Inyección en la cola estructurada de la tabla
            compiledFindings.push({
              id: `F-${String(compiledFindings.length + 1).padStart(3, '0')}`,
              activo: ip,
              herramienta: toolName,
              nombre: finding.title,
              severidad: severity,
              cve: finding.cve || null,
              cvss: finding.cvss ? String(finding.cvss) : "0.0",
              descripcion: finding.description || `Vulnerabilidad técnica identificada de forma automatizada por el escáner ${toolName} en el activo perimetral ${ip}.`,
              medida_ens: severity === 'CRITICAL' || severity === 'HIGH' ? 'op.exp.4' : 'op.exp.2',
              articulo_ens: severity === 'CRITICAL' || severity === 'HIGH'
                ? 'op.exp.4 — Mantenimiento y actualizaciones: Mitigación prioritaria requerida según las ventanas temporales fijadas por el ENS.'
                : 'op.exp.2 — Gestión de vulnerabilidades: Control continuo de la superficie expuesta y evaluación técnica de parches.'
            });
          });
        });
      };

      // Iteramos dinámicamente sobre la lista consolidada de reportes obtenidos
      reports.forEach(({ asset, report }) => {
        processAssetReport(report, asset.ip);
      });

      // Formatear mapeos a arrays estructurados para los diagramas de Recharts
      const topPortsFormatted = Object.entries(portMap)
        .map(([port, count]) => ({ port, count }))
        .sort((a, b) => b.count - a.count);

      const topAssetsFormatted = Object.entries(assetCounts)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value);

      // Actualizar el estado global con datos unificados reales
      setData({
        findings: compiledFindings,
        severity_counts: severityCounts,
        top_ports: topPortsFormatted,
        tool_breakdown: Object.values(toolMap),
        top_assets: topAssetsFormatted
      });

    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('401') || msg.includes('Token expirado')) {
        setError('Token expirado — vuelve a iniciar sesión');
      } else if (msg.includes('fetch') || msg.includes('Failed to fetch') || msg.includes('NetworkError')) {
        setError('Servicio no disponible — comprueba que M1/M3 están activos');
      } else {
        setError(msg || 'Error al obtener datos de escaneo consolidados');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch: fetchData };
}