"""
CORS Advanced Checker — M3 Scanner Client
Detecta configuraciones CORS inseguras más allá de lo que cubre Nuclei:
  - Wildcard origin (*) con y sin credenciales
  - Origen arbitrario reflejado (ACAO refleja el Origin del atacante)
  - Null origin aceptado (iframe sandboxed attack vector)
  - Preflight OPTIONS permisivo con orígenes maliciosos
ENS: mp.info.4, op.exp.2
"""
import urllib.request
import urllib.error
from typing import List, Dict, Optional, Tuple

from shared.scan_logger import ScanLogger

logger = ScanLogger("cors_checker")

_REQUEST_TIMEOUT = 8
_TEST_ORIGINS = [
    "https://evil.attacker.com",
    "https://attacker.com",
    "https://notallowed-origin.io",
]


def _http_request(
    url: str,
    method: str = "GET",
    origin: Optional[str] = None,
    timeout: int = _REQUEST_TIMEOUT,
) -> Tuple[Optional[int], dict]:
    """Devuelve (status_code, headers_dict). En error devuelve (None, {})."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; ScanOPS-CORS-Checker/1.0)"}
        if origin:
            headers["Origin"] = origin
        if method == "OPTIONS":
            headers["Access-Control-Request-Method"] = "GET"
            headers["Access-Control-Request-Headers"] = "Content-Type, Authorization"
        req = urllib.request.Request(url, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        return e.code, resp_headers
    except Exception:
        return None, {}


def _check_cors_on_url(target_url: str) -> List[Dict]:
    findings = []

    # --- Baseline: verificar que el servidor responde ---
    base_status, _ = _http_request(target_url, method="GET")
    if base_status is None:
        return []

    # --- Test 1: GET con Origin: * (wildcard directo) ---
    _, wc_headers = _http_request(target_url, method="GET", origin="*")
    if wc_headers:
        acao = wc_headers.get("access-control-allow-origin", "")
        acac = wc_headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append({
                "title": "CORS: Wildcard Origin con Credenciales",
                "severity": "CRITICAL",
                "cvss_score": 9.0,
                "description": (
                    f"Access-Control-Allow-Origin: * combinado con "
                    f"Access-Control-Allow-Credentials: true en {target_url}. "
                    "Cualquier origen puede enviar peticiones autenticadas."
                ),
                "cve_id": None,
                "evidence": {
                    "url": target_url,
                    "tested_origin": "*",
                    "acao_header": acao,
                    "acac_header": acac,
                    "cwe": "CWE-942",
                },
                "remediation": (
                    "Nunca combinar Access-Control-Allow-Origin: * con "
                    "Access-Control-Allow-Credentials: true. "
                    "Especificar orígenes concretos de confianza."
                ),
                "scanner": "CORS-Checker",
                "ens_measure": "mp.info.4",
            })
        elif acao == "*":
            findings.append({
                "title": "CORS: Wildcard Origin Permitido",
                "severity": "MEDIUM",
                "cvss_score": 5.3,
                "description": (
                    f"Access-Control-Allow-Origin: * detectado en {target_url}. "
                    "Cualquier origen puede leer los recursos de esta URL."
                ),
                "cve_id": None,
                "evidence": {
                    "url": target_url,
                    "tested_origin": "*",
                    "acao_header": acao,
                    "cwe": "CWE-942",
                },
                "remediation": (
                    "Restringir Access-Control-Allow-Origin a orígenes de confianza específicos. "
                    "Evitar wildcard (*) en producción salvo para APIs públicas sin autenticación."
                ),
                "scanner": "CORS-Checker",
                "ens_measure": "mp.info.4",
            })

    # --- Test 2: Origen arbitrario reflejado ---
    reflected_found = False
    for test_origin in _TEST_ORIGINS:
        _, reflected_headers = _http_request(target_url, method="GET", origin=test_origin)
        if not reflected_headers:
            continue
        acao = reflected_headers.get("access-control-allow-origin", "")
        acac = reflected_headers.get("access-control-allow-credentials", "")
        if acao == test_origin:
            reflected_found = True
            has_creds = acac.lower() == "true"
            severity = "HIGH" if has_creds else "MEDIUM"
            cvss = 8.1 if has_creds else 6.5
            creds_label = "con Credenciales" if has_creds else "sin Credenciales"
            findings.append({
                "title": f"CORS: Origen Reflejado Arbitrario ({creds_label})",
                "severity": severity,
                "cvss_score": cvss,
                "description": (
                    f"El servidor refleja el origen enviado ({test_origin}) en "
                    f"Access-Control-Allow-Origin para {target_url}. "
                    f"Access-Control-Allow-Credentials: {acac}. "
                    "Un atacante puede leer respuestas cross-origin."
                ),
                "cve_id": None,
                "evidence": {
                    "url": target_url,
                    "tested_origin": test_origin,
                    "acao_header": acao,
                    "acac_header": acac,
                    "cwe": "CWE-942",
                },
                "remediation": (
                    "Implementar lista blanca de orígenes permitidos. "
                    "Validar Origin contra la lista antes de reflejarlo en ACAO."
                ),
                "scanner": "CORS-Checker",
                "ens_measure": "mp.info.4",
            })
            break  # Una finding por URL es suficiente para reflected origin

    # --- Test 3: Null origin ---
    _, null_headers = _http_request(target_url, method="GET", origin="null")
    if null_headers:
        acao = null_headers.get("access-control-allow-origin", "")
        if acao == "null":
            findings.append({
                "title": "CORS: Null Origin Aceptado",
                "severity": "MEDIUM",
                "cvss_score": 5.3,
                "description": (
                    f"El servidor acepta 'null' como origen CORS en {target_url}. "
                    "Un iframe sandboxed envía Origin: null, lo que puede explotarse para CSRF."
                ),
                "cve_id": None,
                "evidence": {
                    "url": target_url,
                    "tested_origin": "null",
                    "acao_header": acao,
                    "cwe": "CWE-942",
                },
                "remediation": "No permitir 'null' como origen válido en la política CORS.",
                "scanner": "CORS-Checker",
                "ens_measure": "mp.info.4",
            })

    # --- Test 4: Preflight OPTIONS con origen malicioso ---
    if not reflected_found:
        preflight_origin = _TEST_ORIGINS[0]
        _, pre_headers = _http_request(target_url, method="OPTIONS", origin=preflight_origin)
        if pre_headers:
            acao = pre_headers.get("access-control-allow-origin", "")
            acam = pre_headers.get("access-control-allow-methods", "")
            acac = pre_headers.get("access-control-allow-credentials", "")
            is_permissive = acao in (preflight_origin, "*")
            has_dangerous_methods = any(
                m.strip().upper() in ("PUT", "DELETE", "PATCH")
                for m in acam.split(",")
            )
            if is_permissive and acam:
                findings.append({
                    "title": "CORS: Preflight Permisivo con Métodos Extendidos",
                    "severity": "MEDIUM" if not has_dangerous_methods else "HIGH",
                    "cvss_score": 6.5 if not has_dangerous_methods else 7.5,
                    "description": (
                        f"El preflight OPTIONS acepta origen {acao} y métodos '{acam}' en {target_url}. "
                        f"Access-Control-Allow-Credentials: {acac}."
                    ),
                    "cve_id": None,
                    "evidence": {
                        "url": target_url,
                        "method": "OPTIONS",
                        "tested_origin": preflight_origin,
                        "acao_header": acao,
                        "acam_header": acam,
                        "acac_header": acac,
                        "cwe": "CWE-942",
                    },
                    "remediation": (
                        "Restringir Access-Control-Allow-Methods a los mínimos necesarios "
                        "(GET, POST) y validar el origen en el preflight."
                    ),
                    "scanner": "CORS-Checker",
                    "ens_measure": "mp.info.4",
                })

    return findings


def run_cors_check(asset_id: int, target_url: str) -> List[Dict]:
    logger.info("CORS_CHECK_START", target=target_url)
    try:
        findings = _check_cors_on_url(target_url)
        logger.info("CORS_CHECK_FINISH", target=target_url, findings=len(findings))
        return findings
    except Exception as e:
        logger.error("CORS_CHECK_ERROR", target=target_url, error=str(e))
        return []
