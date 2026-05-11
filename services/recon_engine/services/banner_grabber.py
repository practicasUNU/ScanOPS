"""
Banner Grabbing Service - Recon Engine
Captura banners de servicios en puertos abiertos usando asyncio.
"""

import asyncio
import re
import ssl
from datetime import datetime
from typing import Dict, List, Optional

from shared.scan_logger import ScanLogger

logger = ScanLogger("banner_grabber")

TIMEOUT = 3.0

SIGNATURES = {
    "ssh": r"SSH-([\d\.]+)-([\w\._-]+)",
    "ftp": r"220[\s-]([\w\._-]+)",
}

_HTTP_PORTS = {80, 443, 8080, 8443}
_HTTPS_PORTS = {443, 8443}


def _parse_http_response_headers(raw: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    lines = raw.splitlines()
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


def _extract_security_headers(headers: Dict[str, str]) -> Dict:
    return {
        "server": headers.get("server"),
        "x_powered_by": headers.get("x-powered-by"),
        "x_frame_options": headers.get("x-frame-options"),
        "x_content_type_options": headers.get("x-content-type-options"),
        "strict_transport_security": headers.get("strict-transport-security"),
        "content_security_policy": headers.get("content-security-policy"),
    }


def _build_tls_info(cert: Optional[Dict], tls_version: Optional[str]) -> Dict:
    info: Dict = {
        "tls_version": tls_version,
        "cert_expiry": None,
        "cert_issuer": None,
        "days_until_expiry": None,
    }
    if not cert:
        return info
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            info["cert_expiry"] = expiry.isoformat()
            info["days_until_expiry"] = (expiry - datetime.utcnow()).days
        except ValueError:
            pass
    issuer = cert.get("issuer", ())
    try:
        issuer_dict = dict(x[0] for x in issuer)
        info["cert_issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
    except Exception:
        pass
    return info


async def grab_banner(ip: str, port: int) -> Dict:
    """
    Captura el banner de un puerto específico.
    Para HTTPS extrae TLS info y cabeceras de seguridad HTTP.
    """
    result: Dict = {
        "port": port,
        "service": "unknown",
        "version": None,
        "raw_banner": "",
        "http_headers": None,
        "tls_info": None,
    }

    is_https = port in _HTTPS_PORTS
    is_http = port in _HTTP_PORTS

    try:
        if is_https:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_OPTIONAL

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_context),
                timeout=TIMEOUT,
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                try:
                    result["tls_info"] = _build_tls_info(
                        ssl_obj.getpeercert(), ssl_obj.version()
                    )
                except Exception as e:
                    logger.debug("TLS_CERT_PARSE_ERROR", ip=ip, port=port, error=str(e))

            result["service"] = "https"

            writer.write(
                b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=TIMEOUT)
                banner = data.decode("utf-8", errors="ignore").strip()
            except asyncio.TimeoutError:
                banner = ""

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            result["raw_banner"] = banner
            if banner:
                parsed = _parse_http_response_headers(banner)
                result["http_headers"] = _extract_security_headers(parsed)
                server_val = parsed.get("server", "")
                if server_val:
                    result["version"] = server_val

        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=TIMEOUT,
            )

            if is_http:
                writer.write(
                    b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                result["service"] = "http"

            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=TIMEOUT)
                banner = data.decode("utf-8", errors="ignore").strip()
            except asyncio.TimeoutError:
                banner = ""

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            result["raw_banner"] = banner

            if is_http and banner:
                parsed = _parse_http_response_headers(banner)
                result["http_headers"] = _extract_security_headers(parsed)
                server_val = parsed.get("server", "")
                if server_val:
                    result["version"] = server_val
            elif "SSH" in banner:
                result["service"] = "ssh"
                match = re.search(SIGNATURES["ssh"], banner)
                if match:
                    result["version"] = match.group(2)
            elif "220" in banner and ("FTP" in banner or "vsFTPd" in banner):
                result["service"] = "ftp"
                match = re.search(r"220[\s-]([\w\._-]+)", banner)
                if match:
                    result["version"] = match.group(1)

            if not result["version"] and banner:
                result["version"] = banner[:50].split("\n")[0]

    except Exception:
        pass

    return result


async def grab_all_banners(ip: str, ports: List[int]) -> List[Dict]:
    """Captura banners de una lista de puertos en paralelo."""
    if not ports:
        return []

    logger.info("BANNER_GRABBING_START", ip=ip, ports_count=len(ports))

    tasks = [grab_banner(ip, port) for port in ports]
    results = await asyncio.gather(*tasks)

    successful_results = [r for r in results if r["raw_banner"] or r["version"]]

    logger.info("BANNER_GRABBING_COMPLETE", count=len(successful_results))
    return successful_results
