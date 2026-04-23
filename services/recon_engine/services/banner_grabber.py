"""
Banner Grabbing Service - Recon Engine
Captura banners de servicios en puertos abiertos usando asyncio.
"""

import asyncio
import re
from typing import Dict, List, Optional

from shared.scan_logger import ScanLogger

logger = ScanLogger("banner_grabber")

TIMEOUT = 3.0

# Mapeo básico de firmas comunes para extracción de versiones
SIGNATURES = {
    "ssh": r"SSH-([\d\.]+)-([\w\._-]+)",
    "ftp": r"220[\s-]([\w\._-]+)",
    "http": r"Server: ([\w\._\s\-\/]+)",
}

async def grab_banner(ip: str, port: int) -> Dict:
    """
    Intenta capturar el banner de un puerto específico.
    """
    result = {
        "port": port,
        "service": "unknown",
        "version": None,
        "raw_banner": ""
    }

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=TIMEOUT
        )

        # Algunos servicios envían el banner inmediatamente (SSH, FTP)
        # Otros necesitan un probe (HTTP)
        
        banner = ""
        
        # Lógica especial por puerto si es necesario
        if port in [80, 443, 8080, 8443]:
            writer.write(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
            result["service"] = "http"
        
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=TIMEOUT)
            banner = data.decode('utf-8', errors='ignore').strip()
        except asyncio.TimeoutError:
            pass

        writer.close()
        await writer.wait_closed()

        result["raw_banner"] = banner
        
        # Identificación básica
        if "SSH" in banner:
            result["service"] = "ssh"
            match = re.search(SIGNATURES["ssh"], banner)
            if match:
                result["version"] = match.group(2)
        elif "220" in banner and ("FTP" in banner or "vsFTPd" in banner):
            result["service"] = "ftp"
            match = re.search(SIGNATURES["ftp"], banner)
            if match:
                result["version"] = match.group(1)
        elif "HTTP" in banner or "Server:" in banner:
            result["service"] = "http"
            match = re.search(SIGNATURES["http"], banner)
            if match:
                result["version"] = match.group(1)
        
        # Si no hay versión pero hay banner, poner el banner corto
        if not result["version"] and banner:
            result["version"] = banner[:50].split('\n')[0]

    except Exception as e:
        # Fallo de conexión o timeout
        pass

    return result

async def grab_all_banners(ip: str, ports: List[int]) -> List[Dict]:
    """
    Captura banners de una lista de puertos en paralelo.
    """
    if not ports:
        return []

    logger.info("BANNER_GRABBING_START", ip=ip, ports_count=len(ports))
    
    tasks = [grab_banner(ip, port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    # Filtrar resultados que no obtuvieron nada
    successful_results = [r for r in results if r["raw_banner"] or r["version"]]
    
    logger.info("BANNER_GRABBING_COMPLETE", count=len(successful_results))
    return successful_results
