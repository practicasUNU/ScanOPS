"""
DNS and WHOIS Service - Recon Engine
Consultas de registros DNS e información de dominio (WHOIS).
"""

import socket
import logging
from typing import Dict, List, Optional
from datetime import datetime

# Se asume que dnspython y python-whois están instalados
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

from shared.scan_logger import ScanLogger

logger = ScanLogger("dns_whois")

async def get_dns_info(domain: str) -> Dict:
    """
    Realiza consultas DNS (A, MX, TXT, NS).
    """
    results = {
        "A": [],
        "MX": [],
        "TXT": [],
        "NS": []
    }

    if not HAS_DNS:
        logger.warning("DNS_LIB_MISSING", hint="Install dnspython")
        # Fallback básico para registro A usando socket
        try:
            results["A"] = [socket.gethostbyname(domain)]
        except:
            pass
        return results

    records = ["A", "MX", "TXT", "NS"]
    
    for record in records:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                if record == "MX":
                    results[record].append({
                        "host": str(rdata.exchange).strip('.'),
                        "priority": rdata.preference
                    })
                else:
                    results[record].append(str(rdata).strip('"'))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception) as e:
            logger.debug("DNS_QUERY_NO_DATA", domain=domain, record=record, error=str(e))

    return results

async def get_whois_info(domain: str) -> Dict:
    """
    Extrae información WHOIS del dominio.
    """
    results = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "status": None
    }

    if not HAS_WHOIS:
        logger.warning("WHOIS_LIB_MISSING", hint="Install python-whois")
        return results

    try:
        # La librería whois es bloqueante, pero para una sola consulta suele ser rápida
        w = whois.whois(domain)
        
        results["registrar"] = w.registrar
        
        # Las fechas pueden ser una lista o un datetime simple
        def parse_date(date_val):
            if isinstance(date_val, list):
                return date_val[0].isoformat() if date_val else None
            return date_val.isoformat() if hasattr(date_val, 'isoformat') else str(date_val)

        results["creation_date"] = parse_date(w.creation_date)
        results["expiration_date"] = parse_date(w.expiration_date)
        
        if w.name_servers:
            results["name_servers"] = [ns.lower() for ns in w.name_servers]
            
        results["status"] = w.status[0] if isinstance(w.status, list) else w.status

    except Exception as e:
        logger.error("WHOIS_QUERY_FAILED", domain=domain, error=str(e))

    return results

async def get_domain_recon(domain: str) -> Dict:
    """
    Orquesta la recolección de información DNS y WHOIS.
    """
    logger.info("DOMAIN_RECON_START", domain=domain)
    
    # Ejecutamos ambos en paralelo si es posible
    # Aunque whois es bloqueante, en un wrapper async no hay problema mayor 
    # para una sola tarea
    dns_data = await get_dns_info(domain)
    whois_data = await get_whois_info(domain)
    
    logger.info("DOMAIN_RECON_COMPLETE", domain=domain)
    
    return {
        "domain": domain,
        "dns_records": dns_data,
        "whois_info": whois_data,
        "scanned_at": datetime.utcnow().isoformat()
    }
