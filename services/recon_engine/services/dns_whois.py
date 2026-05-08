"""
DNS and WHOIS Service - Recon Engine
Consultas de registros DNS e información de dominio (WHOIS) y ASN.
"""

import socket
import logging
from typing import Dict, Optional
from datetime import datetime

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


def _lookup_asn_iana(target: str) -> Dict:
    """Consulta ASN vía socket TCP a whois.iana.org (port 43). Sin dependencias extras."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(("whois.iana.org", 43))
        sock.sendall((target + "\r\n").encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
        text = b"".join(chunks).decode("utf-8", errors="ignore")

        asn = None
        asn_desc = None
        country = None
        for line in text.splitlines():
            lower = line.lower().strip()
            if lower.startswith("origin:") or lower.startswith("aut-num:"):
                asn = line.split(":", 1)[1].strip()
            elif lower.startswith("descr:") and asn_desc is None:
                asn_desc = line.split(":", 1)[1].strip()
            elif lower.startswith("country:") and country is None:
                country = line.split(":", 1)[1].strip().upper()
        return {"asn": asn, "asn_description": asn_desc, "country": country}
    except Exception as e:
        logger.info("ASN_IANA_LOOKUP_FAILED", target=target, error=str(e))
        return {"asn": None, "asn_description": None, "country": None}


async def get_asn_info(target: str) -> Dict:
    """
    Obtiene ASN, descripción y país para una IP o dominio.
    Intenta python-whois primero; usa IANA como fallback.
    Nunca bloquea el flujo principal — retorna nulls en caso de error.
    """
    result = {"asn": None, "asn_description": None, "country": None}
    try:
        if HAS_WHOIS:
            w = whois.whois(target)
            asn = getattr(w, "asn", None)
            if asn:
                result["asn"] = str(asn)
                result["asn_description"] = getattr(w, "asn_description", None)
                result["country"] = getattr(w, "country", None)
                return result
        # Fallback: IANA socket
        result = _lookup_asn_iana(target)
    except Exception as e:
        logger.info("ASN_LOOKUP_FAILED", target=target, error=str(e))
        result = _lookup_asn_iana(target)
    return result


async def get_dns_info(domain: str) -> Dict:
    """
    Realiza consultas DNS (A, MX, TXT, NS, CNAME).
    Detecta SPF en registros TXT.
    """
    results: Dict = {
        "A": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": [],
        "spf_record": None,
    }

    if not HAS_DNS:
        logger.warning("DNS_LIB_MISSING", hint="Install dnspython")
        try:
            results["A"] = [socket.gethostbyname(domain)]
        except Exception:
            pass
        return results

    for record in ["A", "MX", "TXT", "NS", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                if record == "MX":
                    results[record].append({
                        "host": str(rdata.exchange).strip("."),
                        "priority": rdata.preference,
                    })
                else:
                    results[record].append(str(rdata).strip('"'))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, Exception) as e:
            logger.info("DNS_QUERY_NO_DATA", domain=domain, record=record, error=str(e))

    # SPF detection from TXT records
    for txt in results["TXT"]:
        if isinstance(txt, str) and txt.startswith("v=spf1"):
            results["spf_record"] = txt
            break

    return results


async def get_whois_info(domain: str) -> Dict:
    """Extrae información WHOIS incluyendo ASN cuando está disponible."""
    results = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "status": None,
        "asn": None,
        "asn_description": None,
        "country": None,
    }

    if not HAS_WHOIS:
        logger.warning("WHOIS_LIB_MISSING", hint="Install python-whois")
        return results

    try:
        w = whois.whois(domain)

        results["registrar"] = w.registrar

        def parse_date(date_val):
            if isinstance(date_val, list):
                return date_val[0].isoformat() if date_val else None
            return date_val.isoformat() if hasattr(date_val, "isoformat") else str(date_val) if date_val else None

        results["creation_date"] = parse_date(w.creation_date)
        results["expiration_date"] = parse_date(w.expiration_date)

        if w.name_servers:
            results["name_servers"] = [ns.lower() for ns in w.name_servers]

        results["status"] = w.status[0] if isinstance(w.status, list) else w.status

        # ASN fields (available for some TLDs/IPs via python-whois)
        asn_val = getattr(w, "asn", None)
        if asn_val:
            results["asn"] = str(asn_val)
            results["asn_description"] = getattr(w, "asn_description", None)
        results["country"] = getattr(w, "country", None)

    except Exception as e:
        logger.error("WHOIS_QUERY_FAILED", domain=domain, error=str(e))

    return results


async def _get_dmarc_record(domain: str) -> Optional[str]:
    """Consulta registro DMARC en _dmarc.<domain>."""
    if not HAS_DNS:
        return None
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if "DMARC1" in txt or "v=DMARC" in txt.upper():
                return txt
        # Return first TXT if none matched explicitly
        for rdata in answers:
            return str(rdata).strip('"')
    except Exception as e:
        logger.info("DMARC_QUERY_FAILED", domain=domain, error=str(e))
    return None


async def get_domain_recon(domain: str) -> Dict:
    """Orquesta DNS, WHOIS, SPF y DMARC para un dominio."""
    logger.info("DOMAIN_RECON_START", domain=domain)

    dns_data = await get_dns_info(domain)
    whois_data = await get_whois_info(domain)

    # SPF is extracted from TXT records inside get_dns_info
    spf_record = dns_data.pop("spf_record", None)

    dmarc_record = await _get_dmarc_record(domain)

    logger.info("DOMAIN_RECON_COMPLETE", domain=domain)

    return {
        "domain": domain,
        "dns_records": dns_data,
        "spf_record": spf_record,
        "dmarc_record": dmarc_record,
        "whois_info": whois_data,
        "scanned_at": datetime.utcnow().isoformat(),
    }
