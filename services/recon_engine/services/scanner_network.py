"""
M2 Recon Engine - Scanner Network Module
========================================
Descubrimiento de activos en la red (Reconocimiento puro).
M2: Hechos técnicos (Puertos, Servicios, Versiones, SO).
NO realiza análisis de vulnerabilidades ni severidades.
"""

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
import aiohttp

from shared.scan_logger import ScanLogger
from shared.database import SessionLocal
from services.recon_engine.models.recon import ReconSnapshot, ReconFinding, ReconSubdomain
from services.recon_engine.models.schemas import (
    ReconSnapshotSchema, PortDiscovery, OSInformation,
    HostInformation, ReconData, ReconSummary, DomainRecon, SubdomainInfo,
    HttpHeaders, TlsInfo,
)
from services.recon_engine.services.dns_whois import get_domain_recon, get_asn_info
from services.recon_engine.services.banner_grabber import grab_all_banners

logger = ScanLogger("scanner_network")

_IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


async def _run_tool(cmd: List[str]) -> Tuple[str, str, int]:
    """Ejecuta herramienta externa de forma asíncrona."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await process.communicate()
        return (
            stdout_bytes.decode("utf-8", errors="ignore"),
            stderr_bytes.decode("utf-8", errors="ignore"),
            process.returncode,
        )
    except Exception as e:
        logger.error("TOOL_EXECUTION_ERROR", cmd=" ".join(cmd), error=str(e))
        raise


def parse_nmap_xml(
    xml_output: str,
) -> Tuple[List[PortDiscovery], Optional[OSInformation], Optional[HostInformation], int]:
    """
    Parsea el output XML de Nmap.
    Devuelve (ports_open, os_info, host_info, filtered_count).
    """
    ports_discovered: List[PortDiscovery] = []
    os_info: Optional[OSInformation] = None
    host_info: Optional[HostInformation] = None
    filtered_count = 0

    if not xml_output:
        return ports_discovered, os_info, host_info, filtered_count

    try:
        root = ET.fromstring(xml_output)

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            address = host.find('address[@addrtype="ipv4"]')
            ip = address.get("addr") if address is not None else "unknown"

            mac_addr_elem = host.find('address[@addrtype="mac"]')
            mac_val = mac_addr_elem.get("addr") if mac_addr_elem is not None else None
            vendor_val = mac_addr_elem.get("vendor") if mac_addr_elem is not None else None

            times = host.find("times")
            latency = None
            if times is not None and times.get("srtt"):
                try:
                    latency = float(times.get("srtt")) / 1000.0
                except (ValueError, TypeError):
                    latency = None

            host_info = HostInformation(
                mac_address=mac_val,
                vendor=vendor_val,
                latency_ms=latency,
            )

            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None:
                        continue
                    state_val = state_elem.get("state")

                    if state_val == "filtered":
                        filtered_count += 1
                        continue

                    if state_val == "open":
                        service_elem = port_elem.find("service")
                        port_id = int(port_elem.get("portid"))
                        protocol = port_elem.get("protocol")
                        service_name = service_elem.get("name") if service_elem is not None else "unknown"
                        product = service_elem.get("product") if service_elem is not None else None
                        version = service_elem.get("version") if service_elem is not None else ""
                        extrainfo = service_elem.get("extrainfo") if service_elem is not None else ""

                        parts = [p for p in [product, version, extrainfo] if p and p.strip()]
                        full_version = " ".join(parts) if parts else "unknown"

                        conf = 0.7
                        if service_elem is not None:
                            method = service_elem.get("method")
                            if method == "probed":
                                conf = 0.9
                            elif method == "table":
                                conf = 0.5

                        ports_discovered.append(
                            PortDiscovery(
                                port=port_id,
                                protocol=protocol,
                                state="open",
                                service=service_name,
                                version=full_version or "unknown",
                                product=product,
                                confidence=conf,
                            )
                        )

            os_elem = host.find("os")
            if os_elem is not None:
                os_match = os_elem.find("osmatch")
                if os_match is not None:
                    os_class = os_match.find("osclass")
                    cpe_text = ""
                    if os_class is not None:
                        cpe_elem = os_class.find("cpe")
                        if cpe_elem is not None and cpe_elem.text:
                            cpe_text = cpe_elem.text

                    os_info = OSInformation(
                        detected_family=os_class.get("osfamily", "Unknown") if os_class is not None else "Unknown",
                        detected_version=os_match.get("name", "Unknown"),
                        cpe=cpe_text or None,
                        confidence=float(os_match.get("accuracy", "50")) / 100,
                    )

    except Exception as e:
        logger.error("XML_PARSE_ERROR", error=str(e))

    return ports_discovered, os_info, host_info, filtered_count


async def run_nmap_scan(
    target: str,
) -> Tuple[List[PortDiscovery], Optional[OSInformation], Optional[HostInformation], int]:
    """Ejecuta Nmap con detección de versiones y SO."""
    logger.info("NMAP_RECON_START", target=target)

    cmd = ["nmap", "-sV", "-O", "--osscan-limit", "-T4", "-oX", "-", target]

    try:
        stdout, stderr, returncode = await _run_tool(cmd)
        if returncode != 0:
            logger.warning("NMAP_RECON_PARTIAL", error=stderr[:200])
        return parse_nmap_xml(stdout)
    except FileNotFoundError:
        logger.error("NMAP_NOT_INSTALLED")
        return [], None, None, 0
    except Exception as e:
        logger.error("NMAP_SCAN_ERROR", error=str(e))
        return [], None, None, 0


_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
_WEBCHECK_BASE = "http://scanops-webcheck:3000/api"
_WEBCHECK_ENDPOINTS = ["ssl", "headers", "dns", "cookies", "tech-stack", "dnssec", "mail-config"]


def has_web_service(ports: List[PortDiscovery]) -> bool:
    return any(p.port in _WEB_PORTS for p in ports)


async def run_webcheck(target: str) -> dict:
    url_target = target if target.startswith(("http://", "https://")) else f"https://{target}"
    logger.info("WEBCHECK_START", target=url_target)
    timeout = aiohttp.ClientTimeout(total=30)
    results: dict = {}
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async def _fetch(endpoint: str) -> tuple[str, dict]:
                try:
                    async with session.get(
                        f"{_WEBCHECK_BASE}/{endpoint}",
                        params={"url": url_target},
                    ) as resp:
                        data = await resp.json(content_type=None)
                        return endpoint, data
                except Exception as e:
                    logger.warning("WEBCHECK_ENDPOINT_ERROR", endpoint=endpoint, error=str(e))
                    return endpoint, {}

            responses = await asyncio.gather(*[_fetch(ep) for ep in _WEBCHECK_ENDPOINTS])
            results = {ep: data for ep, data in responses}
    except Exception as e:
        logger.error("WEBCHECK_SESSION_ERROR", target=url_target, error=str(e))
        return {}
    logger.info("WEBCHECK_DONE", target=url_target, endpoints=len(results))
    return results


async def perform_full_recon(snapshot_id: str, target: str, db: Session) -> ReconSnapshotSchema:
    """
    Orquestación completa del reconocimiento M2.
    snapshot_id aquí es el cycle_id (string).
    """
    start_time = datetime.utcnow()

    snapshot_db = db.query(ReconSnapshot).filter(
        ReconSnapshot.cycle_id == snapshot_id
    ).first()

    if not snapshot_db:
        snapshot_db = ReconSnapshot(
            cycle_id=snapshot_id,
            target=target,
            status="running",
            started_at=start_time,
        )
        db.add(snapshot_db)
        db.commit()
        db.refresh(snapshot_db)

    # Determinar si el target es un hostname/dominio o IP pura
    is_domain = not _IP_PATTERN.match(target)

    if is_domain:
        (ports, os_info, host_info, filtered_count), domain_recon_dict = await asyncio.gather(
            run_nmap_scan(target),
            get_domain_recon(target),
        )
    else:
        ports, os_info, host_info, filtered_count = await run_nmap_scan(target)
        domain_recon_dict = None

    # Banner grabbing en paralelo sobre puertos abiertos
    open_ports = [p.port for p in ports]
    banners = await grab_all_banners(target, open_ports)

    # Enriquecer ports con banner / TLS / HTTP headers
    banner_map = {b["port"]: b for b in banners}
    for port_obj in ports:
        banner = banner_map.get(port_obj.port)
        if banner:
            raw_headers = banner.get("http_headers")
            if raw_headers:
                port_obj.http_headers = HttpHeaders(**raw_headers)
            raw_tls = banner.get("tls_info")
            if raw_tls:
                port_obj.tls_info = TlsInfo(**raw_tls)

    # Web-Check (M2 - escáner 4)
    if has_web_service(ports):
        logger.info("WEBCHECK_START", target=target)
        webcheck_data = await run_webcheck(target)
    else:
        logger.info("WEBCHECK_SKIPPED", target=target, reason="no web ports detected")
        webcheck_data = {}

    # Persistir findings
    for p in ports:
        finding = ReconFinding(
            snapshot_id=snapshot_db.id,
            host=target,
            port=str(p.port),
            service=p.service,
            version=p.version,
            state=p.state,
            source="nmap",
            first_seen_snapshot_id=snapshot_db.id,
        )
        db.add(finding)

    # vhost fuzzing — solo para dominios con puertos web abiertos
    if is_domain and has_web_service(ports):
        from services.recon_engine.services.vhost_fuzzer import fuzz_vhosts
        web_ports_list = [p.port for p in ports if p.port in (80, 443, 8080, 8443)]
        try:
            vhost_results = await fuzz_vhosts(target, web_ports_list or [80])
            for vh in vhost_results:
                db.add(ReconSubdomain(
                    snapshot_id=snapshot_db.id,
                    subdomain=vh,
                    source="ffuf_vhost",
                ))
            if vhost_results:
                logger.info("VHOST_FUZZ_PERSIST", target=target, count=len(vhost_results))
        except Exception as e:
            logger.warning("VHOST_FUZZ_ERROR", target=target, error=str(e))

    # ASN para targets IP
    if not is_domain and host_info:
        try:
            asn_info = await get_asn_info(target)
            host_info.asn = asn_info.get("asn")
            host_info.asn_description = asn_info.get("asn_description")
            host_info.country = asn_info.get("country")
        except Exception as e:
            logger.debug("ASN_ENRICH_FAILED", target=target, error=str(e))

    # Actualizar snapshot
    end_time = datetime.utcnow()
    scan_duration = (end_time - start_time).total_seconds()
    snapshot_db.status = "completed"
    snapshot_db.finished_at = end_time

    if os_info:
        snapshot_db.os_family = os_info.detected_family
        snapshot_db.os_version = os_info.detected_version
        snapshot_db.os_cpe = os_info.cpe
        snapshot_db.os_confidence = os_info.confidence

    if host_info:
        snapshot_db.mac_address = host_info.mac_address
        snapshot_db.mac_vendor = host_info.vendor
        snapshot_db.latency_ms = host_info.latency_ms

    snapshot_db.webcheck_data = webcheck_data if webcheck_data else None

    db.commit()
    db.refresh(snapshot_db)

    # Recuperar subdominios persistidos
    subdomains_db = db.query(ReconSubdomain).filter(
        ReconSubdomain.snapshot_id == snapshot_db.id
    ).all()
    subdomains = [
        SubdomainInfo(subdomain=s.subdomain, source=s.source or "subfinder")
        for s in subdomains_db
    ]

    # Construir domain_recon schema si procede
    domain_recon: Optional[DomainRecon] = None
    if domain_recon_dict:
        try:
            domain_recon = DomainRecon(**domain_recon_dict)
        except Exception as e:
            logger.warning("DOMAIN_RECON_SCHEMA_ERROR", error=str(e))

    # Calcular flags de superficie
    ssl_active = any(p.port == 443 for p in ports)
    firewall_detected = filtered_count > 0

    recon_data = ReconData(
        ports_discovered=ports,
        os_information=os_info,
        host_information=host_info,
        domain_recon=domain_recon,
        subdomains=subdomains,
    )

    summary = ReconSummary(
        total_ports_open=len(ports),
        total_ports_filtered=filtered_count,
        total_services_detected=len([p for p in ports if p.service != "unknown"]),
        total_subdomains=len(subdomains),
        ssl_active=ssl_active,
        firewall_detected=firewall_detected,
        scan_duration_seconds=scan_duration,
    )

    return ReconSnapshotSchema(
        snapshot_id=snapshot_db.cycle_id,
        target=snapshot_db.target,
        status=snapshot_db.status,
        created_at=snapshot_db.started_at,
        finished_at=snapshot_db.finished_at,
        reconnaissance=recon_data,
        summary=summary,
        webcheck=webcheck_data if webcheck_data else None,
    )
