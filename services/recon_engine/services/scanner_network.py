"""
M2 Recon Engine - Scanner Network Module
========================================
Descubrimiento de activos en la red (Reconocimiento puro).
M2: Hechos técnicos (Puertos, Servicios, Versiones, SO).
NO realiza análisis de vulnerabilidades ni severidades.
"""

import asyncio
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session

from shared.scan_logger import ScanLogger
from shared.database import SessionLocal
from services.recon_engine.models.recon import ReconSnapshot, ReconFinding, ReconSubdomain
from services.recon_engine.models.schemas import (
    ReconSnapshotSchema, PortDiscovery, OSInformation, 
    HostInformation, ReconData, ReconSummary
)

logger = ScanLogger("scanner_network")

async def _run_tool(cmd: List[str]) -> Tuple[str, str, int]:
    """Ejecuta herramienta externa de forma asíncrona."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_bytes, stderr_bytes = await process.communicate()
        return (
            stdout_bytes.decode('utf-8', errors='ignore'),
            stderr_bytes.decode('utf-8', errors='ignore'),
            process.returncode
        )
    except Exception as e:
        logger.error("TOOL_EXECUTION_ERROR", cmd=" ".join(cmd), error=str(e))
        raise

def parse_nmap_xml(xml_output: str) -> Tuple[List[PortDiscovery], Optional[OSInformation], Optional[HostInformation]]:
    """
    Parsea el output XML de Nmap para extraer hechos técnicos.
    M2: Solo reconocimiento.
    """
    ports_discovered = []
    os_info = None
    host_info = None

    if not xml_output:
        return ports_discovered, os_info, host_info

    try:
        root = ET.fromstring(xml_output)
        
        for host in root.findall('host'):
            # Host Information
            status = host.find('status')
            if status is not None and status.get('state') != 'up':
                continue

            address = host.find('address[@addrtype="ipv4"]')
            ip = address.get('addr') if address is not None else "unknown"

            # MAC and Vendor
            mac_addr_elem = host.find('address[@addrtype="mac"]')
            mac_val = mac_addr_elem.get('addr') if mac_addr_elem is not None else None
            vendor_val = mac_addr_elem.get('vendor') if mac_addr_elem is not None else None

            # Latency
            times = host.find('times')
            latency = None
            if times is not None and times.get('srtt'):
                try:
                    latency = float(times.get('srtt')) / 1000.0  # microseconds → ms
                except (ValueError, TypeError):
                    latency = None

            host_info = HostInformation(
                mac_address=mac_val,
                vendor=vendor_val,
                latency_ms=latency
            )

            # Ports
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    state_elem = port_elem.find('state')
                    if state_elem is not None and state_elem.get('state') == 'open':
                        service_elem = port_elem.find('service')
                        
                        port_id = int(port_elem.get('portid'))
                        protocol = port_elem.get('protocol')
                        service_name = service_elem.get('name') if service_elem is not None else "unknown"
                        product = service_elem.get('product') if service_elem is not None else None
                        version = service_elem.get('version') if service_elem is not None else ""
                        extrainfo = service_elem.get('extrainfo') if service_elem is not None else ""
                        
                        parts = [p for p in [product, version, extrainfo] if p and p.strip()]
                        full_version = " ".join(parts) if parts else "unknown"
                        
                        # Confidence based on method
                        conf = 0.7
                        if service_elem is not None:
                            method = service_elem.get('method')
                            if method == 'probed': conf = 0.9
                            elif method == 'table': conf = 0.5

                        ports_discovered.append(PortDiscovery(
                            port=port_id,
                            protocol=protocol,
                            state="open",
                            service=service_name,
                            version=full_version or "unknown",
                            product=product,
                            confidence=conf
                        ))

            # OS Information
            os_elem = host.find('os')
            if os_elem is not None:
                os_match = os_elem.find('osmatch')
                if os_match is not None:
                    os_class = os_match.find('osclass')
                    
                    # Extraer CPE si existe
                    cpe_text = ""
                    if os_class is not None:
                        cpe_elem = os_class.find('cpe')
                        if cpe_elem is not None and cpe_elem.text:
                            cpe_text = cpe_elem.text

                    os_info = OSInformation(
                        detected_family=os_class.get('osfamily', 'Unknown') if os_class is not None else 'Unknown',
                        detected_version=os_match.get('name', 'Unknown'),
                        cpe=cpe_text or None,
                        confidence=float(os_match.get('accuracy', '50')) / 100
                    )

    except Exception as e:
        logger.error("XML_PARSE_ERROR", error=str(e))

    return ports_discovered, os_info, host_info

async def run_nmap_scan(target: str) -> Tuple[List[PortDiscovery], Optional[OSInformation], Optional[HostInformation]]:
    """Ejecuta Nmap con detección de versiones y SO."""
    logger.info("NMAP_RECON_START", target=target)
    
    # -sV: Version detection
    # -O: OS detection
    # -oX: XML output
    # -T4: Aggressive timing
    cmd = ["nmap", "-sV", "-O", "--osscan-limit", "-T4", "-oX", "-", target]
    
    try:
        stdout, stderr, returncode = await _run_tool(cmd)
        if returncode != 0:
            logger.warning("NMAP_RECON_PARTIAL", error=stderr[:200])
        
        return parse_nmap_xml(stdout)
    except FileNotFoundError:
        logger.error("NMAP_NOT_INSTALLED")
        return [], None, None
    except Exception as e:
        logger.error("NMAP_SCAN_ERROR", error=str(e))
        return [], None, None

async def perform_full_recon(snapshot_id: str, target: str, db: Session) -> ReconSnapshotSchema:
    """
    Orquestación completa del reconocimiento M2.
    snapshot_id aquí es el cycle_id (string).
    """
    start_time = datetime.utcnow()

    # 1. Crear o recuperar snapshot usando cycle_id
    snapshot_db = db.query(ReconSnapshot).filter(
        ReconSnapshot.cycle_id == snapshot_id
    ).first()

    if not snapshot_db:
        snapshot_db = ReconSnapshot(
            cycle_id=snapshot_id,
            target=target,
            status="running",
            started_at=start_time
        )
        db.add(snapshot_db)
        db.commit()
        db.refresh(snapshot_db)

    # 2. Ejecutar Nmap
    ports, os_info, host_info = await run_nmap_scan(target)

    # 3. Persistir puertos como ReconFinding (usando schema real)
    for p in ports:
        finding = ReconFinding(
            snapshot_id=snapshot_db.id,            # INTEGER (PK de snapshot)
            host=target,
            port=str(p.port),                      # VARCHAR en BD
            service=p.service,
            version=p.version,
            state=p.state,
            source="nmap",
            first_seen_snapshot_id=snapshot_db.id
        )
        db.add(finding)

    # 4. Actualizar snapshot con OS y host info
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

    db.commit()
    db.refresh(snapshot_db)

    # 5. Construir ReconData para response
    recon_data = ReconData(
        ports_discovered=ports,
        os_information=os_info,
        host_information=host_info
    )

    summary = ReconSummary(
        total_ports_open=len(ports),
        total_services_detected=len([p for p in ports if p.service != "unknown"]),
        scan_duration_seconds=scan_duration
    )

    return ReconSnapshotSchema(
        snapshot_id=snapshot_db.cycle_id,      # cycle_id como string
        target=snapshot_db.target,
        status=snapshot_db.status,
        created_at=snapshot_db.started_at,     # started_at → created_at
        finished_at=snapshot_db.finished_at,
        reconnaissance=recon_data,
        summary=summary
    )
