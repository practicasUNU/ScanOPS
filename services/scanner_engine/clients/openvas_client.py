"""
OpenVAS Client - Scanner Engine M3
Cliente real para OpenVAS/GVM usando la librería oficial python-gvm.
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import xml.etree.ElementTree as ET

try:
    from gvm.connections import TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    from gvm.errors import GvmError
    GVM_AVAILABLE = True
except ImportError:
    GVM_AVAILABLE = False
    TLSConnection = None
    Gmp = None
    EtreeTransform = None
    GvmError = Exception

from shared.config import settings

logger = logging.getLogger(__name__)

@dataclass
class CVEFinding:
    asset_id: int
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    cve_id: Optional[str]
    evidence: str
    remediation: str
    scanner: str = "OpenVAS"
    created_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "scanner": self.scanner,
            "created_at": self.created_at.isoformat(),
        }


class OpenVASClient:

    def __init__(self):
        self.host = settings.openvas_host
        self.port = settings.openvas_port
        self.username = settings.openvas_user
        self.password = settings.openvas_pass

    def _run_full_scan(self, asset_id: int, asset_ip: str, asset_name: str) -> List[CVEFinding]:
        if not GVM_AVAILABLE:
            logger.error("gvm-tools no esta instalado.")
            return []

        try:
            logger.info(f"Conectando a OpenVAS en {self.host}:{self.port}...")
            connection = TLSConnection(hostname=self.host, port=self.port)
            transform = EtreeTransform()

            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                logger.info("Autenticacion exitosa en OpenVAS GVM")

                target_name = f"TGT_{asset_name}_{asset_id}"
                response = gmp.create_target(
                    name=target_name,
                    hosts=[asset_ip],
                    port_list_id="4a4717fe-57d2-11e1-9a26-406186ea4fc5"
                )
                logger.info(f"Target response attribs: {response.attrib}")
                target_id = response.attrib.get("id")
                if not target_id:
                    logger.error(f"No se obtuvo target_id. Response: {ET.tostring(response)}")
                    return []
                logger.info(f"Target creado: {target_id}")

                task_name = f"TSK_{asset_name}_{asset_id}"
                scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
                config_id = "daba56c8-73ec-11df-a475-002264764cea"

                response = gmp.create_task(
                    name=task_name,
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id
                )
                logger.info(f"Task response attribs: {response.attrib}")
                task_id = response.attrib.get("id")
                if not task_id:
                    logger.error(f"No se obtuvo task_id. Response: {ET.tostring(response)}")
                    return []
                logger.info(f"Task creada: {task_id}")

                response = gmp.start_task(task_id=task_id)
                report_id_elem = response.find(".//report_id")
                if report_id_elem is None:
                    logger.error("No se obtuvo report_id")
                    return []
                report_id = report_id_elem.text
                logger.info(f"Task iniciada. Report ID: {report_id}")

                timeout = 3600
                start_time = datetime.utcnow()
                while (datetime.utcnow() - start_time).total_seconds() < timeout:
                    resp = gmp.get_task(task_id=task_id)
                    task_elem = resp.find(".//task")
                    status = task_elem.find("status").text
                    progress_text = task_elem.find("progress").text
                    progress = int(progress_text) if progress_text and int(progress_text) >= 0 else 0

                    if status == "Done":
                        break
                    if status in ["Stopped", "Error", "Internal Error"]:
                        logger.error(f"Task {task_id} fallo con estado: {status}")
                        return []

                    logger.info(f"OpenVAS progresando: {progress}% (Estado: {status})")
                    time.sleep(30)
                else:
                    logger.error(f"Timeout OpenVAS para {asset_ip}")
                    return []

                response = gmp.get_report(report_id=report_id, filter_string="levels=hml")
                findings = []
                severity_map = {
                    "High": "HIGH",
                    "Medium": "MEDIUM",
                    "Low": "LOW",
                    "Log": "INFO",
                    "Debug": "INFO"
                }

                results = response.findall(".//result")
                for res in results:
                    nvt = res.find("nvt")
                    threat_elem = res.find("threat")
                    severity_text = threat_elem.text if threat_elem is not None else "Log"
                    cve_elem = nvt.find("cve") if nvt is not None else None
                    cves = cve_elem.text if cve_elem is not None else None
                    name_elem = res.find("name")
                    desc_elem = res.find("description")
                    sev_elem = res.find("severity")

                    finding = CVEFinding(
                        asset_id=asset_id,
                        title=name_elem.text if name_elem is not None else "Unknown",
                        description=desc_elem.text if desc_elem is not None else "",
                        severity=severity_map.get(severity_text, "INFO"),
                        cvss_score=float(sev_elem.text) if sev_elem is not None else 0.0,
                        cve_id=cves.split(",")[0] if cves and cves != "NOCVE" else None,
                        evidence=desc_elem.text if desc_elem is not None else "",
                        remediation=""
                    )
                    findings.append(finding)

                logger.info(f"OpenVAS finalizado: {len(findings)} vulnerabilidades")
                return findings

        except GvmError as ge:
            logger.error(f"Error GVM: {str(ge)}")
            return []
        except Exception as e:
            logger.error(f"Error OpenVAS: {str(e)}")
            return []

    async def scan_asset(self, asset_id: int, asset_ip: str, asset_name: str) -> List[CVEFinding]:
        logger.info(f"Iniciando escaneo OpenVAS para {asset_name} ({asset_ip})")
        return await asyncio.to_thread(self._run_full_scan, asset_id, asset_ip, asset_name)


_client_instance = None

async def get_openvas_client() -> OpenVASClient:
    global _client_instance
    if _client_instance is None:
        _client_instance = OpenVASClient()
    return _client_instance
