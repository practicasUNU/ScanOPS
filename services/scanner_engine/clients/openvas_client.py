"""
OpenVAS Client - Scanner Engine M3
Cliente real para OpenVAS/GVM usando la librería oficial python-gvm.
Cumple con ENS Alto [op.exp.3] para la gestión segura de parámetros.
"""

import asyncio
import logging
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
    # gvm not available, using mock/alternate
    # needs: pip install gvm-tools
    GVM_AVAILABLE = False
    TLSConnection = None
    Gmp = None
    EtreeTransform = None
    GvmError = Exception

from shared.config import settings

logger = logging.getLogger(__name__)

@dataclass
class CVEFinding:
    """Hallazgo normalizado desde OpenVAS"""
    asset_id: int
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
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

import time

class OpenVASClient:
    """Cliente para OpenVAS/GVM real usando protocolo GMP"""

    def __init__(self):
        self.host = settings.openvas_host
        self.port = settings.openvas_port
        self.username = settings.openvas_user
        self.password = settings.openvas_pass

    def _run_full_scan(self, asset_id: int, asset_ip: str, asset_name: str) -> List[CVEFinding]:
        """Ejecución síncrona del flujo completo GVM"""
        if not GVM_AVAILABLE:
            logger.error("✗ gvm-tools no está instalado.")
            return []

        try:
            logger.info(f"Conectando a OpenVAS en {self.host}:{self.port}...")
            connection = TLSConnection(hostname=self.host, port=self.port)
            transform = EtreeTransform()

            with Gmp(connection=connection, transform=transform) as gmp:
                # Autenticación automática via context manager / call explicit
                gmp.authenticate(self.username, self.password)
                logger.info(f"✓ Autenticación exitosa en OpenVAS GVM")

                # 1. Crear Target
                target_name = f"TGT_{asset_name}_{asset_id}"
                response = gmp.create_target(
                    name=target_name,
                    hosts=[asset_ip],
                    port_list_id="33d0cd10-f6ec-11e0-815c-002264764cea"
                )
                target_id = response.get("id")
                logger.info(f"✓ Target creado: {target_id}")

                # 2. Crear Task
                task_name = f"TSK_{asset_name}_{asset_id}"
                # Scanner ID por defecto (OpenVAS Default)
                scanner_id = "08b69003-5fc2-45d1-a82e-ab9734732d91"
                config_id = "daba56c8-73ec-11df-a475-002264764cea" # Full and fast

                response = gmp.create_task(
                    name=task_name,
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id
                )
                task_id = response.get("id")
                logger.info(f"✓ Task creada: {task_id}")

                # 3. Iniciar
                response = gmp.start_task(task_id=task_id)
                report_id = response.find(".//report_id").text
                logger.info(f"✓ Task iniciada. Report ID: {report_id}")

                # 4. Esperar (Sync loop)
                finished = False
                timeout = 3600
                start_time = datetime.utcnow()
                while (datetime.utcnow() - start_time).total_seconds() < timeout:
                    resp = gmp.get_task(task_id=task_id)
                    task_elem = resp.find(".//task")
                    status = task_elem.find("status").text
                    progress_text = task_elem.find("progress").text
                    progress = int(progress_text) if progress_text and int(progress_text) >= 0 else 0

                    if status == "Done":
                        finished = True
                        break
                    if status in ["Stopped", "Error", "Internal Error"]:
                        logger.error(f"✗ Task {task_id} falló con estado: {status}")
                        return []

                    logger.info(f"→ Escaneo OpenVAS progresando: {progress}% (Estado: {status})")
                    time.sleep(30)

                if not finished:
                    logger.error(f"✗ Timeout esperando escaneo OpenVAS para {asset_ip}")
                    return []

                # 5. Obtener resultados
                logger.info(f"Descargando resultados para reporte {report_id}")
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
                    severity_text = res.find("threat").text
                    cves = nvt.find("cve").text if nvt.find("cve") is not None else None

                    finding = CVEFinding(
                        asset_id=asset_id,
                        title=res.find("name").text,
                        description=nvt.find("description").text if nvt.find("description") is not None else "",
                        severity=severity_map.get(severity_text, "INFO"),
                        cvss_score=float(res.find("severity").text) if res.find("severity") is not None else 0.0,
                        cve_id=cves.split(",")[0] if cves and cves != "NOCVE" else None,
                        evidence=res.find("description").text if res.find("description") is not None else "Ver reporte completo en GVM",
                        remediation=nvt.find("solution").text if nvt.find("solution") is not None else "No especificada"
                    )
                    findings.append(finding)

                logger.info(f"✓ Escaneo OpenVAS finalizado: {len(findings)} vulnerabilidades encontradas")
                return findings

        except GvmError as ge:
            logger.error(f"✗ Error de protocolo GVM: {str(ge)}")
            return []
        except Exception as e:
            logger.error(f"✗ Error crítico en escaneo OpenVAS: {str(e)}")
            return []

    async def scan_asset(self, asset_id: int, asset_ip: str, asset_name: str) -> List[CVEFinding]:
        """Punto de entrada asíncrono que delega a un hilo síncrono"""
        logger.info(f"Iniciando escaneo OpenVAS real para {asset_name} ({asset_ip})")
        return await asyncio.to_thread(self._run_full_scan, asset_id, asset_ip, asset_name)

# Singleton instance
_client_instance = None

async def get_openvas_client() -> OpenVASClient:
    """Obtiene el cliente configurado desde settings"""
    global _client_instance
    if _client_instance is None:
        _client_instance = OpenVASClient()
    return _client_instance