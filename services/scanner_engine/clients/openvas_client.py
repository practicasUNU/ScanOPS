"""OpenVAS Client - Scanner Engine M3"""
import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import httpx
import xml.etree.ElementTree as ET

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


class OpenVASClient:
    """Cliente para OpenVAS/GVM"""

    def __init__(
        self,
        host: str,
        port: int = 9392,
        username: str = "admin",
        password: str = "admin",
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout)
        self.base_url = f"https://{host}:{port}"
        self.is_connected = False

    async def connect(self) -> bool:
        try:
            resp = await self.session.get(f"{self.base_url}/gmp", auth=(self.username, self.password))
            self.is_connected = resp.status_code == 200
            logger.info("✓ OpenVAS connected" if self.is_connected else "✗ OpenVAS failed")
            return self.is_connected
        except Exception as e:
            logger.error(f"✗ Error: {e}")
            return False

    async def disconnect(self):
        """Cerrar sesión"""
        self.is_connected = False
        logger.info("✓ OpenVAS desconectado")

    async def get_available_scanners(self) -> Dict[str, str]:
        """Obtener scanners disponibles"""
        if not self.is_connected:
            return {}

        try:
            scanners = {
                "08b69003-5fc2-45d1-a82e-ab9734732d91": "Full and fast",
                "d2590a07-56a8-4249-a11c-1e6c9eb4eee6": "Full and very deep",
                "daba56c8-73ec-11df-a475-002264764cea": "Full and deep",
            }
            logger.info(f"✓ Scanners disponibles: {list(scanners.values())}")
            return scanners
        except Exception as e:
            logger.error(f"✗ Error obteniendo scanners: {str(e)}")
            return {}

    async def create_target(self, target_ips: List[str], target_name: str, allow_simultaneous_ips: bool = False) -> Optional[str]:
        if not self.is_connected:
            logger.error("OpenVAS not connected")
            return None
        try:
            hosts = ",".join(target_ips)
            xml_body = f'<create_target><name>{target_name}</name><hosts>{hosts}</hosts></create_target>'
            resp = await self.session.post(f"{self.base_url}/gmp", data=xml_body, auth=(self.username, self.password))
            root = ET.fromstring(resp.text)
            target_id = root.find(".//target/uuid").text if root.find(".//target/uuid") is not None else None
            logger.info(f"✓ Target created: {target_id}")
            return target_id
        except Exception as e:
            logger.error(f"✗ Error: {e}")
            return None

    async def create_task(self, target_id: str, task_name: str, scanner_id: str = "08b69003-5fc2-45d1-a82e-ab9734732d91") -> Optional[str]:
        if not self.is_connected:
            return None
        try:
            xml_body = f'<create_task><name>{task_name}</name><target id="{target_id}"/><config id="{scanner_id}"/></create_task>'
            resp = await self.session.post(f"{self.base_url}/gmp", data=xml_body, auth=(self.username, self.password))
            root = ET.fromstring(resp.text)
            task_id = root.find(".//task/uuid").text if root.find(".//task/uuid") is not None else None
            logger.info(f"✓ Task created: {task_id}")
            return task_id
        except Exception as e:
            logger.error(f"✗ Error: {e}")
            return None

    async def start_task(self, task_id: str) -> bool:
        if not self.is_connected:
            return False
        try:
            xml_body = f'<start_task task_id="{task_id}"/>'
            resp = await self.session.post(f"{self.base_url}/gmp", data=xml_body, auth=(self.username, self.password))
            logger.info(f"✓ Task started: {task_id}")
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"✗ Error: {e}")
            return False

    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        if not self.is_connected:
            return {"status": "DISCONNECTED"}
        try:
            resp = await self.session.get(f"{self.base_url}/gmp?cmd=get_tasks&task_id={task_id}", auth=(self.username, self.password))
            root = ET.fromstring(resp.text)
            status = root.find(".//task/status").text if root.find(".//task/status") is not None else "Running"
            progress = root.find(".//task/progress").text if root.find(".//task/progress") is not None else "0"
            logger.debug(f"Status {task_id}: {status} {progress}%")
            return {"task_id": task_id, "status": status, "progress": int(progress) if progress.isdigit() else 0, "report_count": 1}
        except Exception as e:
            logger.error(f"✗ Error: {e}")
            return {}

    async def wait_for_task_completion(
        self,
        task_id: str,
        max_wait: int = 3600,
        poll_interval: int = 30,
    ) -> bool:
        """Esperar a que se complete una tarea"""
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < max_wait:
            status = await self.get_task_status(task_id)
            
            if status.get("status") == "Done":
                logger.info(f"✓ Tarea {task_id} completada")
                return True
            
            logger.info(f"→ Esperando... {status.get('progress', 0)}%")
            await asyncio.sleep(poll_interval)
        
        logger.warning(f"✗ Timeout esperando tarea {task_id}")
        return False

    async def get_task_report(self, task_id: str) -> Optional[Dict[str, Any]]:
        if not self.is_connected:
            return None
        try:
            resp = await self.session.get(f"{self.base_url}/gmp?cmd=get_reports&task_id={task_id}", auth=(self.username, self.password))
            root = ET.fromstring(resp.text)
            results = []
            for result in root.findall(".//result"):
                name = result.find("name").text if result.find("name") is not None else "Unknown"
                severity = result.find("severity").text if result.find("severity") is not None else "0"
                cve = result.find("cve").text if result.find("cve") is not None else None
                host = result.find("host").text if result.find("host") is not None else "N/A"
                cvss = float(severity) if severity.replace(".", "").isdigit() else 0
                results.append({"name": name, "severity": severity, "cvss": cvss, "cve": cve, "host": host, "description": ""})
            logger.info(f"✓ Report: {len(results)} findings")
            return {"task_id": task_id, "created": datetime.utcnow().isoformat(), "results": results}
        except Exception as e:
            logger.error(f"✗ Error: {e}")
            return None

    async def normalize_findings(
        self,
        report: Dict[str, Any],
        asset_id: int,
    ) -> List[CVEFinding]:
        """Normalizar hallazgos de OpenVAS al schema común"""
        findings = []
        
        severity_map = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "None": "INFO",
        }
        
        for result in report.get("results", []):
            finding = CVEFinding(
                asset_id=asset_id,
                title=result.get("name", "Unknown"),
                description=result.get("description", ""),
                severity=severity_map.get(result.get("severity"), "INFO"),
                cvss_score=result.get("cvss"),
                cve_id=result.get("cve"),
                evidence=f"Host: {result.get('host', 'N/A')}",
                remediation="Refer to vendor guidance or CVE details",
            )
            findings.append(finding)
        
        logger.info(f"✓ Normalizados {len(findings)} hallazgos")
        return findings

    async def scan_asset(
        self,
        asset_id: int,
        asset_ip: str,
        asset_name: str,
    ) -> List[CVEFinding]:
        """Ejecutar escaneo completo de un activo"""
        if not self.is_connected:
            logger.error("OpenVAS no conectado")
            return []

        try:
            # 1. Crear target
            target_id = await self.create_target(
                target_ips=[asset_ip],
                target_name=f"Target_{asset_name}_{asset_id}",
            )
            if not target_id:
                return []

            # 2. Crear tarea
            task_id = await self.create_task(
                target_id=target_id,
                task_name=f"Scan_{asset_name}_{asset_id}",
            )
            if not task_id:
                return []

            # 3. Iniciar escaneo
            if not await self.start_task(task_id):
                return []

            # 4. Esperar a completación
            if not await self.wait_for_task_completion(task_id):
                logger.warning(f"Escaneo de {asset_name} no completado en tiempo")
                return []

            # 5. Obtener reporte
            report = await self.get_task_report(task_id)
            if not report:
                return []

            # 6. Normalizar hallazgos
            findings = await self.normalize_findings(report, asset_id)

            logger.info(
                f"✓ Escaneo completado para {asset_name}: {len(findings)} hallazgos"
            )
            return findings

        except Exception as e:
            logger.error(f"✗ Error escaneando {asset_name}: {str(e)}")
            return []


# Global client instance
openvas_client = None


async def get_openvas_client() -> OpenVASClient:
    """Obtener instancia global de OpenVAS client"""
    global openvas_client
    if openvas_client is None:
        openvas_client = OpenVASClient(
            host="openvas",
            port=9392,
            username="admin",
            password="admin",
        )
        await openvas_client.connect()
    return openvas_client