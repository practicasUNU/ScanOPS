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

class OpenVASClient:
    """Cliente para OpenVAS/GVM real usando protocolo GMP"""

    def __init__(self):
        self.host = settings.openvas_host
        self.port = settings.openvas_port
        self.username = settings.openvas_user
        self.password = settings.openvas_pass
        self._gmp = None
        self._connection = None

    async def _get_gmp(self) -> Gmp:
        """Inicializa y autentica el cliente GMP si no existe"""
        if not GVM_AVAILABLE:
            logger.error("✗ gvm-tools no está instalado. Ejecute 'pip install gvm-tools'")
            raise ImportError("Librería 'gvm' no disponible. Instale python-gvm / gvm-tools.")

        if self._gmp and self._gmp.is_connected():
            return self._gmp

        try:
            logger.info(f"Conectando a OpenVAS en {self.host}:{self.port}...")
            # La conexión TLS puede tardar si hay problemas de red
            self._connection = TLSConnection(hostname=self.host, port=self.port)
            self._gmp = Gmp(connection=self._connection, transform=EtreeTransform())
            
            # Autenticación (operación síncrona en hilo para no bloquear)
            await asyncio.to_thread(self._gmp.authenticate, self.username, self.password)
            logger.info(f"✓ Autenticación exitosa en OpenVAS GVM")
            return self._gmp
        except GvmError as ge:
            logger.error(f"✗ Error de protocolo GVM: {str(ge)}")
            raise ConnectionError(f"Protocolo GVM falló: {ge}")
        except Exception as e:
            logger.error(f"✗ Error de conexión física a OpenVAS: {str(e)}")
            raise ConnectionError(f"No se pudo establecer conexión TLS con OpenVAS: {e}")

    async def disconnect(self):
        """Cerrar sesión"""
        if self._gmp:
            await asyncio.to_thread(self._gmp.disconnect)
            logger.info("✓ OpenVAS desconectado")

    async def create_target(self, target_ips: List[str], target_name: str) -> str:
        """Crea un target real en GVM"""
        gmp = await self._get_gmp()
        hosts = ",".join(target_ips)
        
        response = await asyncio.to_thread(
            gmp.create_target, 
            name=target_name, 
            hosts=target_ips,
            port_list_id="33d0cd10-f6ec-11e0-815c-002264764cea"  # All IANA relevant TCP
        )
        target_id = response.get("id")
        logger.info(f"✓ Target creado: {target_id}")
        return target_id

    async def create_task(self, target_id: str, task_name: str, config_id: str = "daba56c8-73ec-11df-a475-002264764cea") -> str:
        """Crea una tarea real en GVM (Default: Full and fast)"""
        gmp = await self._get_gmp()
        
        # Scanner ID por defecto (OpenVAS Default)
        scanner_id = "08b69003-5fc2-45d1-a82e-ab9734732d91"
        
        response = await asyncio.to_thread(
            gmp.create_task,
            name=task_name,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id
        )
        task_id = response.get("id")
        logger.info(f"✓ Task creada: {task_id}")
        return task_id

    async def start_task(self, task_id: str) -> str:
        """Inicia la tarea y devuelve el ID del reporte"""
        gmp = await self._get_gmp()
        response = await asyncio.to_thread(gmp.start_task, task_id=task_id)
        report_id = response.find(".//report_id").text
        logger.info(f"✓ Task iniciada. Report ID: {report_id}")
        return report_id

    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Obtiene el progreso real de la tarea"""
        gmp = await self._get_gmp()
        response = await asyncio.to_thread(gmp.get_task, task_id=task_id)
        
        task = response.find(".//task")
        status = task.find("status").text
        progress = task.find("progress").text
        
        return {
            "status": status,
            "progress": int(progress) if progress and int(progress) >= 0 else 0
        }

    async def wait_for_task_completion(self, task_id: str, timeout: int = 3600) -> bool:
        """Espera activa hasta que la tarea termine"""
        start_time = datetime.utcnow()
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            status_data = await self.get_task_status(task_id)
            status = status_data["status"]
            progress = status_data["progress"]
            
            if status == "Done":
                return True
            if status in ["Stopped", "Error", "Internal Error"]:
                logger.error(f"✗ Task {task_id} falló con estado: {status}")
                return False
                
            logger.info(f"→ Escaneo OpenVAS progresando: {progress}% (Estado: {status})")
            await asyncio.sleep(30)
            
        return False

    async def get_report_findings(self, report_id: str, asset_id: int) -> List[CVEFinding]:
        """Descarga y parsea el reporte real en formato XML"""
        gmp = await self._get_gmp()
        # Filtro para obtener solo resultados relevantes (niveles High, Medium, Low)
        response = await asyncio.to_thread(gmp.get_report, report_id=report_id, filter_string="levels=hml")
        
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
            
            # Extraer CVEs
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
            
        return findings

    async def scan_asset(self, asset_id: int, asset_ip: str, asset_name: str) -> List[CVEFinding]:
        """Flujo completo de producción: Target -> Task -> Start -> Wait -> Report"""
        try:
            logger.info(f"Iniciando escaneo OpenVAS real para {asset_name} ({asset_ip})")
            
            # 1. Crear Target
            target_id = await self.create_target([asset_ip], f"TGT_{asset_name}_{asset_id}")
            
            # 2. Crear Task
            task_id = await self.create_task(target_id, f"TSK_{asset_name}_{asset_id}")
            
            # 3. Iniciar
            report_id = await self.start_task(task_id)
            
            # 4. Esperar
            if await self.wait_for_task_completion(task_id):
                # 5. Obtener resultados
                findings = await self.get_report_findings(report_id, asset_id)
                logger.info(f"✓ Escaneo finalizado: {len(findings)} vulnerabilidades encontradas")
                return findings
            else:
                logger.error(f"✗ El escaneo no se completó correctamente")
                return []
                
        except Exception as e:
            logger.error(f"✗ Error crítico en scan_asset: {str(e)}")
            return []
        finally:
            await self.disconnect()

# Singleton instance
_client_instance = None

async def get_openvas_client() -> OpenVASClient:
    """Obtiene el cliente configurado desde settings"""
    global _client_instance
    if _client_instance is None:
        _client_instance = OpenVASClient()
    return _client_instance