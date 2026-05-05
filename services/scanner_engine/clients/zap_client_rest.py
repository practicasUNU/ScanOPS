"""
ZAP (OWASP Zed Attack Proxy) REST Client - Scanner Engine M3
Implementación directa vía REST API para evitar dependencia de zapv2.
"""

import asyncio
import logging
import httpx
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from shared.config import settings

logger = logging.getLogger(__name__)

@dataclass
class ZAPFinding:
    """Hallazgo normalizado desde ZAP"""
    asset_id: int
    title: str
    description: str
    severity: str  # HIGH, MEDIUM, LOW, INFO
    cve_id: Optional[str]
    evidence: str
    remediation: str
    scanner: str = "ZAP"
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
            "cve_id": self.cve_id,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "scanner": self.scanner,
            "created_at": self.created_at.isoformat(),
        }

class ZAPClientREST:
    """Cliente para OWASP ZAP usando la API REST nativa"""

    def __init__(self):
        import os
        self.host = os.environ.get("ZAP_HOST", "scanops-zap")
        self.port = int(os.environ.get("ZAP_PORT", "8080"))
        self.api_key = os.environ.get("ZAP_API_KEY", "")
        self.base_url = f"http://{self.host}:{self.port}/JSON"
        self.client = httpx.AsyncClient(timeout=60.0)

    async def _get(self, component: str, view: str, params: Dict = None) -> Dict:
        """Helper para llamadas GET a la API de ZAP"""
        if params is None: params = {}
        if self.api_key: params["apikey"] = self.api_key
        
        url = f"{self.base_url}/{component}/view/{view}/"
        resp = await self.client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    async def _post(self, component: str, action: str, params: Dict = None) -> Dict:
        """Helper para llamadas POST a la API de ZAP"""
        if params is None: params = {}
        if self.api_key: params["apikey"] = self.api_key
        
        url = f"{self.base_url}/{component}/action/{action}/"
        resp = await self.client.post(url, params=params)
        resp.raise_for_status()
        return resp.json()

    async def new_session(self, name: str = "ScanOPS_Session"):
        """Inicia una nueva sesión en ZAP"""
        try:
            await self._post("core", "newSession", {"name": name, "overwrite": "true"})
            logger.info(f"✓ Nueva sesión ZAP creada: {name}")
        except Exception as e:
            logger.error(f"✗ Error creando sesión ZAP: {e}")

    async def start_spider(self, url: str) -> str:
        """Inicia el Spider de ZAP"""
        resp = await self._post("spider", "scan", {"url": url})
        return resp.get("scan")

    async def start_active_scan(self, url: str) -> str:
        """Inicia el Active Scan de ZAP"""
        resp = await self._post("ascan", "scan", {"url": url})
        return resp.get("scan")

    async def wait_for_scan(self, component: str, scan_id: str, timeout: int = 1800):
        """Espera a que un scan (spider o ascan) termine"""
        start_time = datetime.utcnow()
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            data = await self._get(component, "status", {"scanId": scan_id})
            status = int(data.get("status", 0))
            if status >= 100:
                logger.info(f"✓ ZAP {component} completado")
                return True
            logger.info(f"→ ZAP {component} progresando: {status}%")
            await asyncio.sleep(10)
        return False

    async def get_alerts(self, base_url: str) -> List[Dict]:
        """Obtiene las alertas detectadas para una URL"""
        data = await self._get("core", "alerts", {"baseurl": base_url})
        return data.get("alerts", [])

    async def scan_asset(self, asset_id: int, asset_url: str) -> List[ZAPFinding]:
        """Flujo completo de escaneo DAST: Session -> Spider -> Ascan -> Alerts"""
        if not asset_url.startswith("http"):
            asset_url = f"http://{asset_url}"
            
        # Connectivity check
        try:
            async with httpx.AsyncClient(timeout=5.0) as check:
                await check.get(f"http://{self.host}:{self.port}/JSON/core/view/version/")
        except Exception as e:
            logger.error(f"✗ ZAP no disponible en {self.host}:{self.port}: {e}")
            return []
            
        try:
            # 1. Preparar sesión
            await self.new_session(f"Scan_{asset_id}")
            
            # 2. Spider
            logger.info(f"→ Iniciando ZAP Spider para {asset_url}")
            spider_id = await self.start_spider(asset_url)
            await self.wait_for_scan("spider", spider_id)
            
            # 3. Active Scan
            logger.info(f"→ Iniciando ZAP Active Scan para {asset_url}")
            ascan_id = await self.start_active_scan(asset_url)
            await self.wait_for_scan("ascan", ascan_id)
            
            # 4. Obtener Alertas
            alerts = await self.get_alerts(asset_url)
            
            findings = []
            risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
            
            for alert in alerts:
                finding = ZAPFinding(
                    asset_id=asset_id,
                    title=alert.get("alert", "DAST Finding"),
                    description=alert.get("description", ""),
                    severity=risk_map.get(alert.get("risk"), "INFO"),
                    cve_id=None, # ZAP no suele dar CVE directamente sin plugins
                    evidence=f"URL: {alert.get('url')} | Param: {alert.get('param')}",
                    remediation=alert.get("solution", "Consult OWASP Top 10")
                )
                findings.append(finding)
            
            return findings
        except Exception as e:
            logger.error(f"✗ Error en escaneo ZAP DAST: {e}")
            return []
        finally:
            await self.client.aclose()
