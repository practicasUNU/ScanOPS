"""ZAP (OWASP Zed Attack Proxy) client for web vulnerability scanning."""

import asyncio
import logging
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Normalizado finding"""
    asset_id: int
    title: str
    description: str
    severity: str
    cve_id: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    scanner: str = "ZAP"
    created_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()

    def to_dict(self):
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


class ZAPClient:
    """Client for OWASP ZAP web scanning."""

    def __init__(
        self,
        host: str = "zap",
        port: int = 8080,
        timeout: int = 1800,
    ):
        """Initialize ZAP client."""
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"

    async def scan_asset(
        self, asset_id: int, asset_url: str, asset_name: str
    ) -> List[Finding]:
        """Execute ZAP scan on asset."""
        findings = []

        try:
            logger.info(f"→ ZAP scan iniciado para {asset_id} ({asset_url})")

            # Asegurar que URL tiene protocolo
            if not asset_url.startswith("http"):
                asset_url = f"http://{asset_url}"

            # Mock scan por ahora
            findings = await self._mock_zap_scan(asset_id, asset_url)

            logger.info(f"✓ ZAP completado: {len(findings)} hallazgos")

        except Exception as e:
            logger.error(f"✗ Error ZAP: {str(e)}")

        return findings

    async def _mock_zap_scan(self, asset_id: int, asset_url: str) -> List[Finding]:
        """Mock ZAP scan results."""
        await asyncio.sleep(0.1)

        mock_data = [
            {
                "name": "Missing HTTP Security Header",
                "severity": "MEDIUM",
                "description": "Missing X-Frame-Options header",
                "solution": "Add X-Frame-Options: DENY",
            },
            {
                "name": "Insecure HTTP Methods",
                "severity": "HIGH",
                "description": "Server allows PUT and DELETE methods",
                "solution": "Disable unnecessary HTTP methods",
            },
        ]

        findings = []
        for item in mock_data:
            finding = Finding(
                asset_id=asset_id,
                title=item.get("name", "Unknown"),
                description=item.get("description", ""),
                severity=item.get("severity", "LOW"),
                evidence=f"URL: {asset_url}",
                remediation=item.get("solution", "Consult security guidelines"),
            )
            findings.append(finding)

        return findings

    async def _spider(self, target_url: str) -> bool:
        """Spider target URL to discover resources."""
        try:
            logger.debug(f"Spidering {target_url}")
            return True
        except Exception as e:
            logger.error(f"Spidering failed: {e}")
            return False

    async def _active_scan(self, target_url: str) -> Optional[str]:
        """Start active scan and return scan ID."""
        try:
            logger.debug(f"Starting active scan for {target_url}")
            return "scan_12345"
        except Exception as e:
            logger.error(f"Active scan start failed: {e}")
            return None

    async def _wait_for_scan(self, scan_id: str) -> bool:
        """Wait for scan to complete."""
        try:
            logger.debug(f"Waiting for scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Scan wait failed: {e}")
            return False

    async def is_available(self) -> bool:
        """Check if ZAP is available."""
        try:
            logger.info("✓ ZAP disponible (mock)")
            return True
        except Exception:
            logger.warning("✗ ZAP no disponible")
            return False