"""Nuclei CLI-based vulnerability scanner client."""

import asyncio
import json
import logging
import subprocess
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
    scanner: str = "Nuclei"
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


class NucleiClient:
    """Client for Nuclei template-based scanning."""

    def __init__(
        self,
        templates_path: str = "/app/templates/nuclei",
        timeout: int = 1800,
    ):
        """Initialize Nuclei client."""
        self.templates_path = templates_path
        self.timeout = timeout

    async def scan_asset(
        self, asset_id: int, asset_ip: str, asset_name: str
    ) -> List[Finding]:
        """Execute Nuclei scan on asset."""
        findings = []

        try:
            logger.info(f"→ Nuclei scan iniciado para {asset_id} ({asset_ip})")

            target_url = asset_ip if asset_ip.startswith("http") else f"http://{asset_ip}"
            
            # Mock scan por ahora
            findings = await self._mock_nuclei_scan(asset_id, target_url)

            logger.info(f"✓ Nuclei completado: {len(findings)} hallazgos")

        except subprocess.TimeoutExpired:
            logger.error(f"✗ Nuclei timeout para asset {asset_id}")
        except FileNotFoundError:
            logger.error("✗ Nuclei no encontrado en PATH")
        except Exception as e:
            logger.error(f"✗ Error Nuclei: {str(e)}")

        return findings

    async def _mock_nuclei_scan(self, asset_id: int, target_url: str) -> List[Finding]:
        """Mock Nuclei scan results."""
        await asyncio.sleep(0.1)

        mock_data = [
            {
                "name": "SQL Injection",
                "severity": "CRITICAL",
                "description": "Potential SQL injection detected",
                "host": target_url,
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "description": "Possible XSS vulnerability",
                "host": target_url,
            },
        ]

        findings = []
        for item in mock_data:
            finding = Finding(
                asset_id=asset_id,
                title=item.get("name", "Unknown"),
                description=item.get("description", ""),
                severity=item.get("severity", "LOW"),
                evidence=f"Host: {item.get('host', 'N/A')}",
                remediation="Consult security guidelines",
            )
            findings.append(finding)

        return findings

    async def is_available(self) -> bool:
        """Check if Nuclei is installed."""
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(subprocess.run, ["nuclei", "-version"], capture_output=True),
                timeout=5,
            )
            available = result.returncode == 0
            if available:
                logger.info("✓ Nuclei disponible")
            return available
        except Exception:
            logger.warning("✗ Nuclei no disponible")
            return False