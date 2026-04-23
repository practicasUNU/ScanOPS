"""ZAP (OWASP Zed Attack Proxy) client for web vulnerability scanning."""

import asyncio
import logging
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime
from zapv2 import ZAPv2

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
        self.host = host
        self.port = port
        self.timeout = timeout
        self.zap = ZAPv2(proxies={'http': f'http://{host}:{port}', 'https': f'http://{host}:{port}'})

    async def scan_asset(self, asset_id: int, asset_url: str, asset_name: str) -> List[Finding]:
        findings = []
        try:
            if not asset_url.startswith("http"):
                asset_url = f"http://{asset_url}"
            logger.info(f"→ ZAP scan: {asset_id} ({asset_url})")
            
            # Spider
            spider_id = await asyncio.to_thread(self.zap.spider.scan, url=asset_url)
            await self._wait_for_scan(spider_id)
            
            # Active scan
            scan_id = await asyncio.to_thread(self.zap.ascan.scan, url=asset_url)
            await self._wait_for_scan(scan_id)
            
            # Get alerts
            alerts = await asyncio.to_thread(self.zap.alert.alerts, baseurl=asset_url)
            for alert in alerts:
                finding = Finding(
                    asset_id=asset_id,
                    title=alert.get("name", "Unknown"),
                    description=alert.get("description", ""),
                    severity=alert.get("riskcode", "1"),
                    evidence=f"URL: {asset_url}",
                    remediation=alert.get("solution", "Review"),
                )
                findings.append(finding)
            
            logger.info(f"✓ ZAP: {len(findings)} findings")
        except Exception as e:
            logger.error(f"✗ ZAP error: {e}")
        
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
        try:
            while True:
                status = await asyncio.to_thread(self.zap.ascan.status, id=scan_id) if scan_id.isdigit() else await asyncio.to_thread(self.zap.spider.status)
                if int(status) == 100:
                    logger.info(f"✓ Scan {scan_id} completed")
                    return True
                logger.debug(f"Waiting... {status}%")
                await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"✗ Error: {e}")
            return False

    async def is_available(self) -> bool:
        try:
            version = await asyncio.to_thread(self.zap.core.version)
            available = version is not None
            logger.info("✓ ZAP available") if available else logger.warning("✗ ZAP unavailable")
            return available
        except Exception as e:
            logger.warning(f"✗ ZAP unavailable: {e}")
            return False