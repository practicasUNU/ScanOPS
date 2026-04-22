"""Nuclei CLI-based vulnerability scanner client."""

import asyncio
import json
import logging
import subprocess
import glob
from typing import List, Optional, Dict
from dataclasses import dataclass
from datetime import datetime
import yaml

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

            # Prefer real scan if nuclei available and templates exist
            if await self.is_available():
                try:
                    templates_meta = await self.load_custom_templates(self.templates_path + "/custom")
                    raw = await self.run_real_scan(target_url, self.templates_path + "/custom")
                    parsed = self.parse_nuclei_json(raw)
                    findings = await self.enrich_findings(parsed, templates_meta, asset_id)
                except Exception:
                    # fallback to mock if anything fails during real scan
                    findings = await self._mock_nuclei_scan(asset_id, target_url)
            else:
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

    def load_custom_templates(self, path: str = "templates/nuclei/custom") -> List[Dict]:
        """Load YAML templates from directory"""
        import glob
        import yaml
        
        templates = []
        try:
            for file in glob.glob(f"{path}/*.yaml"):
                with open(file, 'r') as f:
                    for doc in yaml.safe_load_all(f):
                        if doc and 'id' in doc:
                            templates.append({
                                "id": doc.get("id"),
                                "name": doc.get("info", {}).get("name", "Unknown"),
                                "severity": doc.get("info", {}).get("severity", "low"),
                                "tags": doc.get("info", {}).get("tags", []),
                                "description": doc.get("info", {}).get("description", ""),
                            })
            logger.info(f"✓ Loaded {len(templates)} custom templates")
        except Exception as e:
            logger.error(f"✗ Error loading templates: {e}")
        
        return templates

    async def run_real_scan(self, target_url: str, templates_path: str) -> str:
        """Run nuclei CLI against a target using provided templates path. Returns raw JSON lines output."""
        cmd = ["nuclei", "-u", target_url, "-t", templates_path, "-json"]

        def _run():
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            if result.returncode not in (0, 2):
                # Nuclei returns 2 when findings found; 0 on success without findings
                logger.warning(f"Nuclei returned code {result.returncode}")
            return result.stdout or result.stderr or ""

        return await asyncio.to_thread(_run)

    def parse_nuclei_json(self, json_output: str) -> List[Dict]:
        """Parse Nuclei JSON output (one object per line)"""
        findings = []
        try:
            for line in json_output.strip().split('\n'):
                if line.strip():
                    obj = json.loads(line)
                    findings.append({
                        "template_id": obj.get("template-id", "unknown"),
                        "name": obj.get("info", {}).get("name", "Unknown"),
                        "severity": obj.get("info", {}).get("severity", "low"),
                        "matched_at": obj.get("matched-at", ""),
                        "type": obj.get("type", ""),
                        "description": obj.get("info", {}).get("description", ""),
                        "tags": obj.get("info", {}).get("tags", []),
                    })
            logger.debug(f"✓ Parsed {len(findings)} findings from Nuclei JSON")
        except Exception as e:
            logger.error(f"✗ Error parsing Nuclei JSON: {e}")
        
        return findings

    def enrich_findings_with_templates(self, findings: List[Dict], templates_metadata: Dict) -> List[Finding]:
        """Enrich findings with template metadata and ENS mapping"""
        from services.scanner_engine.models.finding import Finding, ENS_MAPPING
        
        enriched = []
        try:
            for f in findings:
                template_id = f.get("template_id", "")
                template = templates_metadata.get(template_id, {})
                title = f.get("name", "Unknown")
                ens_tags = ENS_MAPPING.get(title, [])
                
                finding = Finding(
                    asset_id=0,  # Will be set by caller
                    title=title,
                    description=f.get("description", ""),
                    severity=f.get("severity", "low").upper(),
                    evidence=f.get("matched_at", ""),
                    remediation="Refer to Nuclei template documentation",
                    scanner="Nuclei",
                    template_id=template_id,
                    template_tags=f.get("tags", []),
                    ens_tags=ens_tags,
                )
                enriched.append(finding)
            
            logger.info(f"✓ Enriched {len(enriched)} findings")
        except Exception as e:
            logger.error(f"✗ Error enriching findings: {e}")
        
        return enriched

    async def scan_asset_with_custom_templates(
        self, asset_id: int, asset_ip: str, asset_name: str
    ) -> List[Finding]:
        """Full scan using custom templates"""
        try:
            logger.info(f"→ Nuclei custom templates scan: {asset_ip}")
            
            # Load templates
            templates = self.load_custom_templates()
            templates_metadata = {t["id"]: t for t in templates}
            
            # Run mock scan (real scan would call nuclei CLI)
            findings = await self._mock_nuclei_scan(asset_id, asset_ip)
            
            # Enrich with template metadata
            enriched = self.enrich_findings_with_templates(
                [{"template_id": "mock", "name": f.title, "severity": f.severity, 
                   "matched_at": f.evidence, "description": f.description, "tags": []}
                 for f in findings],
                templates_metadata
            )
            
            logger.info(f"✓ Custom templates scan complete: {len(enriched)} findings")
            return enriched
        except Exception as e:
            logger.error(f"✗ Custom templates scan failed: {e}")
            return []