"""Finding models and normalizers for vulnerability scanning results."""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class SeverityLevel(str, Enum):
    """CVSS severity classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerType(str, Enum):
    """Scanner source identification."""
    OPENVAS = "OpenVAS"
    NUCLEI = "Nuclei"
    ZAP = "ZAP"


class Finding(BaseModel):
    """Normalized vulnerability finding across all scanners."""
    asset_id: int
    title: str
    description: str
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    evidence: str
    remediation: str
    scanner: ScannerType
    ens_mapping: List[str] = Field(default_factory=list)  # ["op.exp.2", "mp.info.3"]
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return self.dict(by_alias=True)


def normalize_cvss_score(score: Optional[float]) -> Optional[float]:
    """Validate and normalize CVSS score (0.0-10.0)."""
    if score is None:
        return None
    score = float(score)
    if 0.0 <= score <= 10.0:
        return round(score, 1)
    logger.warning(f"Invalid CVSS score: {score}, returning None")
    return None


def normalize_severity_openvvas(severity: str) -> SeverityLevel:
    """Map OpenVAS severity to standard level."""
    severity_map = {
        "log": SeverityLevel.INFO,
        "info": SeverityLevel.INFO,
        "low": SeverityLevel.LOW,
        "medium": SeverityLevel.MEDIUM,
        "high": SeverityLevel.HIGH,
        "critical": SeverityLevel.CRITICAL,
    }
    return severity_map.get(severity.lower(), SeverityLevel.INFO)


def normalize_severity_nuclei(severity: str) -> SeverityLevel:
    """Map Nuclei severity to standard level."""
    severity_map = {
        "info": SeverityLevel.INFO,
        "low": SeverityLevel.LOW,
        "medium": SeverityLevel.MEDIUM,
        "high": SeverityLevel.HIGH,
        "critical": SeverityLevel.CRITICAL,
    }
    return severity_map.get(severity.lower(), SeverityLevel.INFO)


def normalize_severity_zap(risk: str) -> SeverityLevel:
    """Map ZAP risk rating to standard level."""
    risk_map = {
        "informational": SeverityLevel.INFO,
        "low": SeverityLevel.LOW,
        "medium": SeverityLevel.MEDIUM,
        "high": SeverityLevel.HIGH,
        "critical": SeverityLevel.CRITICAL,
    }
    return risk_map.get(risk.lower(), SeverityLevel.INFO)


def normalize_openvvas_findings(
    openvvas_data: Dict, asset_id: int
) -> List[Finding]:
    """
    Normalize OpenVAS report to Finding list.
    
    Expected structure:
    {
        "report": {
            "results": [
                {
                    "name": "Title",
                    "severity": "high",
                    "cvss_base": 7.5,
                    "cve": "CVE-2021-1234",
                    "description": "...",
                    "solution": "..."
                }
            ]
        }
    }
    """
    findings = []
    results = openvvas_data.get("report", {}).get("results", [])
    
    for result in results:
        try:
            finding = Finding(
                asset_id=asset_id,
                title=result.get("name", "Unknown"),
                description=result.get("description", ""),
                severity=normalize_severity_openvvas(result.get("severity", "info")),
                cvss_score=normalize_cvss_score(result.get("cvss_base")),
                cve_id=result.get("cve"),
                evidence=result.get("description", ""),
                remediation=result.get("solution", "No remediation provided"),
                scanner=ScannerType.OPENVAS,
            )
            findings.append(finding)
            logger.debug(f"Normalized OpenVAS finding: {finding.title}")
        except Exception as e:
            logger.error(f"Error normalizing OpenVAS finding: {e}")
            continue
    
    logger.info(f"Normalized {len(findings)} OpenVAS findings for asset {asset_id}")
    return findings


def normalize_nuclei_findings(nuclei_data: List[Dict], asset_id: int) -> List[Finding]:
    """
    Normalize Nuclei JSON output to Finding list.
    
    Expected structure (JSON lines):
    {
        "template-id": "sql-injection",
        "name": "SQL Injection",
        "severity": "critical",
        "matched-at": "http://...",
        "extracted-results": ["..."],
        "description": "..."
    }
    """
    findings = []
    
    # Handle both list and generator
    if not isinstance(nuclei_data, (list, tuple)):
        nuclei_data = list(nuclei_data)
    
    for result in nuclei_data:
        try:
            finding = Finding(
                asset_id=asset_id,
                title=result.get("name", result.get("template-id", "Unknown")),
                description=result.get("description", ""),
                severity=normalize_severity_nuclei(result.get("severity", "info")),
                cvss_score=None,  # Nuclei doesn't provide CVSS
                cve_id=None,
                evidence=result.get("matched-at", ""),
                remediation="Manual review required",
                scanner=ScannerType.NUCLEI,
            )
            findings.append(finding)
            logger.debug(f"Normalized Nuclei finding: {finding.title}")
        except Exception as e:
            logger.error(f"Error normalizing Nuclei finding: {e}")
            continue
    
    logger.info(f"Normalized {len(findings)} Nuclei findings for asset {asset_id}")
    return findings


def normalize_zap_findings(zap_data: Dict, asset_id: int) -> List[Finding]:
    """
    Normalize ZAP alerts to Finding list.
    
    Expected structure:
    {
        "site": {
            "alerts": [
                {
                    "name": "Title",
                    "riskcode": "3",  # 0=info, 1=low, 2=medium, 3=high
                    "confidence": "2",
                    "description": "...",
                    "solution": "...",
                    "reference": "..."
                }
            ]
        }
    }
    """
    findings = []
    alerts = zap_data.get("site", {}).get("alerts", [])
    
    risk_map = {
        "0": SeverityLevel.INFO,
        "1": SeverityLevel.LOW,
        "2": SeverityLevel.MEDIUM,
        "3": SeverityLevel.HIGH,
        "4": SeverityLevel.CRITICAL,
    }
    
    for alert in alerts:
        try:
            riskcode = str(alert.get("riskcode", "0"))
            finding = Finding(
                asset_id=asset_id,
                title=alert.get("name", "Unknown"),
                description=alert.get("description", ""),
                severity=risk_map.get(riskcode, SeverityLevel.INFO),
                cvss_score=None,  # ZAP doesn't provide CVSS
                cve_id=None,
                evidence=alert.get("reference", ""),
                remediation=alert.get("solution", "Manual review required"),
                scanner=ScannerType.ZAP,
            )
            findings.append(finding)
            logger.debug(f"Normalized ZAP finding: {finding.title}")
        except Exception as e:
            logger.error(f"Error normalizing ZAP finding: {e}")
            continue
    
    logger.info(f"Normalized {len(findings)} ZAP findings for asset {asset_id}")
    return findings
