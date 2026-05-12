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


STATIC_ENRICHMENT: dict = {
    "x-content-type-options":    {"cvss": 5.3, "cve": None, "cwe": "CWE-16"},
    "x-frame-options":           {"cvss": 6.1, "cve": None, "cwe": "CWE-693"},
    "strict-transport-security": {"cvss": 7.4, "cve": None, "cwe": "CWE-319"},
    "content-security-policy":   {"cvss": 6.1, "cve": None, "cwe": "CWE-79"},
    "x-xss-protection":          {"cvss": 4.3, "cve": None, "cwe": "CWE-79"},
    "referrer-policy":           {"cvss": 3.1, "cve": None, "cwe": "CWE-200"},
    "permissions-policy":        {"cvss": 3.1, "cve": None, "cwe": "CWE-284"},
    "cache-control":             {"cvss": 3.1, "cve": None, "cwe": "CWE-524"},
    "server":                    {"cvss": 5.3, "cve": None, "cwe": "CWE-200"},
    "x-powered-by":              {"cvss": 5.3, "cve": None, "cwe": "CWE-200"},
    "missing security header":   {"cvss": 5.3, "cve": None, "cwe": "CWE-16"},
    "clickjacking":              {"cvss": 6.1, "cve": None, "cwe": "CWE-1021"},
    "information disclosure":    {"cvss": 5.3, "cve": None, "cwe": "CWE-200"},
    "ssl":                       {"cvss": 7.4, "cve": None, "cwe": "CWE-326"},
    "tls":                       {"cvss": 7.4, "cve": None, "cwe": "CWE-326"},
    "cors":                      {"cvss": 6.5, "cve": None, "cwe": "CWE-942"},
    "cookie":                    {"cvss": 5.4, "cve": None, "cwe": "CWE-614"},
}


def _enrich_from_static(title: str, cvss_score, cve_id):
    """
    Si cvss_score o cve_id son None, busca en STATIC_ENRICHMENT por keyword en el título.
    No sobrescribe valores ya presentes (ej: CVE real del scanner).
    """
    if cvss_score is not None and cve_id is not None:
        return cvss_score, cve_id

    title_lower = title.lower()
    for keyword, data in STATIC_ENRICHMENT.items():
        if keyword in title_lower:
            return (
                cvss_score if cvss_score is not None else data["cvss"],
                cve_id if cve_id is not None else data["cve"],
            )
    return cvss_score, cve_id


# ENS measures mapping for quick enrichment
ENS_MAPPING = {
    "SQL Injection CVE-2024-XXXX": ["op.exp.2", "mp.info.3"],
    "XML External Entity (XXE) CVE-2024-YYYY": ["op.exp.2"],
    "Weak Cipher Suite CVE-2023-ZZZZ": ["mp.com.2"],
    "Missing Security Headers": ["mp.info.4"],
    "Weak Password Policy Detection": ["op.acc.5"],
    "Exposed API Keys in Response": ["mp.info.3", "mp.info.4"],
    "SSH Weak Key Exchange Algorithms": ["op.exp.2", "mp.com.2"],
    "Unencrypted Data Transmission": ["mp.com.2", "mp.info.3"],
    "Default Credentials Detection": ["op.acc.5"],
    "Generic Remote Code Execution Check": ["op.exp.2"],
    "Server-Side Request Forgery (SSRF) Detection": ["op.exp.2"],
    "Local File Inclusion (LFI) Pattern": ["op.exp.2"],
}


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
    ens_mapping: List[str] = Field(default_factory=list)  # Legacy support
    template_id: Optional[str] = None
    template_tags: List[str] = Field(default_factory=list)
    ens_tags: List[str] = Field(default_factory=list)
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
            title = result.get("name", result.get("template-id", "Unknown"))
            cvss_final, cve_final = _enrich_from_static(title, None, None)
            finding = Finding(
                asset_id=asset_id,
                title=title,
                description=result.get("description", ""),
                severity=normalize_severity_nuclei(result.get("severity", "info")),
                cvss_score=cvss_final,
                cve_id=cve_final,
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
            title = alert.get("name", "Unknown")
            cvss_final, cve_final = _enrich_from_static(title, None, None)
            finding = Finding(
                asset_id=asset_id,
                title=title,
                description=alert.get("description", ""),
                severity=risk_map.get(riskcode, SeverityLevel.INFO),
                cvss_score=cvss_final,
                cve_id=cve_final,
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
