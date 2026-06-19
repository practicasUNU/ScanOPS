"""
Threat Intelligence Tasks — M3.1 FASE 3
========================================
Celery task to enrich behavioral findings with threat intel.
Auto-triggered by run_behavioral_scan after persisting new findings.
Can also be called on-demand from POST /edr/enrich-findings.

For each finding:
  1. Extract IOCs (IPs, domains, hashes) from indicators.cmdline
  2. Query VT / CrowdSec / OTX (cache-first)
  3. Escalate severity if any IOC is confirmed malicious
  4. Stamp indicators.threat_intel with enrichment metadata
"""
from __future__ import annotations

from typing import Dict, List, Optional

from shared.celery_app import app
from shared.database import SessionLocal
from shared.scan_logger import ScanLogger

logger = ScanLogger("threat_intel_tasks")

_ESCALATE = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"}


@app.task(
    name="tasks.enrich_findings_with_threat_intel",
    queue="vulnerabilities",
    time_limit=600,
    soft_time_limit=570,
)
def enrich_findings_with_threat_intel(
    finding_ids: List[int],
    force_refresh: bool = False,
) -> Dict:
    """
    Enrich a batch of behavioral_findings rows with threat intelligence.
    Returns stats: enriched, escalated, iocs_processed, errors.
    Never raises — always returns a result dict.
    """
    from services.scanner_engine.models.edr import BehavioralFinding
    from services.scanner_engine.services.ioc_extractor import extract_iocs
    from services.scanner_engine.services.threat_intel_service import lookup_ioc

    stats = {"enriched": 0, "escalated": 0, "iocs_processed": 0, "errors": 0}
    db = SessionLocal()
    try:
        for finding_id in finding_ids:
            try:
                _enrich_one(db, finding_id, force_refresh, stats)
            except Exception as exc:
                logger.error(
                    "THREAT_INTEL_FINDING_ERROR",
                    finding_id=finding_id,
                    error=str(exc),
                )
                stats["errors"] += 1

        logger.info("THREAT_INTEL_TASK_COMPLETE", **stats)
        return {"status": "completed", **stats}

    except Exception as exc:
        db.rollback()
        logger.error("THREAT_INTEL_TASK_FATAL", error=str(exc))
        return {"status": "error", "reason": str(exc)}
    finally:
        db.close()


def _enrich_one(db, finding_id: int, force_refresh: bool, stats: dict) -> None:
    from services.scanner_engine.models.edr import BehavioralFinding
    from services.scanner_engine.services.ioc_extractor import extract_iocs
    from services.scanner_engine.services.threat_intel_service import lookup_ioc

    finding = db.query(BehavioralFinding).filter(BehavioralFinding.id == finding_id).first()
    if not finding:
        logger.warning("THREAT_INTEL_NOT_FOUND", finding_id=finding_id)
        return

    iocs = extract_iocs(finding.indicators)
    if not iocs:
        return

    malicious_iocs: List[str] = []
    for ioc in iocs:
        try:
            result = lookup_ioc(db, ioc, force_refresh=force_refresh)
            stats["iocs_processed"] += 1
            if result.is_malicious:
                malicious_iocs.append(ioc.value)
        except Exception as exc:
            logger.warning("THREAT_INTEL_IOC_ERROR", ioc=ioc.value, error=str(exc))
            stats["errors"] += 1

    # Severity escalation — at most one step up
    if malicious_iocs and finding.severity in _ESCALATE:
        new_sev = _ESCALATE[finding.severity]
        logger.info(
            "THREAT_INTEL_SEVERITY_ESCALATED",
            finding_id=finding_id,
            old=finding.severity,
            new=new_sev,
            malicious_iocs=malicious_iocs,
        )
        finding.severity = new_sev
        stats["escalated"] += 1

    # Stamp enrichment metadata into indicators JSON
    indicators = dict(finding.indicators or {})
    indicators["threat_intel"] = {
        "enriched":       True,
        "iocs_found":     [{"value": i.value, "type": i.ioc_type} for i in iocs],
        "malicious_iocs": malicious_iocs,
    }
    finding.indicators = indicators
    db.add(finding)
    db.commit()
    stats["enriched"] += 1
