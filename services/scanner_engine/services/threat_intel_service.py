"""
Threat Intel Service — M3.1 FASE 3
====================================
Aggregates VT + CrowdSec + OTX lookups behind a PostgreSQL cache.
Cache TTL per IOC type:
  ip     → min(CrowdSec 12h)   — IPs rotate fastest
  domain → min(VT 30d, OTX 7d) = 7 days
  hash   → VT 30d               — file hashes are stable
Severity escalation: LOW→MEDIUM, MEDIUM→HIGH, HIGH→CRITICAL.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from services.scanner_engine.clients.threat_intel_client import (
    CROWDSEC_TTL_HOURS,
    OTX_TTL_DAYS,
    VT_TTL_DAYS,
    CrowdSecClient,
    OTXClient,
    VirusTotalClient,
)
from services.scanner_engine.models.edr import ThreatIntelCache
from services.scanner_engine.services.ioc_extractor import IOC
from shared.scan_logger import ScanLogger

logger = ScanLogger("threat_intel_service")

SEVERITY_ESCALATE = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"}

# Module-level client singletons — shared across Celery task calls
_vt       = VirusTotalClient()
_crowdsec = CrowdSecClient()
_otx      = OTXClient()


def _cache_ttl(ioc_type: str) -> datetime:
    now = datetime.utcnow()
    if ioc_type == "ip":
        return now + timedelta(hours=CROWDSEC_TTL_HOURS)
    if ioc_type == "domain":
        return now + timedelta(days=min(VT_TTL_DAYS, OTX_TTL_DAYS))
    return now + timedelta(days=VT_TTL_DAYS)  # hash


def _is_valid(entry: ThreatIntelCache, force_refresh: bool) -> bool:
    return (not force_refresh) and (entry.ttl_expires > datetime.utcnow())


def _verdict(vt, cs, otx) -> Tuple[bool, int]:
    """Compute (is_malicious, votes) from multi-source dicts."""
    votes = 0
    if vt:
        m, s = vt.get("malicious", 0), vt.get("suspicious", 0)
        if m >= 3:
            votes += m
        elif s >= 5:
            votes += s // 2
    if cs and cs.get("reputation") in ("malicious", "suspicious"):
        votes += 5
    if otx and otx.get("pulse_count", 0) >= 2:
        votes += otx["pulse_count"]
    return votes >= 3, votes


def _query_apis(ioc: IOC) -> Tuple[Optional[dict], Optional[dict], Optional[dict]]:
    """Call all relevant APIs for the IOC type. Returns (vt, cs, otx)."""
    vt = cs = otx = None
    try:
        if ioc.ioc_type == "ip":
            vt  = _vt.lookup_ip(ioc.value)
            cs  = _crowdsec.lookup_ip(ioc.value)
            otx = _otx.lookup_ip(ioc.value)
        elif ioc.ioc_type == "domain":
            vt  = _vt.lookup_domain(ioc.value)
            otx = _otx.lookup_domain(ioc.value)
        elif ioc.ioc_type == "hash":
            vt  = _vt.lookup_hash(ioc.value)
            otx = _otx.lookup_hash(ioc.value)
    except Exception as exc:
        logger.error("THREAT_INTEL_API_ERROR", ioc=ioc.value, error=str(exc))
    return vt, cs, otx


def lookup_ioc(
    db: Session,
    ioc: IOC,
    force_refresh: bool = False,
) -> ThreatIntelCache:
    """
    Return a ThreatIntelCache row for the IOC, using cache when valid.
    Always commits the result to the DB — caller should NOT commit afterwards.
    """
    existing = (
        db.query(ThreatIntelCache)
        .filter(
            ThreatIntelCache.ioc_value == ioc.value,
            ThreatIntelCache.ioc_type  == ioc.ioc_type,
        )
        .first()
    )
    if existing and _is_valid(existing, force_refresh):
        logger.info("THREAT_INTEL_CACHE_HIT", ioc=ioc.value, type=ioc.ioc_type)
        return existing

    logger.info("THREAT_INTEL_CACHE_MISS", ioc=ioc.value, type=ioc.ioc_type)
    vt, cs, otx = _query_apis(ioc)
    is_malicious, votes = _verdict(vt, cs, otx)
    ttl = _cache_ttl(ioc.ioc_type)

    if existing:
        existing.vt_result       = vt
        existing.crowdsec_result = cs
        existing.otx_result      = otx
        existing.is_malicious    = is_malicious
        existing.malicious_votes = votes
        existing.ttl_expires     = ttl
        existing.updated_at      = datetime.utcnow()
        db.add(existing)
        db.commit()
        db.refresh(existing)
        return existing

    entry = ThreatIntelCache(
        ioc_value       = ioc.value,
        ioc_type        = ioc.ioc_type,
        vt_result       = vt,
        crowdsec_result = cs,
        otx_result      = otx,
        is_malicious    = is_malicious,
        malicious_votes = min(votes, 32767),  # SmallInteger cap
        ttl_expires     = ttl,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
