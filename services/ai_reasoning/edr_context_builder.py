"""
EDR Context Builder — M8 FASE 6
=================================
Fetches behavioral findings and threat intelligence from the shared PostgreSQL DB
and structures them into the behavioral + threat_intel context dicts that M8 prompts
and the Prioritizer expect.

Used by:
  - StreamingProcessor.process_finding() — injected into asset_context
  - run_full_ai_pipeline Celery task — to discover assets needing EDR-enriched analysis
  - kill_chain_detector — full context input

Design: synchronous (psycopg2 / SessionLocal), safe to call from both Celery tasks
and asyncio contexts via asyncio.to_thread().
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}

# Only consider findings from the last N days to avoid stale data
_LOOKBACK_DAYS = int(os.getenv("EDR_M8_LOOKBACK_DAYS", "7"))


def build_edr_context_for_asset(asset_id: int) -> Dict:
    """
    Return EDR context for an asset.
    Returns {} if no active behavioral findings exist (asset is clean or not scanned yet).

    Output structure:
      {
        "behavioral": {
          "anomalies": [...],
          "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
          "total_findings": int,
          "active_c2_detected": bool,
          "yara_hits": int,
        },
        "threat_intel": {
          "malicious_ips": [...],
          "compromised_domains": [...],
          "data_exfil_detected": bool,
          "c2_confidence": float,   # 0.0–1.0
        }
      }
    """
    try:
        from shared.database import SessionLocal
        from sqlalchemy import text as sql_text

        db = SessionLocal()
        try:
            return _build(db, asset_id, sql_text)
        finally:
            db.close()
    except Exception as exc:
        logger.error("EDR_CONTEXT_BUILD_ERROR", extra={"asset_id": asset_id, "error": str(exc)})
        return {}


def get_assets_with_active_edr_findings() -> List[Dict]:
    """
    Return list of {asset_id} dicts for assets that have open/investigating
    behavioral findings in the last EDR_M8_LOOKBACK_DAYS days.
    Used by run_full_ai_pipeline to discover which assets need EDR-enriched M8 analysis.
    """
    try:
        from shared.database import SessionLocal
        from sqlalchemy import text as sql_text

        cutoff = datetime.utcnow() - timedelta(days=_LOOKBACK_DAYS)
        db = SessionLocal()
        try:
            rows = db.execute(
                sql_text(
                    "SELECT DISTINCT asset_id FROM behavioral_findings "
                    "WHERE status IN ('open','investigating') AND created_at >= :cutoff "
                    "ORDER BY asset_id"
                ),
                {"cutoff": cutoff},
            ).fetchall()
            return [{"asset_id": row[0]} for row in rows]
        finally:
            db.close()
    except Exception as exc:
        logger.error("EDR_ASSETS_QUERY_ERROR", extra={"error": str(exc)})
        return []


# ── Internal helpers ──────────────────────────────────────────────────────────

def _build(db, asset_id: int, sql_text) -> Dict:
    cutoff = datetime.utcnow() - timedelta(days=_LOOKBACK_DAYS)

    rows = db.execute(
        sql_text(
            """
            SELECT id, process_name, anomaly_type, severity, confidence_score,
                   detection_method, indicators, mitre_attack_tactics
            FROM behavioral_findings
            WHERE asset_id = :aid
              AND status IN ('open', 'investigating')
              AND created_at >= :cutoff
            ORDER BY severity DESC, confidence_score DESC
            LIMIT 20
            """
        ),
        {"aid": asset_id, "cutoff": cutoff},
    ).fetchall()

    if not rows:
        return {}

    anomalies: List[Dict] = []
    all_ips:     List[str] = []
    all_domains: List[str] = []
    highest_rank = 0
    c2_confidences: List[float] = []

    for row in rows:
        (rid, proc_name, atype, severity, confidence,
         det_method, indicators, mitre_tactics) = row

        ind = indicators or {}

        # Extract IPs and domains from indicators
        ips     = _extract_ips(ind)
        domains = _extract_domains(ind)
        all_ips.extend(ips)
        all_domains.extend(domains)

        # YARA match name from indicators
        yara_match = None
        if det_method and "yara" in det_method.lower():
            matched = ind.get("matched", [])
            yara_rules = [m for m in matched if isinstance(m, str) and "YARA:" in m]
            yara_match = yara_rules[0].replace("YARA:", "") if yara_rules else "YARA_MATCH"

        if "C2" in (atype or "").upper() or "CALLBACK" in (atype or "").upper():
            c2_confidences.append(confidence / 100.0 if confidence else 0.0)

        anomalies.append({
            "type":             atype,
            "process":          proc_name,
            "severity":         severity,
            "confidence":       confidence or 50,
            "ip":               ips[0] if ips else None,
            "mitre_tactics":    mitre_tactics or [],
            "crowdsec":         "UNKNOWN",  # resolved below
            "yara_match":       yara_match,
            "detection_method": det_method,
        })
        highest_rank = max(highest_rank, _SEV_RANK.get(severity or "LOW", 1))

    # Deduplicate
    unique_ips     = list(dict.fromkeys(all_ips))
    unique_domains = list(dict.fromkeys(all_domains))

    # Fetch threat intel from cache
    malicious_ips     = _fetch_malicious(db, sql_text, unique_ips,     "ip")
    malicious_domains = _fetch_malicious(db, sql_text, unique_domains, "domain")

    # Stamp CrowdSec reputation into anomalies
    malicious_ips_set = set(malicious_ips)
    for a in anomalies:
        if a["ip"] and a["ip"] in malicious_ips_set:
            a["crowdsec"] = "MALICIOUS"

    # Build summary
    c2_confidence    = round(max(c2_confidences, default=0.0), 2)
    active_c2        = any("C2" in (a["type"] or "").upper() for a in anomalies)
    data_exfil       = any("EXFIL" in (a["type"] or "").upper() for a in anomalies)
    yara_hits        = sum(1 for a in anomalies if a["yara_match"])

    return {
        "behavioral": {
            "anomalies":          anomalies,
            "severity":           _RANK_SEV.get(highest_rank, "MEDIUM"),
            "total_findings":     len(anomalies),
            "active_c2_detected": active_c2,
            "yara_hits":          yara_hits,
        },
        "threat_intel": {
            "malicious_ips":        malicious_ips,
            "compromised_domains":  malicious_domains,
            "data_exfil_detected":  data_exfil,
            "c2_confidence":        c2_confidence,
        },
    }


def _fetch_malicious(db, sql_text, ioc_values: List[str], ioc_type: str) -> List[str]:
    if not ioc_values:
        return []
    try:
        rows = db.execute(
            sql_text(
                "SELECT ioc_value FROM threat_intel_cache "
                "WHERE ioc_type = :t AND ioc_value = ANY(:vals) "
                "  AND is_malicious = TRUE AND ttl_expires > NOW()"
            ),
            {"t": ioc_type, "vals": ioc_values},
        ).fetchall()
        return [r[0] for r in rows]
    except Exception as exc:
        logger.warning("EDR_TI_FETCH_ERROR", extra={"type": ioc_type, "error": str(exc)})
        return []


def _extract_ips(indicators: dict) -> List[str]:
    import re
    _RE = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    _PRIVATE = ('10.', '127.', '0.', '169.254.', '192.168.',
                 '172.16.', '172.17.', '172.18.', '172.19.',
                 '172.20.', '172.21.', '172.22.', '172.23.',
                 '172.24.', '172.25.', '172.26.', '172.27.',
                 '172.28.', '172.29.', '172.30.', '172.31.')
    text = indicators.get("cmdline", "") + " " + " ".join(
        str(m) for m in indicators.get("matched", [])
    )
    return [
        ip for ip in _RE.findall(text)
        if not any(ip.startswith(p) for p in _PRIVATE)
    ]


def _extract_domains(indicators: dict) -> List[str]:
    import re
    _RE = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:'
        r'com|net|org|io|info|tk|ga|ml|cf|gq|pw|xyz|top|site|online|duckdns'
        r')\b',
        re.IGNORECASE,
    )
    text = indicators.get("cmdline", "")
    return list({d.lower() for d in _RE.findall(text)})
