"""
US-6.1 -- Wazuh HIDS alerts reader via OpenSearch
ENS Alto: op.exp.5 (vigilancia operativa — HIDS)
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import APIRouter

router = APIRouter(tags=["US-6.1 Wazuh HIDS"])

_INDEXER_URL = os.getenv("INDEXER_URL", "http://wazuh.indexer:9200")
_INDEXER_USER = "admin"
_INDEXER_PASS = "admin"
_INDEX_PATTERN = "wazuh-alerts-4.x-*"


def _level_to_severity(level: int) -> str:
    if level >= 12:
        return "CRITICAL"
    if level >= 8:
        return "HIGH"
    if level >= 5:
        return "MEDIUM"
    return "LOW"


def _build_query(limit: int, min_level: int, days: int) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    return {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": since}}},
                    {"range": {"rule.level": {"gte": min_level}}},
                ]
            }
        },
        "_source": [
            "timestamp", "@timestamp",
            "rule.id", "rule.level", "rule.description", "rule.groups",
            "rule.mitre.technique", "rule.mitre.tactic",
            "agent.name",
            "data.srcip", "data.src_ip",
            "location", "id",
        ],
    }


@router.get("/siem/wazuh/alerts")
async def get_wazuh_alerts(
    limit: int = 100,
    min_level: int = 1,
    days: int = 7,
) -> dict[str, Any]:
    """
    Últimas alertas del HIDS Wazuh desde OpenSearch.
    ENS op.exp.5 — Vigilancia operativa continua.
    """
    query = _build_query(limit, min_level, days)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{_INDEXER_URL}/{_INDEX_PATTERN}/_search",
                json=query,
                auth=(_INDEXER_USER, _INDEXER_PASS),
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"alerts": [], "count": 0, "source": "wazuh-hids", "error": str(e)}

    hits = data.get("hits", {}).get("hits", [])
    alerts = []
    for hit in hits:
        src = hit.get("_source", {})
        rule = src.get("rule", {})
        agent = src.get("agent", {})
        data_field = src.get("data", {}) or {}

        level = rule.get("level", 0)
        src_ip = (
            data_field.get("srcip")
            or data_field.get("src_ip")
        )

        mitre_tactics = rule.get("mitre", {}).get("tactic", []) if isinstance(rule.get("mitre"), dict) else []
        mitre_techniques = rule.get("mitre", {}).get("technique", []) if isinstance(rule.get("mitre"), dict) else []

        alerts.append({
            "id": hit.get("_id", src.get("id", "")),
            "timestamp": src.get("timestamp") or src.get("@timestamp", ""),
            "rule_id": rule.get("id", ""),
            "level": level,
            "severity": _level_to_severity(level),
            "description": rule.get("description", "Wazuh alert"),
            "agent": agent.get("name", "wazuh-manager"),
            "src_ip": src_ip,
            "groups": rule.get("groups", []),
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "location": src.get("location", ""),
        })

    total = data.get("hits", {}).get("total", {}).get("value", len(alerts))
    return {
        "alerts": alerts,
        "count": len(alerts),
        "total_in_index": total,
        "source": "wazuh-hids",
        "index": _INDEX_PATTERN,
    }
