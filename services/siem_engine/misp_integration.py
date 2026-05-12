"""
US-6.8 — Integración MISP: publicación y consumo de IoCs
ENS: op.exp.4 | Pts: 5
"""
import os
import json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter
from shared.scan_logger import ScanLogger
from .misp_client import misp_get, misp_post, is_configured, MISP_URL

logger = ScanLogger("siem_engine.misp_integration")
router = APIRouter(tags=["US-6.8 MISP"])

COWRIE_LOG = "/var/log/cowrie/cowrie.json"


def _read_cowrie_ips(hours: int = 24) -> list:
    ips = set()
    if not os.path.exists(COWRIE_LOG):
        return []
    since = datetime.utcnow() - timedelta(hours=hours)
    try:
        with open(COWRIE_LOG) as f:
            for line in f.readlines():
                try:
                    d = json.loads(line)
                    ts_str = d.get("timestamp", "")
                    if not ts_str:
                        continue
                    ts = datetime.fromisoformat(ts_str[:19])
                    if ts < since:
                        continue
                    ip = d.get("src_ip", "")
                    if ip and not ip.startswith("127.") and not ip.startswith("172."):
                        ips.add(ip)
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"Cowrie read error: {e}")
    return list(ips)


@router.get("/siem/misp/status")
async def misp_status():
    if not is_configured():
        return {
            "connected": False,
            "reason": "api_key_not_configured",
            "misp_url": MISP_URL,
            "ens_compliance": {"op_exp_4": True},
            "timestamp": datetime.utcnow().isoformat(),
        }
    try:
        data = await misp_get("/users/view/me.json")
        user = data.get("User", {})
        return {
            "connected": True,
            "misp_url": MISP_URL,
            "user": user.get("email", ""),
            "org": user.get("org_id", ""),
            "role": user.get("role_id", ""),
            "ens_compliance": {"op_exp_4": True},
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {
            "connected": False,
            "reason": str(e)[:100],
            "misp_url": MISP_URL,
            "ens_compliance": {"op_exp_4": True},
            "timestamp": datetime.utcnow().isoformat(),
        }


@router.post("/siem/misp/publish-iocs")
async def publish_iocs():
    if not is_configured():
        return {"published": 0, "reason": "api_key_not_configured", "iocs": []}

    ips = _read_cowrie_ips(hours=24)
    if not ips:
        return {"published": 0, "reason": "no_new_iocs", "iocs": []}

    published = []
    for ip in ips[:20]:
        try:
            event = {
                "Event": {
                    "info": f"ScanOps Honeypot Detection - SSH Attack from {ip}",
                    "threat_level_id": "2",
                    "analysis": "0",
                    "distribution": "0",
                    "Attribute": [
                        {
                            "type": "ip-src",
                            "value": ip,
                            "category": "Network activity",
                            "to_ids": True,
                        }
                    ],
                }
            }
            await misp_post("/events/add", event)
            published.append(ip)
        except Exception as e:
            logger.warning(f"Error publicando IoC {ip}: {e}")

    logger.info(f"[US-6.8] Publicados {len(published)} IoCs en MISP")
    return {
        "published": len(published),
        "iocs": published,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/siem/misp/iocs")
async def get_iocs():
    if not is_configured():
        return {"total": 0, "iocs": [], "reason": "api_key_not_configured"}
    try:
        data = await misp_post("/attributes/restSearch", {
            "returnFormat": "json",
            "limit": 100,
            "type": "ip-src",
        })
        attrs = data.get("response", {}).get("Attribute", [])
        iocs = [
            {
                "ip": a.get("value"),
                "event_id": a.get("event_id"),
                "timestamp": a.get("timestamp"),
            }
            for a in attrs if a.get("value")
        ]
        return {"total": len(iocs), "iocs": iocs}
    except Exception as e:
        return {"total": 0, "iocs": [], "error": str(e)[:100]}


@router.post("/siem/misp/sync-to-crowdsec")
async def sync_to_crowdsec():
    iocs_resp = await get_iocs()
    iocs = iocs_resp.get("iocs", [])
    blocked = []
    for ioc in iocs[:50]:
        ip = ioc.get("ip", "")
        if not ip:
            continue
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                continue
            from .blocking import _crowdsec_block
            ok, method = await _crowdsec_block(ip, "misp_ioc", "48h")
            if ok:
                blocked.append(ip)
        except Exception as e:
            logger.debug(f"Skip {ip}: {e}")
    return {
        "synced": len(blocked),
        "blocked_ips": blocked,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/siem/misp/events")
async def list_misp_events():
    if not is_configured():
        return {"total": 0, "events": [], "reason": "api_key_not_configured"}
    try:
        data = await misp_get("/events/index")
        events = [
            {
                "id": e.get("id"),
                "info": e.get("info"),
                "date": e.get("date"),
                "threat_level_id": e.get("threat_level_id"),
                "org": e.get("Org", {}).get("name", ""),
            }
            for e in (data if isinstance(data, list) else [])
        ]
        return {"total": len(events), "events": events}
    except Exception as e:
        return {"total": 0, "events": [], "error": str(e)[:100]}