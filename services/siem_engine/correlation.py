"""
US-6.5 — Correlación IA eventos SIEM
ENS: op.exp.4 | Pts: 8
"""
import json
import re
import uuid
import os
import asyncio
import paramiko
from datetime import datetime, timedelta, timezone as _tz
from typing import Optional, List
from fastapi import APIRouter
from pydantic import BaseModel
import httpx
from shared.scan_logger import ScanLogger
from .db import get_conn

logger = ScanLogger("siem_engine.correlation")
router = APIRouter(tags=["US-6.5 Correlación IA"])

OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:latest")
INDEXER_URL = os.getenv("INDEXER_URL", "http://wazuh.indexer:9200")
COWRIE_LOG = "/var/log/cowrie/cowrie.json"
SURICATA_LOG = "/var/log/suricata/eve.json"

CORRELATION_PROMPT = """Eres un analista de ciberseguridad experto en ENS Alto (Esquema Nacional de Seguridad, España).
Analiza los siguientes eventos de seguridad y detecta patrones de ataque.

EVENTOS (ordenados cronológicamente):
{events_json}

INSTRUCCIONES:
1. Identifica si hay un patrón de ataque coordinado (reconocimiento, brute force, movimiento lateral, exfiltración)
2. Determina si los eventos son de un solo atacante o múltiples
3. Evalúa el nivel de amenaza real considerando el contexto ENS Alto
4. Sugiere la acción inmediata más importante

Responde ÚNICAMENTE con este JSON, sin texto adicional, sin markdown:
{{
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "attack_pattern": "nombre corto del patrón",
  "confidence": 0.0,
  "affected_ips": ["ip1"],
  "ai_reasoning": "explicación en 2-3 frases",
  "recommended_action": "acción concreta inmediata",
  "ens_measures": ["op.exp.4", "op.exp.5"]
}}"""


class CorrelationRequest(BaseModel):
    window_minutes: int = 60
    min_severity: str = "LOW"
    asset_id: Optional[int] = None


def _collect_wazuh_events(window_minutes: int) -> list:
    events = []
    since = (datetime.utcnow() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        import httpx as _httpx
        r = _httpx.post(
            f"{INDEXER_URL}/wazuh-alerts-*/_search",
            json={"size": 50, "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": since}}}
            ]}}},
            timeout=10
        )
        for hit in r.json().get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            events.append({
                "source": "wazuh",
                "timestamp": src.get("@timestamp", ""),
                "src_ip": src.get("data", {}).get("srcip", src.get("agent", {}).get("ip", "")),
                "event_type": src.get("rule", {}).get("description", "wazuh_alert"),
                "severity": str(src.get("rule", {}).get("level", 0)),
                "description": src.get("rule", {}).get("description", ""),
            })
    except Exception as e:
        logger.debug(f"Wazuh collection error: {e}")
    return events


def _collect_cowrie_events(window_minutes: int) -> list:
    events = []
    if not os.path.exists(COWRIE_LOG):
        return events
    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    try:
        with open(COWRIE_LOG) as f:
            for line in f.readlines()[-200:]:
                try:
                    d = json.loads(line)
                    ts_str = d.get("timestamp", "")
                    if not ts_str:
                        continue
                    ts = datetime.fromisoformat(ts_str[:19])
                    if ts < since:
                        continue
                    eventid = d.get("eventid", "")
                    if not any(x in eventid for x in ["login", "command", "connect", "session"]):
                        continue
                    events.append({
                        "source": "cowrie",
                        "timestamp": ts_str,
                        "src_ip": d.get("src_ip", ""),
                        "event_type": eventid,
                        "severity": "HIGH" if "login.failed" in eventid else "MEDIUM",
                        "description": d.get("input", d.get("username", eventid)),
                    })
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"Cowrie collection error: {e}")
    return events


def _collect_suricata_events(window_minutes: int) -> list:
    events = []
    if not os.path.exists(SURICATA_LOG):
        return events
    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    try:
        with open(SURICATA_LOG) as f:
            for line in f.readlines()[-100:]:
                try:
                    d = json.loads(line)
                    if d.get("event_type") != "alert":
                        continue
                    ts = datetime.fromisoformat(d.get("timestamp", "")[:19])
                    if ts < since:
                        continue
                    events.append({
                        "source": "suricata",
                        "timestamp": d.get("timestamp", ""),
                        "src_ip": d.get("src_ip", ""),
                        "event_type": d.get("alert", {}).get("signature", "suricata_alert"),
                        "severity": str(d.get("alert", {}).get("severity", "MEDIUM")),
                        "description": d.get("alert", {}).get("category", ""),
                    })
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"Suricata collection error: {e}")
    return events


def _rule_based_fallback(events: list) -> dict:
    from collections import Counter
    ips = [e.get("src_ip", "") for e in events if e.get("src_ip")]
    ip_counts = Counter(ips)
    sources = set(e.get("source") for e in events)
    top_ip = ip_counts.most_common(1)[0][0] if ip_counts else ""
    top_count = ip_counts.most_common(1)[0][1] if ip_counts else 0

    if len(sources) > 1 and top_count > 3:
        threat_level, pattern = "CRITICAL", "Multi-vector Attack"
    elif top_count >= 5:
        threat_level, pattern = "HIGH", "Brute Force"
    elif top_count >= 2:
        threat_level, pattern = "MEDIUM", "Reconnaissance"
    else:
        threat_level, pattern = "LOW", "Isolated Event"

    return {
        "threat_level": threat_level,
        "attack_pattern": pattern,
        "confidence": 0.6,
        "affected_ips": list(ip_counts.keys())[:5],
        "ai_reasoning": f"Análisis basado en reglas: {top_count} eventos de {top_ip}. Fuentes: {', '.join(sources)}.",
        "recommended_action": "Revisar logs manualmente y considerar bloqueo de IP origen.",
        "ens_measures": ["op.exp.4", "op.exp.5"],
    }


async def _correlate_with_ai(events: list) -> dict:
    if not events:
        return _rule_based_fallback(events)

    events_summary = [
        {"source": e["source"], "timestamp": e["timestamp"],
         "src_ip": e["src_ip"], "event_type": e["event_type"],
         "description": str(e["description"])[:100]}
        for e in events[:50]
    ]
    prompt = CORRELATION_PROMPT.format(events_json=json.dumps(events_summary, indent=2, ensure_ascii=False))

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            if resp.status_code == 200:
                raw = resp.json().get("response", "")
                raw = raw.strip()
                if raw.startswith("```"):
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                result = json.loads(raw)
                result["ai_used"] = True
                return result
    except Exception as e:
        logger.warning(f"Ollama error, usando fallback: {e}")

    result = _rule_based_fallback(events)
    result["ai_used"] = False
    return result


def _persist_correlation(correlation_id: str, result: dict, events: list) -> None:
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO siem_correlations
                    (correlation_id, threat_level, attack_pattern, confidence,
                     affected_ips, timeline, ai_reasoning, recommended_action,
                     ens_measures, events_analyzed, ai_used)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (correlation_id) DO NOTHING
                """, (
                    correlation_id,
                    result.get("threat_level", "LOW"),
                    result.get("attack_pattern", "Unknown"),
                    result.get("confidence", 0.5),
                    json.dumps(result.get("affected_ips", [])),
                    json.dumps(events[:20]),
                    result.get("ai_reasoning", ""),
                    result.get("recommended_action", ""),
                    json.dumps(result.get("ens_measures", [])),
                    len(events),
                    result.get("ai_used", False),
                ))
    finally:
        conn.close()


@router.post("/siem/correlate")
async def correlate(req: CorrelationRequest):
    all_events = []
    all_events += _collect_wazuh_events(req.window_minutes)
    all_events += _collect_cowrie_events(req.window_minutes)
    all_events += _collect_suricata_events(req.window_minutes)
    all_events.sort(key=lambda x: x.get("timestamp", ""))

    correlation_id = str(uuid.uuid4())
    result = await _correlate_with_ai(all_events)
    result["correlation_id"] = correlation_id
    result["timestamp"] = datetime.utcnow().isoformat()
    result["events_analyzed"] = len(all_events)

    _persist_correlation(correlation_id, result, all_events)
    logger.info(f"[US-6.5] Correlación {correlation_id}: {result.get('threat_level')} — {result.get('attack_pattern')}")
    return result


@router.get("/siem/correlations")
async def list_correlations(limit: int = 20, threat_level: Optional[str] = None):
    conn = get_conn()
    try:
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if threat_level:
                cur.execute("""
                    SELECT correlation_id, threat_level, attack_pattern, confidence,
                           affected_ips, ai_reasoning, recommended_action, events_analyzed,
                           ai_used, correlated_at
                    FROM siem_correlations WHERE threat_level = %s
                    ORDER BY correlated_at DESC LIMIT %s
                """, (threat_level, limit))
            else:
                cur.execute("""
                    SELECT correlation_id, threat_level, attack_pattern, confidence,
                           affected_ips, ai_reasoning, recommended_action, events_analyzed,
                           ai_used, correlated_at
                    FROM siem_correlations ORDER BY correlated_at DESC LIMIT %s
                """, (limit,))
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("correlated_at"):
                    r["correlated_at"] = r["correlated_at"].isoformat()
                if isinstance(r.get("affected_ips"), str):
                    r["affected_ips"] = json.loads(r["affected_ips"])
        return {"total": len(rows), "correlations": rows}
    finally:
        conn.close()


@router.get("/siem/correlations/{correlation_id}")
async def get_correlation(correlation_id: str):
    conn = get_conn()
    try:
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM siem_correlations WHERE correlation_id = %s", (correlation_id,))
            row = cur.fetchone()
            if not row:
                from fastapi import HTTPException
                raise HTTPException(status_code=404, detail="Correlación no encontrada")
            r = dict(row)
            if r.get("correlated_at"):
                r["correlated_at"] = r["correlated_at"].isoformat()
            return r
    finally:
        conn.close()


async def auto_correlate():
    """Llamada desde el loop de fondo cada 5 minutos."""
    try:
        req = CorrelationRequest(window_minutes=10)
        await correlate(req)
        logger.info("[US-6.5] Auto-correlación completada")
    except Exception as e:
        logger.warning(f"[US-6.5] Auto-correlación fallida: {e}")


# Formato clásico: "Jun  3 10:01:03 hostname sshd[pid]: msg"
_AUTH_LOG_RE_CLASSIC = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+(?:sshd|pam_unix|sudo|systemd-logind)\[.*?\]:\s+(?P<msg>.+)'
)
# Formato ISO: "2026-06-03T10:01:03.123456+02:00 hostname sshd[pid]: msg"
_AUTH_LOG_RE_ISO = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+\S+\s+(?:sshd|pam_unix|sudo|systemd-logind)\[.*?\]:\s+(?P<msg>.+)'
)
_AUTH_KEYWORDS = [
    'Accepted password', 'Accepted publickey',
    'Failed password', 'Invalid user',
    'authentication failure', 'FAILED LOGIN',
    'session opened', 'session closed',
    'Connection closed', 'Disconnected',
]


def _parse_auth_log_line(line: str, year: int) -> dict | None:
    if not any(k in line for k in _AUTH_KEYWORDS):
        return None

    # Intentar formato ISO primero, luego clásico
    m_iso = _AUTH_LOG_RE_ISO.match(line)
    m_classic = _AUTH_LOG_RE_CLASSIC.match(line)

    if m_iso:
        try:
            ts_raw = m_iso.group('ts')
            # Normalizar a UTC isoformat
            ts = datetime.fromisoformat(ts_raw).astimezone(_tz.utc)
            timestamp = ts.isoformat()
        except Exception:
            timestamp = datetime.now(_tz.utc).isoformat()
        msg = m_iso.group('msg')
    elif m_classic:
        try:
            ts_str = f"{m_classic.group('month')} {m_classic.group('day')} {m_classic.group('time')} {year}"
            ts = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y").replace(tzinfo=_tz.utc)
            timestamp = ts.isoformat()
        except Exception:
            timestamp = datetime.now(_tz.utc).isoformat()
        msg = m_classic.group('msg')
    else:
        return None

    success = any(k in msg for k in ['Accepted password', 'Accepted publickey', 'session opened'])
    if 'Invalid user' in msg or 'FAILED LOGIN' in msg:
        severity = 'HIGH'
    elif 'Failed password' in msg or 'authentication failure' in msg:
        severity = 'MEDIUM'
    elif success:
        severity = 'LOW'
    else:
        severity = 'INFO'

    user_match = re.search(r'(?:for|user)\s+(\S+)', msg)
    ip_match   = re.search(r'from\s+([\d\.]+)', msg)

    return {
        'raw_log':   line.strip(),
        'timestamp': timestamp,
        'message':   msg,
        'success':   success,
        'severity':  severity,
        'src_user':  user_match.group(1) if user_match else None,
        'src_ip':    ip_match.group(1) if ip_match else None,
    }


def _ssh_read_auth_log(ip: str, user: str, password: str, lines: int = 500) -> list[dict]:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=user, password=password, timeout=10)
        # Intentar con sudo -S (lee password desde stdin)
        cmd = f'echo {password} | sudo -S tail -n {lines} /var/log/auth.log 2>/dev/null'
        _, stdout, stderr = client.exec_command(cmd, get_pty=False)
        raw = stdout.read().decode('utf-8', errors='ignore')
        # Fallback: intentar sin sudo por si el usuario tiene permisos directos
        if not raw.strip():
            _, stdout2, _ = client.exec_command(f'tail -n {lines} /var/log/auth.log 2>/dev/null')
            raw = stdout2.read().decode('utf-8', errors='ignore')
        client.close()
        year = datetime.now().year
        return [ev for line in raw.splitlines() if (ev := _parse_auth_log_line(line, year))]
    except Exception as e:
        return [{'error': str(e), 'ip': ip}]


@router.get("/siem/auth-events")
async def list_auth_events(limit: int = 100):
    """
    Lee auth.log de los activos registrados en M1 vía SSH.
    Devuelve eventos de autenticación SSH/PAM estructurados.
    ENS: op.exp.5
    """
    assets = []
    try:
        async with httpx.AsyncClient(verify=False, timeout=8) as client:
            r = await client.get("http://m1:8001/api/v1/assets?page=1&page_size=100")
            if r.status_code == 200:
                assets = r.json().get('items', [])
    except Exception:
        pass

    if not assets:
        assets = [{'id': 1, 'ip': '10.202.15.100', 'name': 'srv-target'}]

    results = []
    for asset in assets:
        ip = asset.get('ip')
        if not ip:
            continue
        ssh_user = asset.get('ssh_user') or 'admin'
        ssh_pass = asset.get('ssh_password') or 'test123'
        events = _ssh_read_auth_log(ip, ssh_user, ssh_pass, lines=limit)
        for ev in events:
            if 'error' in ev:
                continue
            ev['agent_name']      = asset.get('name') or asset.get('hostname') or ip
            ev['agent_ip']        = ip
            ev['agent_id']        = str(asset.get('id', ''))
            ev['alert_id']        = f"ssh-{ip}-{ev.get('timestamp', '')}"
            ev['rule_id']         = 'auth.log'
            ev['rule_desc']       = ev.get('message', '')
            ev['mitre_tactic']    = 'TA0006' if not ev.get('success') else ''
            ev['mitre_technique'] = 'T1110' if 'Failed password' in ev.get('message', '') else ''
            results.append(ev)

    results.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    results = results[:limit]

    return {'total': len(results), 'events': results}