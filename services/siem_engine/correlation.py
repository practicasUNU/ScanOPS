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


# Regex para dos formatos de timestamp en auth.log
_AUTH_LOG_RE_ISO = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+\S+\s+'
    r'(?:sshd|pam_unix|pam_faillock|pam_tally2|sudo|su|useradd|usermod|userdel|passwd|chpasswd|systemd-logind|groupadd|groupdel)\[.*?\]:\s+(?P<msg>.+)'
)
_AUTH_LOG_RE_CLASSIC = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+'
    r'(?:sshd|pam_unix|pam_faillock|pam_tally2|sudo|su|useradd|usermod|userdel|passwd|chpasswd|systemd-logind|groupadd|groupdel)\[.*?\]:\s+(?P<msg>.+)'
)

# Keywords ampliadas — toda acción relevante para ENS op.acc / op.exp.5
_AUTH_KEYWORDS = [
    # SSH autenticación
    'Accepted password', 'Accepted publickey', 'Accepted keyboard',
    'Failed password', 'Invalid user', 'authentication failure',
    'FAILED LOGIN', 'Maximum authentication attempts exceeded',
    'Connection closed by authenticating user',
    # Sesiones
    'session opened', 'session closed', 'Disconnected from user',
    'New session', 'Removed session',
    # sudo / su
    'COMMAND=', 'incorrect password attempts',
    'sudo: auth failure', 'sudo:', 'NOT in sudoers',
    'su: pam_authenticate', 'su: Authentication failure',
    'Successful su for', 'FAILED su for',
    # Usuarios y grupos
    'new user:', 'new group:', 'delete user', 'usermod:',
    'password changed for', 'chpasswd:', 'passwd:',
    'account locked', 'account unlocked',
    # PAM / faillock
    'pam_faillock', 'pam_tally', 'user locked out',
    'User account has expired', 'pam_unix(su',
    # Systemd-logind
    'New seat', 'logind:',
    # Llaves SSH
    'Accepted publickey for', 'Invalid publickey',
    # Escalada
    'privilege escalation',
]

# Clasificación de action_type por keywords en el mensaje
_ACTION_MAP = [
    (['Accepted password', 'Accepted publickey', 'Accepted keyboard'],  'SSH_LOGIN_OK',       'LOW',      True),
    (['Failed password', 'Maximum authentication attempts exceeded'],    'SSH_LOGIN_FAIL',     'MEDIUM',   False),
    (['Invalid user'],                                                    'SSH_INVALID_USER',   'HIGH',     False),
    (['Connection closed by authenticating user'],                       'SSH_ABORT',          'MEDIUM',   False),
    (['session opened'],                                                  'SESSION_OPEN',       'INFO',     True),
    (['session closed', 'Disconnected from user', 'Removed session'],   'SESSION_CLOSE',      'INFO',     True),
    (['COMMAND='],                                                        'SUDO_COMMAND',       'MEDIUM',   True),
    (['NOT in sudoers', 'sudo: auth failure', 'incorrect password attempts'], 'SUDO_FAIL',    'HIGH',     False),
    (['Successful su for'],                                               'SU_OK',              'MEDIUM',   True),
    (['FAILED su for', 'su: Authentication failure'],                   'SU_FAIL',            'HIGH',     False),
    (['new user:'],                                                       'USER_CREATED',       'HIGH',     True),
    (['delete user'],                                                     'USER_DELETED',       'CRITICAL', True),
    (['usermod:'],                                                        'USER_MODIFIED',      'HIGH',     True),
    (['new group:'],                                                      'GROUP_CREATED',      'MEDIUM',   True),
    (['password changed for', 'passwd:', 'chpasswd:'],                  'PASSWORD_CHANGED',   'HIGH',     True),
    (['account locked'],                                                  'ACCOUNT_LOCKED',     'HIGH',     False),
    (['pam_faillock', 'pam_tally', 'user locked out'],                  'ACCOUNT_LOCKOUT',    'HIGH',     False),
    (['authentication failure', 'FAILED LOGIN'],                        'AUTH_FAILURE',       'MEDIUM',   False),
    (['privilege escalation'],                                            'PRIV_ESCALATION',    'CRITICAL', False),
]


def _classify(msg: str) -> tuple:
    """Devuelve (action_type, severity, success) según el mensaje."""
    for keywords, action_type, severity, success in _ACTION_MAP:
        if any(k in msg for k in keywords):
            return action_type, severity, success
    return 'OTHER', 'INFO', False


def _parse_auth_log_line(line: str, year: int) -> dict | None:
    if not any(k in line for k in _AUTH_KEYWORDS):
        return None

    m_iso     = _AUTH_LOG_RE_ISO.match(line)
    m_classic = _AUTH_LOG_RE_CLASSIC.match(line)

    if m_iso:
        try:
            ts = datetime.fromisoformat(m_iso.group('ts')).astimezone(_tz.utc)
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

    action_type, severity, success = _classify(msg)

    user_match = re.search(r'(?:for user |for |user )(\S+)', msg)
    if not user_match:
        user_match = re.search(r'(?:by |to )(\S+)', msg)

    ip_match   = re.search(r'from\s+([\d\.]+)', msg)
    cmd_match  = re.search(r'COMMAND=(\S+)', msg)
    port_match = re.search(r'port\s+(\d+)', msg)

    return {
        'raw_log':     line.strip(),
        'timestamp':   timestamp,
        'message':     msg,
        'action_type': action_type,
        'success':     success,
        'severity':    severity,
        'src_user':    user_match.group(1) if user_match else None,
        'src_ip':      ip_match.group(1) if ip_match else None,
        'command':     cmd_match.group(1) if cmd_match else None,
        'port':        port_match.group(1) if port_match else None,
    }


def _ssh_read_auth_log(ip: str, user: str, password: str, lines: int = 500) -> list[dict]:
    try:
        import subprocess
        ssh_cmd = [
            'sshpass', '-p', password,
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'HostKeyAlgorithms=+ssh-rsa',
            '-o', 'KexAlgorithms=+diffie-hellman-group1-sha1',
            '-o', 'ConnectTimeout=3',
            f'{user}@{ip}',
            f'tail -n {lines} /var/log/auth.log 2>/dev/null'
        ]
        # Intento 1: con sudo (para usuarios no-root)
        ssh_cmd_sudo = ssh_cmd[:-1] + [
            f'echo {password} | sudo -S tail -n {lines} /var/log/auth.log 2>/dev/null'
        ]
        result = subprocess.run(ssh_cmd_sudo, capture_output=True, text=True, timeout=5)
        raw = result.stdout.strip()
        # Filtrar línea "[sudo] password for ..." que va a stdout en algunos sistemas
        raw = '\n'.join(l for l in raw.splitlines() if not l.startswith('[sudo]'))

        # Intento 2: sin sudo (para root u otros con acceso directo)
        if not raw:
            result2 = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=5)
            raw = result2.stdout.strip()

        if not raw:
            return [{'error': f'No output — stderr: {result.stderr[:200]}', 'ip': ip}]
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
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    assets = []
    try:
        from shared.auth import create_access_token
        _svc_token = create_access_token("scanops_service", "service")
        async with httpx.AsyncClient(verify=False, timeout=8) as client:
            r = await client.get(
                "http://scanops-m1:8001/api/v1/assets?page=1&page_size=100",
                headers={"Authorization": f"Bearer {_svc_token}"}
            )
            if r.status_code == 200:
                assets = r.json().get('items', [])
    except Exception as e:
        logger.warning(f"M1 assets fetch failed: {e}")

    if not assets:
        return {
            'total': 0, 'events': [], 'server_stats': [], 'brute_force_ips': [],
            'info': 'No hay activos registrados con credenciales SSH en M1',
        }

    def _fetch_asset(asset: dict) -> list[dict]:
        ip = asset.get('ip')
        if not ip:
            return []
        ssh_user = asset.get('ssh_user') or 'admin'
        ssh_pass = asset.get('ssh_password') or 'test123'
        events = _ssh_read_auth_log(ip, ssh_user, ssh_pass, lines=limit)
        enriched = []
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
            enriched.append(ev)
        return enriched

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=min(len(assets), 10)) as pool:
        futures = [loop.run_in_executor(pool, _fetch_asset, a) for a in assets]
        asset_results = await asyncio.gather(*futures)

    results = [ev for evs in asset_results for ev in evs]

    results.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    results = results[:limit]

    # Agrupar estadísticas por servidor
    stats: dict[str, dict] = {}
    for ev in results:
        key = ev.get('agent_ip', 'unknown')
        if key not in stats:
            stats[key] = {
                'agent_name':     ev.get('agent_name', key),
                'agent_ip':       key,
                'total':          0,
                'failures':       0,
                'successes':      0,
                'sudo_cmds':      0,
                'unique_ips':     set(),
                'unique_users':   set(),
                'critical_count': 0,
                'high_count':     0,
            }
        s = stats[key]
        s['total'] += 1
        if ev.get('success'):
            s['successes'] += 1
        else:
            s['failures'] += 1
        if ev.get('action_type') == 'SUDO_COMMAND':
            s['sudo_cmds'] += 1
        if ev.get('src_ip'):
            s['unique_ips'].add(ev['src_ip'])
        if ev.get('src_user'):
            s['unique_users'].add(ev['src_user'])
        if ev.get('severity') == 'CRITICAL':
            s['critical_count'] += 1
        elif ev.get('severity') == 'HIGH':
            s['high_count'] += 1

    srv_stats = []
    for s in stats.values():
        srv_stats.append({
            **s,
            'unique_ips':   list(s['unique_ips']),
            'unique_users': list(s['unique_users']),
        })

    # Detección brute force: >=5 fallos SSH desde misma IP en últimos 10 min
    cutoff = datetime.now(_tz.utc) - timedelta(minutes=10)
    bf_counter: dict[str, int] = {}
    for ev in results:
        if not ev.get('success') and ev.get('src_ip'):
            try:
                ts = datetime.fromisoformat(ev['timestamp'])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=_tz.utc)
                if ts > cutoff:
                    bf_counter[ev['src_ip']] = bf_counter.get(ev['src_ip'], 0) + 1
            except Exception:
                pass
    brute_force_ips = [ip for ip, count in bf_counter.items() if count >= 5]

    return {
        'total':           len(results),
        'events':          results,
        'server_stats':    srv_stats,
        'brute_force_ips': brute_force_ips,
    }


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRÍA AGENTLESS — recolección multi-fuente vía SSH (sin instalar agentes)
# Cada activo registrado en M1 con SSH credentials es monitorizado
# automáticamente. ENS: op.exp.4 | op.exp.5 | op.mon.1
# ─────────────────────────────────────────────────────────────────────────────

def _ssh_run(ip: str, user: str, password: str, cmd: str, timeout: int = 5) -> str:
    """Ejecuta un comando remoto via SSH con sshpass. Retorna stdout o vacío."""
    import subprocess
    base = [
        'sshpass', '-p', password,
        'ssh',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'HostKeyAlgorithms=+ssh-rsa',
        '-o', 'KexAlgorithms=+diffie-hellman-group1-sha1',
        '-o', 'ConnectTimeout=3',
        f'{user}@{ip}',
    ]
    # Intentar con sudo primero, luego sin sudo
    for cmd_variant in [
        f'echo {password} | sudo -S bash -c "{cmd}" 2>/dev/null',
        cmd,
    ]:
        try:
            r = subprocess.run(base + [cmd_variant], capture_output=True, text=True, timeout=timeout)
            out = r.stdout.strip()
            out = '\n'.join(l for l in out.splitlines() if not l.startswith('[sudo]'))
            if out:
                return out
        except Exception:
            pass
    return ''


# ─── Patrones de detección web (Apache/Nginx access.log) ───

_WEB_ATTACK_PATTERNS = [
    # DVWA / bWAPP — endpoints de vulnerabilidades conocidas (acceso = explotación activa)
    (re.compile(r"POST .*/vulnerabilities/(exec|sqli|sqli_blind|upload|fi|csrf|xss)", re.IGNORECASE),
                'DVWA_EXPLOIT', 'CRITICAL', 'TA0002', 'T1190'),
    (re.compile(r"GET .*/vulnerabilities/(exec|sqli|sqli_blind|fi)", re.IGNORECASE),
                'DVWA_EXPLOIT', 'CRITICAL', 'TA0002', 'T1190'),
    (re.compile(r"/(phpmyadmin|pma|myadmin|mysqladmin)/", re.IGNORECASE),
                'PHPMYADMIN_ACCESS', 'HIGH', 'TA0001', 'T1190'),
    # Juice Shop endpoints de explotación
    (re.compile(r"(api/users|rest/user/login|api/basket|api/products.*q=)", re.IGNORECASE),
                'JUICESHOP_ENUM', 'MEDIUM', 'TA0001', 'T1595'),
    # SQL Injection
    (re.compile(r"(%27|'|%22|\"|--|%23|#|%3B|;)\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE|CAST|CONVERT|CHAR|DECLARE|WAITFOR)",
                re.IGNORECASE), 'SQL_INJECTION', 'CRITICAL', 'TA0001', 'T1190'),
    (re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE), 'SQL_INJECTION_UNION', 'CRITICAL', 'TA0001', 'T1190'),
    # Command/RCE
    (re.compile(r"(%3B|;|%7C|\|)\s*(ls|id|whoami|cat|wget|curl|bash|sh|python|perl|ruby|nc|netcat|ncat)",
                re.IGNORECASE), 'COMMAND_INJECTION', 'CRITICAL', 'TA0002', 'T1059'),
    (re.compile(r"(eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(", re.IGNORECASE),
                'RCE_ATTEMPT', 'CRITICAL', 'TA0002', 'T1059'),
    # Path traversal
    (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f){2,}", re.IGNORECASE),
                'PATH_TRAVERSAL', 'HIGH', 'TA0005', 'T1083'),
    # Web shells
    (re.compile(r"\.(php|asp|aspx|jsp|cgi)\?.*=(ls|id|whoami|cat\s|wget|curl|bash)", re.IGNORECASE),
                'WEBSHELL_EXEC', 'CRITICAL', 'TA0002', 'T1505'),
    # Scanners y enumeración — User-Agent y rutas típicas
    (re.compile(r"(gobuster|nikto|sqlmap|nmap|masscan|dirb|dirbuster|wfuzz|ffuf|hydra|medusa|DirBuster|w3af|burpsuite|ZAP|python-requests|Go-http-client)",
                re.IGNORECASE), 'SCANNER_DETECTED', 'HIGH', 'TA0043', 'T1595'),
    # Enumeración de directorios (rutas típicas de wordlists)
    (re.compile(r'" 404 .*(admin|backup|config|\.git|\.env|wp-admin|shell|cmd|upload|include)', re.IGNORECASE),
                'DIR_ENUM_404', 'MEDIUM', 'TA0043', 'T1595'),
    # XSS
    (re.compile(r"<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\s*\(", re.IGNORECASE),
                'XSS_ATTEMPT', 'MEDIUM', 'TA0001', 'T1189'),
    # Fuerza bruta web
    (re.compile(r"(wp-login\.php|phpmyadmin|admin/login|/login\.php).*POST.*4[0-9]{2}",
                re.IGNORECASE), 'BRUTE_FORCE_WEB', 'HIGH', 'TA0006', 'T1110'),
    # File upload
    (re.compile(r"(upload|file_upload|fileupload).*\.(php|asp|aspx|jsp|phtml|php5|phar)",
                re.IGNORECASE), 'MALICIOUS_UPLOAD', 'CRITICAL', 'TA0002', 'T1505'),
    # LFI/RFI
    (re.compile(r"(include|require|include_once|require_once)\s*[=(].*?(http://|https://|//|php://|data://|file://)",
                re.IGNORECASE), 'FILE_INCLUSION', 'CRITICAL', 'TA0005', 'T1083'),
    # HTTP 500 masivo (puede indicar ataque activo)
    (re.compile(r'" 500 '), 'HTTP_500_ERROR', 'LOW', '', ''),
]

_WEB_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def _parse_web_log_line(line: str, asset: dict) -> dict | None:
    """Parsea una línea de access.log (Apache/Nginx) y detecta ataques."""
    if not line.strip():
        return None

    for pattern, attack_type, severity, tactic, technique in _WEB_ATTACK_PATTERNS:
        if pattern.search(line):
            m = _WEB_LOG_RE.match(line)
            src_ip = m.group('ip') if m else None
            req    = m.group('req') if m else line[:200]
            status = m.group('status') if m else ''
            ua     = m.group('ua') if m else ''
            raw_ts = m.group('ts') if m else ''
            # Parsear timestamp Apache: "17/Jun/2026:09:15:33 +0200"
            ts_iso = datetime.now(_tz.utc).isoformat()
            try:
                ts_iso = datetime.strptime(raw_ts[:20], '%d/%b/%Y:%H:%M:%S').replace(tzinfo=_tz.utc).isoformat()
            except Exception:
                pass
            return {
                'timestamp':      ts_iso,
                'source':         'web_log',
                'log_source':     'apache/nginx access.log',
                'action_type':    attack_type,
                'severity':       severity,
                'success':        False,
                'src_ip':         src_ip,
                'src_user':       None,
                'message':        f'{attack_type}: {req[:150]}',
                'raw_log':        line[:300],
                'http_status':    status,
                'user_agent':     ua[:100] if ua else '',
                'agent_name':     asset.get('name') or asset.get('hostname') or asset.get('ip'),
                'agent_ip':       asset.get('ip'),
                'agent_id':       str(asset.get('id', '')),
                'alert_id':       f"web-{asset.get('ip')}-{ts_iso}-{attack_type}",
                'rule_id':        attack_type,
                'rule_desc':      f'Web attack detected: {attack_type}',
                'mitre_tactic':   tactic,
                'mitre_technique': technique,
            }
    return None


# ─── Patrones de detección syslog ───

_SYSLOG_ATTACK_PATTERNS = [
    (re.compile(r'(kernel|audit).*?(oom|Out of memory|Killed process)', re.IGNORECASE),
                'OOM_KILL', 'HIGH', '', ''),
    (re.compile(r'segfault|segmentation fault', re.IGNORECASE),
                'SEGFAULT', 'MEDIUM', '', ''),
    (re.compile(r'cron.*(/tmp/|/dev/shm/|wget|curl|bash\s+-[ci])', re.IGNORECASE),
                'SUSPICIOUS_CRON', 'CRITICAL', 'TA0003', 'T1053'),
    (re.compile(r'(useradd|adduser|usermod|groupadd).*root', re.IGNORECASE),
                'PRIVILEGE_ESCALATION', 'CRITICAL', 'TA0004', 'T1136'),
    (re.compile(r'iptables.*DROP|ufw.*BLOCK', re.IGNORECASE),
                'FIREWALL_BLOCK', 'LOW', '', ''),
    (re.compile(r'(nmap|masscan|gobuster|nikto|sqlmap|hydra)\[', re.IGNORECASE),
                'ATTACK_TOOL_EXEC', 'CRITICAL', 'TA0043', 'T1595'),
    (re.compile(r'(nc|netcat|ncat)\s+(-e|-c|--exec)', re.IGNORECASE),
                'REVERSE_SHELL', 'CRITICAL', 'TA0002', 'T1059'),
    (re.compile(r'ptrace|strace.*passwd|ltrace.*crypt', re.IGNORECASE),
                'PROCESS_TRACE', 'HIGH', 'TA0006', 'T1003'),
]

_SYSLOG_TS_RE_ISO     = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)')
_SYSLOG_TS_RE_CLASSIC = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})')


def _parse_syslog_line(line: str, asset: dict) -> dict | None:
    if not line.strip():
        return None
    for pattern, attack_type, severity, tactic, technique in _SYSLOG_ATTACK_PATTERNS:
        if pattern.search(line):
            ts_iso = datetime.now(_tz.utc).isoformat()
            m = _SYSLOG_TS_RE_ISO.match(line)
            if m:
                try:
                    ts_iso = datetime.fromisoformat(m.group(1)).isoformat()
                except Exception:
                    pass
            return {
                'timestamp':      ts_iso,
                'source':         'syslog',
                'log_source':     'syslog/messages',
                'action_type':    attack_type,
                'severity':       severity,
                'success':        False,
                'src_ip':         None,
                'src_user':       None,
                'message':        f'{attack_type}: {line[:200]}',
                'raw_log':        line[:300],
                'http_status':    '',
                'user_agent':     '',
                'agent_name':     asset.get('name') or asset.get('hostname') or asset.get('ip'),
                'agent_ip':       asset.get('ip'),
                'agent_id':       str(asset.get('id', '')),
                'alert_id':       f"sys-{asset.get('ip')}-{ts_iso}-{attack_type}",
                'rule_id':        attack_type,
                'rule_desc':      f'Syslog anomaly: {attack_type}',
                'mitre_tactic':   tactic,
                'mitre_technique': technique,
            }
    return None


# ─── Recolección de procesos sospechosos ───

_SUSPICIOUS_PROCESSES = [
    'nmap', 'masscan', 'gobuster', 'nikto', 'sqlmap', 'hydra', 'medusa',
    'john', 'hashcat', 'aircrack', 'metasploit', 'msfconsole', 'meterpreter',
    'nc', 'netcat', 'ncat', 'socat', 'cryptominer', 'xmrig', 'minerd',
    'tcpdump', 'wireshark', 'tshark', 'ettercap', 'arpspoof',
    'python3 -c', 'python -c', 'perl -e', 'bash -i', 'sh -i',
    'wget http', 'curl http', '/tmp/', '/dev/shm',
]


def _collect_host_telemetry(asset: dict) -> dict:
    """
    Recolecta telemetría completa de un activo vía SSH.
    No requiere instalar ningún agente en el destino.
    """
    ip       = asset.get('ip', '')
    user     = asset.get('ssh_user') or 'admin'
    password = asset.get('ssh_password') or 'test123'
    name     = asset.get('name') or asset.get('hostname') or ip

    events: list[dict] = []
    telemetry: dict = {
        'asset_ip':   ip,
        'asset_id':   str(asset.get('id', '')),
        'asset_name': name,
        'reachable':  False,
        'collected_at': datetime.now(_tz.utc).isoformat(),
        'events':       [],
        'processes':    [],
        'connections':  [],
        'open_ports':   [],
        'disk_usage':   [],
        'last_logins':  [],
        'errors':       [],
    }

    # ── 1. Comprobación de conectividad ──
    probe = _ssh_run(ip, user, password, 'echo OK', timeout=4)
    if probe.strip() != 'OK':
        telemetry['errors'].append('SSH unreachable or auth failed')
        return telemetry
    telemetry['reachable'] = True

    # ── 2. Logs web (Apache + Nginx) — host ──
    web_log_paths = [
        '/var/log/apache2/access.log',
        '/var/log/apache2/other_vhosts_access.log',
        '/var/log/nginx/access.log',
        '/var/log/httpd/access_log',
    ]
    for log_path in web_log_paths:
        raw = _ssh_run(ip, user, password, f'tail -n 300 {log_path} 2>/dev/null')
        for line in raw.splitlines():
            ev = _parse_web_log_line(line, asset)
            if ev:
                events.append(ev)

    # ── 2b. Logs web dentro de contenedores Docker en el activo ──
    # Apps web (DVWA, Juice Shop, bWAPP) corren como contenedores Docker.
    # Sus logs Apache/Nginx están dentro de los contenedores, no en el host.
    # Usamos "docker logs" que lee stdout/stderr del contenedor sin TTY.
    docker_containers_raw = _ssh_run(
        ip, user, password,
        "docker ps --format '{{.Names}}' 2>/dev/null",
        timeout=5,
    )
    container_names = [c.strip() for c in docker_containers_raw.splitlines() if c.strip()]

    for container in container_names:
        raw = _ssh_run(
            ip, user, password,
            f'docker logs --tail 300 {container} 2>&1',
            timeout=6,
        )
        for line in raw.splitlines():
            ev = _parse_web_log_line(line, asset)
            if ev:
                ev['log_source'] = f'docker:{container}'
                events.append(ev)

    # ── 3. Syslog / messages ──
    for log_path in ['/var/log/syslog', '/var/log/messages']:
        raw = _ssh_run(ip, user, password, f'tail -n 200 {log_path} 2>/dev/null')
        for line in raw.splitlines():
            ev = _parse_syslog_line(line, asset)
            if ev:
                events.append(ev)

    # ── 4. Auth log ──
    raw = _ssh_run(ip, user, password, 'tail -n 300 /var/log/auth.log 2>/dev/null')
    year = datetime.now().year
    for line in raw.splitlines():
        ev = _parse_auth_log_line(line, year)
        if ev:
            ev.update({
                'source':     'auth_log',
                'log_source': 'auth.log',
                'agent_name': name,
                'agent_ip':   ip,
                'agent_id':   str(asset.get('id', '')),
                'alert_id':   f"auth-{ip}-{ev.get('timestamp','')}",
                'rule_id':    'auth.log',
                'rule_desc':  ev.get('message', ''),
                'mitre_tactic':    'TA0006' if not ev.get('success') else '',
                'mitre_technique': 'T1110' if 'Failed password' in ev.get('message','') else '',
            })
            events.append(ev)

    # ── 5. Audit log (/var/log/audit/audit.log) ──
    raw = _ssh_run(ip, user, password, 'tail -n 200 /var/log/audit/audit.log 2>/dev/null')
    for line in raw.splitlines():
        if 'execve' in line and ('SYSCALL' in line or 'EXECVE' in line):
            # Extraer comando ejecutado
            cmd_match = re.search(r'a0="([^"]+)"', line)
            cmd = cmd_match.group(1) if cmd_match else ''
            ts_iso = datetime.now(_tz.utc).isoformat()
            m = re.search(r'msg=audit\((\d+)', line)
            if m:
                try:
                    ts_iso = datetime.fromtimestamp(float(m.group(1)), tz=_tz.utc).isoformat()
                except Exception:
                    pass
            # Detectar comandos sospechosos
            suspicious = any(s in line.lower() for s in [
                'nmap', 'nc ', 'netcat', 'wget', 'curl', '/tmp/', 'python', 'perl',
                'bash -i', 'sh -i', '/dev/shm', 'chmod +x',
            ])
            if suspicious:
                events.append({
                    'timestamp':      ts_iso,
                    'source':         'audit_log',
                    'log_source':     'audit.log',
                    'action_type':    'SUSPICIOUS_EXEC',
                    'severity':       'HIGH',
                    'success':        True,
                    'src_ip':         None,
                    'src_user':       None,
                    'message':        f'Suspicious command: {cmd or line[:150]}',
                    'raw_log':        line[:300],
                    'http_status':    '',
                    'user_agent':     '',
                    'agent_name':     name,
                    'agent_ip':       ip,
                    'agent_id':       str(asset.get('id', '')),
                    'alert_id':       f"audit-{ip}-{ts_iso}",
                    'rule_id':        'SUSPICIOUS_EXEC',
                    'rule_desc':      'Suspicious process execution detected via auditd',
                    'mitre_tactic':   'TA0002',
                    'mitre_technique': 'T1059',
                })

    # ── 6. Lista de procesos activos ──
    raw = _ssh_run(ip, user, password, 'ps aux --no-headers 2>/dev/null | head -50')
    processes = []
    for line in raw.splitlines():
        parts = line.split(None, 10)
        if len(parts) >= 11:
            cmd_full = parts[10]
            is_suspicious = any(s in cmd_full.lower() for s in _SUSPICIOUS_PROCESSES)
            proc = {
                'user':    parts[0],
                'pid':     parts[1],
                'cpu':     parts[2],
                'mem':     parts[3],
                'command': cmd_full[:150],
                'suspicious': is_suspicious,
            }
            processes.append(proc)
            if is_suspicious:
                events.append({
                    'timestamp':      datetime.now(_tz.utc).isoformat(),
                    'source':         'process_list',
                    'log_source':     'ps aux',
                    'action_type':    'SUSPICIOUS_PROCESS',
                    'severity':       'HIGH',
                    'success':        True,
                    'src_ip':         None,
                    'src_user':       parts[0],
                    'message':        f'Suspicious process running: {cmd_full[:120]}',
                    'raw_log':        line[:300],
                    'http_status':    '',
                    'user_agent':     '',
                    'agent_name':     name,
                    'agent_ip':       ip,
                    'agent_id':       str(asset.get('id', '')),
                    'alert_id':       f"proc-{ip}-{parts[1]}",
                    'rule_id':        'SUSPICIOUS_PROCESS',
                    'rule_desc':      'Suspicious process found via ps aux',
                    'mitre_tactic':   'TA0002',
                    'mitre_technique': 'T1059',
                })
    telemetry['processes'] = processes

    # ── 7. Conexiones de red ──
    raw = _ssh_run(ip, user, password,
        'ss -antup 2>/dev/null || netstat -antup 2>/dev/null | head -60')
    connections = []
    for line in raw.splitlines()[1:]:  # skip header
        if 'ESTABLISHED' in line or 'LISTEN' in line:
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    'state':   parts[0] if len(parts) > 0 else '',
                    'local':   parts[3] if len(parts) > 3 else '',
                    'remote':  parts[4] if len(parts) > 4 else '',
                    'process': parts[-1] if len(parts) > 5 else '',
                })
    telemetry['connections'] = connections[:30]

    # ── 8. Últimos logins ──
    raw = _ssh_run(ip, user, password, 'last -n 10 2>/dev/null')
    telemetry['last_logins'] = [l for l in raw.splitlines() if l.strip()][:10]

    # ── 9. Uso de disco (alerta si >90%) ──
    raw = _ssh_run(ip, user, password, 'df -h --output=pcent,target 2>/dev/null | tail -n +2')
    disk_usage = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                pct = int(parts[0].rstrip('%'))
                disk_usage.append({'mount': parts[1], 'used_pct': pct})
                if pct >= 90:
                    events.append({
                        'timestamp':      datetime.now(_tz.utc).isoformat(),
                        'source':         'system',
                        'log_source':     'df',
                        'action_type':    'DISK_CRITICAL',
                        'severity':       'HIGH',
                        'success':        False,
                        'src_ip':         None,
                        'src_user':       None,
                        'message':        f'Disk usage {pct}% on {parts[1]}',
                        'raw_log':        line,
                        'http_status':    '',
                        'user_agent':     '',
                        'agent_name':     name,
                        'agent_ip':       ip,
                        'agent_id':       str(asset.get('id', '')),
                        'alert_id':       f"disk-{ip}-{parts[1]}",
                        'rule_id':        'DISK_CRITICAL',
                        'rule_desc':      'Disk usage above 90%',
                        'mitre_tactic':   '',
                        'mitre_technique': '',
                    })
            except ValueError:
                pass
    telemetry['disk_usage'] = disk_usage

    telemetry['events'] = events
    return telemetry


@router.get("/siem/host-telemetry")
async def get_host_telemetry(limit: int = 200):
    """
    Telemetría agentless multi-fuente para todos los activos registrados en M1.
    Recolecta vía SSH: logs web, syslog, auth.log, audit.log, procesos, conexiones.
    No requiere instalar ningún agente en los activos.
    ENS: op.exp.4 | op.exp.5 | op.mon.1
    """
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    assets = []
    try:
        from shared.auth import create_access_token
        token = create_access_token("scanops_service", "service")
        async with httpx.AsyncClient(verify=False, timeout=8) as client:
            r = await client.get(
                "http://scanops-m1:8001/api/v1/assets?page=1&page_size=100",
                headers={"Authorization": f"Bearer {token}"}
            )
            if r.status_code == 200:
                assets = r.json().get('items', [])
    except Exception as e:
        logger.warning(f"M1 assets fetch failed: {e}")

    if not assets:
        return {
            'total_events': 0,
            'assets_scanned': 0,
            'assets_reachable': 0,
            'events': [],
            'host_summaries': [],
            'info': 'No hay activos registrados con credenciales SSH en M1',
        }

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=min(len(assets), 10)) as pool:
        futures = [loop.run_in_executor(pool, _collect_host_telemetry, a) for a in assets]
        results = await asyncio.gather(*futures)

    all_events: list[dict] = []
    host_summaries: list[dict] = []
    reachable = 0

    for tel in results:
        if tel['reachable']:
            reachable += 1

        events = tel.get('events', [])
        all_events.extend(events)

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        sources_seen: set[str] = set()
        for ev in events:
            sev = ev.get('severity', 'INFO')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            sources_seen.add(ev.get('log_source', 'unknown'))

        host_summaries.append({
            'asset_ip':       tel['asset_ip'],
            'asset_id':       tel['asset_id'],
            'asset_name':     tel['asset_name'],
            'reachable':      tel['reachable'],
            'collected_at':   tel['collected_at'],
            'total_events':   len(events),
            'severity_counts': severity_counts,
            'log_sources':    list(sources_seen),
            'processes':      tel.get('processes', []),
            'connections':    tel.get('connections', []),
            'last_logins':    tel.get('last_logins', []),
            'disk_usage':     tel.get('disk_usage', []),
            'errors':         tel.get('errors', []),
        })

    all_events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    all_events = all_events[:limit]

    return {
        'total_events':    len(all_events),
        'assets_scanned':  len(assets),
        'assets_reachable': reachable,
        'events':          all_events,
        'host_summaries':  host_summaries,
    }