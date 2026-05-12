"""
US-6.2 — Agentes Wazuh en activos M1
ENS: op.exp.5
"""
import os
import asyncio
import paramiko
import httpx
from datetime import datetime
from fastapi import APIRouter
from shared.scan_logger import ScanLogger
from .db import get_conn
from .wazuh_client import wazuh_get, wazuh_post, WAZUH_API

logger = ScanLogger("siem_engine.agents")
router = APIRouter(tags=["US-6.2 Wazuh Agents"])

M1_URL = os.getenv("M1_URL", "http://m1:8001")
SCANOPS_API_KEY = os.getenv("SCANOPS_API_KEY", "scanops_secret")
WAZUH_MANAGER_IP = os.getenv("WAZUH_MANAGER_IP", "scanops-wazuh")

# --- FIM syscheck config que se inyecta en ossec.conf del agente ---
_SYSCHECK = """
<syscheck>
  <frequency>300</frequency>
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
  <directories check_all="yes">/var/ossec</directories>
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/mnttab</ignore>
</syscheck>
"""

_INSTALL_SCRIPT = """
set -e
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq
apt-get install -y wazuh-agent 2>/dev/null || true
"""

_OSSEC_CLIENT_CONF = """<ossec_config>
  <client>
    <server>
      <address>{manager_ip}</address>
      <port>1514</port>
      <protocol>udp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
    </enrollment>
  </client>
{syscheck}
</ossec_config>
"""


async def _get_assets() -> list:
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            f"{M1_URL}/api/v1/assets",
            headers={"Authorization": f"Bearer {SCANOPS_API_KEY}"},
        )
        resp.raise_for_status()
        data = resp.json()
        items = data.get("items", data) if isinstance(data, dict) else data
        return [
            a for a in items
            if a.get("status") == "ACTIVO"
            and a.get("tipo", "").upper() in ("SERVER", "SERVIDOR")
        ]


def _get_vault_creds(vault_path: str | None, asset_ip: str) -> dict | None:
    if not vault_path:
        return None
    try:
        from shared.vault_client import vault_client
        return vault_client.read_credentials(vault_path)
    except Exception as e:
        logger.warning(f"Vault error para {asset_ip}: {e}")
        return None


def _ssh_deploy(asset_ip: str, creds: dict) -> tuple[bool, str]:
    """Intenta instalación SSH. Devuelve (ok, detalle)."""
    ssh_user = creds.get("ssh_user") or creds.get("username", "root")
    ssh_pass = creds.get("ssh_password") or creds.get("password")
    ssh_key = creds.get("ssh_key")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs: dict = {"hostname": asset_ip, "username": ssh_user, "timeout": 20}
        if ssh_key:
            import io
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(ssh_key))
            connect_kwargs["pkey"] = pkey
        elif ssh_pass:
            connect_kwargs["password"] = ssh_pass
        else:
            return False, "Sin credenciales SSH disponibles"

        client.connect(**connect_kwargs)

        # Instalar agente
        _, stdout, stderr = client.exec_command(_INSTALL_SCRIPT, timeout=120)
        stdout.channel.recv_exit_status()

        # Configurar ossec.conf
        conf = _OSSEC_CLIENT_CONF.format(
            manager_ip=WAZUH_MANAGER_IP,
            syscheck=_SYSCHECK,
        )
        _, _, _ = client.exec_command(
            f"cat > /var/ossec/etc/ossec.conf << 'EOFCONF'\n{conf}\nEOFCONF", timeout=15
        )

        # Arrancar agente
        _, _, _ = client.exec_command(
            "systemctl enable wazuh-agent 2>/dev/null; systemctl start wazuh-agent 2>/dev/null || true",
            timeout=30,
        )
        client.close()
        return True, "ok"
    except Exception as e:
        return False, str(e)


def _register_agent_wazuh_sync(name: str, ip: str) -> str | None:
    """Registra agente via API Wazuh y devuelve el agent_id."""
    import asyncio

    async def _reg():
        try:
            data = await wazuh_post("/agents", {"name": name, "ip": ip})
            return data.get("data", {}).get("id")
        except Exception:
            return None

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, _reg())
                return future.result(timeout=15)
        return loop.run_until_complete(_reg())
    except Exception:
        return None


def _persist_agent(asset_id: int, agent_id: str | None, name: str, ip: str, status: str) -> None:
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO siem_agents (asset_id, wazuh_agent_id, agent_name, agent_ip, status)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (asset_id, agent_id, name, ip, status))
    finally:
        conn.close()


@router.post("/siem/agents/deploy")
async def deploy_agents():
    """Despliega agentes Wazuh en activos Linux/Servidor activos de M1."""
    results = []
    try:
        assets = await _get_assets()
    except Exception as e:
        logger.error(f"No se pudo obtener activos de M1: {e}")
        return {"deployed": 0, "errors": 1, "results": [{"error": str(e)}]}

    for asset in assets:
        asset_id = asset.get("id")
        asset_ip = asset.get("ip", "")
        hostname = asset.get("hostname") or asset_ip
        entry: dict = {"asset_id": asset_id, "ip": asset_ip, "name": hostname}

        creds = _get_vault_creds(asset.get("vault_path"), asset_ip)
        if not creds:
            entry["status"] = "unreachable"
            entry["detail"] = "Sin credenciales SSH en Vault"
            _persist_agent(asset_id, None, hostname, asset_ip, "unreachable")
            results.append(entry)
            logger.warning(f"[US-6.2] {asset_ip} → sin creds Vault, marcado unreachable")
            continue

        ok, detail = await asyncio.to_thread(_ssh_deploy, asset_ip, creds)
        if not ok:
            entry["status"] = "unreachable"
            entry["detail"] = detail
            _persist_agent(asset_id, None, hostname, asset_ip, "unreachable")
            logger.warning(f"[US-6.2] SSH failed {asset_ip}: {detail}")
        else:
            agent_id = await asyncio.to_thread(
                _register_agent_wazuh_sync, hostname, asset_ip
            )
            _persist_agent(asset_id, agent_id, hostname, asset_ip, "deployed")
            entry["status"] = "deployed"
            entry["wazuh_agent_id"] = agent_id
            logger.info(f"[US-6.2] Agente desplegado en {asset_ip}, wazuh_id={agent_id}")

        results.append(entry)

    deployed = sum(1 for r in results if r.get("status") == "deployed")
    return {
        "deployed": deployed,
        "unreachable": len(results) - deployed,
        "total": len(results),
        "results": results,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/siem/agents")
async def list_agents():
    """Lista agentes desde Wazuh Manager con campos ENS."""
    data = await wazuh_get("/agents?limit=500&status=active,disconnected,pending,never_connected")
    raw_agents = data.get("data", {}).get("affected_items", [])
    agents = []
    for a in raw_agents:
        agents.append({
            "id": a.get("id"),
            "name": a.get("name"),
            "ip": a.get("ip"),
            "status": a.get("status"),
            "os": a.get("os", {}).get("name") if a.get("os") else None,
            "last_keep_alive": a.get("lastKeepAlive"),
        })
    return {"total": len(agents), "agents": agents, "timestamp": datetime.utcnow().isoformat()}
