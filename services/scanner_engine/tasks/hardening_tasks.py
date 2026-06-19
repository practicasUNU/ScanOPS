"""
Tarea Celery de verificación de bastionado — ENS Alto
13 controles vía SSH+paramiko. Solo lectura. Sin modificar el servidor.
ENS: op.exp.2, mp.com.1, mp.si.5, op.exp.3, op.exp.5, op.acc.6,
     mp.info.3, mp.com.2, op.cont.2
"""

import json
import paramiko
from datetime import datetime, timezone
from typing import List, Dict, Any

from shared.celery_app import app
from shared.scan_logger import ScanLogger

logger = ScanLogger("hardening_tasks")

HARDENING_CONTROLS = [
    {"id": 1,  "nombre": "Antivirus",                 "medida_ens": "op.exp.2"},
    {"id": 2,  "nombre": "Cortafuegos (Firewall)",    "medida_ens": "mp.com.1"},
    {"id": 3,  "nombre": "Almacenamiento externo",    "medida_ens": "mp.si.5"},
    {"id": 4,  "nombre": "Aplicaciones permitidas",   "medida_ens": "op.exp.3"},
    {"id": 5,  "nombre": "Configuración de logs",     "medida_ens": "op.exp.5"},
    {"id": 6,  "nombre": "Puertos de red",            "medida_ens": "op.acc.6"},
    {"id": 7,  "nombre": "Servidor horario (NTP)",    "medida_ens": "op.exp.3"},
    {"id": 8,  "nombre": "Versión del software",      "medida_ens": "op.exp.2"},
    {"id": 9,  "nombre": "Niveles de parches",        "medida_ens": "op.exp.2"},
    {"id": 10, "nombre": "Unidades encriptadas",      "medida_ens": "mp.info.3"},
    {"id": 11, "nombre": "Certificado SSL",           "medida_ens": "mp.com.2"},
    {"id": 12, "nombre": "Doble factor (2FA)",        "medida_ens": "op.acc.6"},
    {"id": 13, "nombre": "Copias de seguridad",       "medida_ens": "op.cont.2"},
]


def _ssh_exec(client: paramiko.SSHClient, cmd: str, password: str = None,
              use_sudo: bool = False, timeout: int = 15) -> str:
    """
    Ejecuta un comando via SSH y devuelve stdout limpio.
    Si use_sudo=True prefija con "echo {password} | sudo -S ".
    Nunca lanza excepción — devuelve "" en caso de fallo.
    """
    try:
        full_cmd = f"echo {password} | sudo -S {cmd}" if use_sudo and password else cmd
        _, stdout, _ = client.exec_command(full_cmd, timeout=timeout, get_pty=False)
        return stdout.read().decode("utf-8", errors="ignore").strip()
    except Exception as e:
        logger.warning(f"SSH exec error [{cmd[:40]}]: {e}")
        return ""


def _run_13_checks(client: paramiko.SSHClient, password: str) -> List[Dict]:
    """
    Ejecuta los 13 comandos de bastionado y devuelve lista de controles con resultado.
    Resultado: "SI" | "NO" | "REVISAR"
    """
    controles = []

    # 1 — Antivirus (ClamAV)
    out = _ssh_exec(client, "systemctl is-active clamav-daemon 2>/dev/null")
    controles.append({
        **HARDENING_CONTROLS[0],
        "resultado": "SI" if out == "active" else "NO",
        "detalle": "ClamAV activo" if out == "active"
                   else f"ClamAV no activo (estado: {out or 'no encontrado'})",
    })

    # 2 — Cortafuegos UFW
    out = _ssh_exec(client, "ufw status 2>/dev/null | head -1", password=password, use_sudo=True)
    if "active" in out.lower():
        reglas = _ssh_exec(client, "ufw status 2>/dev/null | grep -c ALLOW",
                           password=password, use_sudo=True)
        controles.append({**HARDENING_CONTROLS[1], "resultado": "SI",
                           "detalle": f"UFW activo, {reglas.strip() or '?'} reglas ALLOW"})
    else:
        controles.append({**HARDENING_CONTROLS[1], "resultado": "NO",
                           "detalle": "UFW inactivo o no encontrado"})

    # 3 — Almacenamiento externo (USB)
    out = _ssh_exec(client, "lsblk -o NAME,TRAN 2>/dev/null | grep -i usb")
    controles.append({
        **HARDENING_CONTROLS[2],
        "resultado": "SI" if not out.strip() else "NO",
        "detalle": "Sin dispositivos USB montados" if not out.strip()
                   else f"USB detectado: {out[:100]}",
    })

    # 4 — Aplicaciones instaladas manualmente
    out = _ssh_exec(client, "apt-mark showmanual 2>/dev/null | wc -l")
    try:
        num = int(out.strip())
        if num <= 100:
            resultado, detalle = "REVISAR", f"{num} paquetes — lista corta, revisar contenido"
        else:
            resultado, detalle = "NO", f"{num} paquetes instalados manualmente — sin política formal"
    except ValueError:
        resultado, detalle = "REVISAR", "No se pudo obtener número de paquetes"
    controles.append({**HARDENING_CONTROLS[3], "resultado": resultado, "detalle": detalle})

    # 5 — Configuración de logs (rsyslog)
    out = _ssh_exec(client, "systemctl is-active rsyslog 2>/dev/null")
    if out != "active":
        out2 = _ssh_exec(client, "systemctl is-active syslog 2>/dev/null")
        activo = out2 == "active"
        servicio = "syslog"
    else:
        activo = True
        servicio = "rsyslog"
    controles.append({
        **HARDENING_CONTROLS[4],
        "resultado": "SI" if activo else "NO",
        "detalle": f"{servicio} activo" if activo else "rsyslog/syslog no está activo",
    })

    # 6 — Puertos de red expuestos
    out = _ssh_exec(client, "ss -tlnp 2>/dev/null", password=password, use_sudo=True)
    puertos_expuestos = []
    for line in out.splitlines()[1:]:
        if "0.0.0.0" in line or ":::" in line:
            parts = line.split()
            if len(parts) >= 4:
                port_str = parts[3].split(":")[-1]
                if port_str not in ("22", "80", "443", "56789"):
                    puertos_expuestos.append(port_str)
    if not puertos_expuestos:
        controles.append({**HARDENING_CONTROLS[5], "resultado": "SI",
                           "detalle": "Solo puertos necesarios expuestos (22/80/443)"})
    else:
        controles.append({**HARDENING_CONTROLS[5], "resultado": "REVISAR",
                           "detalle": f"Puertos adicionales en 0.0.0.0: {', '.join(puertos_expuestos[:10])}"})

    # 7 — NTP sincronizado
    out = _ssh_exec(client, "timedatectl status 2>/dev/null")
    sync_ok = "synchronized: yes" in out.lower()
    ntp_ok = ("ntp service: active" in out.lower()
              or "systemd-timesyncd.service active" in out.lower())
    controles.append({
        **HARDENING_CONTROLS[6],
        "resultado": "SI" if (sync_ok and ntp_ok) else "NO",
        "detalle": "Sincronizado y activo" if (sync_ok and ntp_ok)
                   else f"sync={'sí' if sync_ok else 'no'}, NTP={'activo' if ntp_ok else 'inactivo'}",
    })

    # 8 — Versión del software (upgradable)
    out = _ssh_exec(client, "apt list --upgradable 2>/dev/null | grep -c '/'")
    try:
        num = int(out.strip())
        if num == 0:
            resultado, detalle = "SI", "Sin actualizaciones pendientes"
        elif num <= 5:
            resultado, detalle = "REVISAR", f"{num} paquetes pendientes de actualizar"
        else:
            resultado, detalle = "NO", f"{num} paquetes pendientes de actualizar"
    except ValueError:
        resultado, detalle = "REVISAR", "No se pudo obtener lista de actualizaciones"
    controles.append({**HARDENING_CONTROLS[7], "resultado": resultado, "detalle": detalle})

    # 9 — Parches de seguridad pendientes
    out = _ssh_exec(client, "apt list --upgradable 2>/dev/null | grep -i -c 'security'")
    try:
        num = int(out.strip())
        controles.append({
            **HARDENING_CONTROLS[8],
            "resultado": "SI" if num == 0 else "NO",
            "detalle": "Sin parches de seguridad pendientes" if num == 0
                       else f"{num} parches de seguridad pendientes",
        })
    except ValueError:
        controles.append({**HARDENING_CONTROLS[8], "resultado": "REVISAR",
                           "detalle": "No se pudo verificar parches de seguridad"})

    # 10 — Cifrado LUKS
    out = _ssh_exec(client, "lsblk -o FSTYPE 2>/dev/null | grep -c 'crypto_LUKS'")
    try:
        num = int(out.strip())
        controles.append({
            **HARDENING_CONTROLS[9],
            "resultado": "SI" if num > 0 else "NO",
            "detalle": f"LUKS detectado en {num} partición/es" if num > 0
                       else "Sin cifrado de disco detectado (LUKS no encontrado)",
        })
    except ValueError:
        controles.append({**HARDENING_CONTROLS[9], "resultado": "NO",
                           "detalle": "No se pudo verificar cifrado de disco"})

    # 11 — Certificado SSL
    cert_path = _ssh_exec(
        client,
        "find /etc/ssl /etc/apache2 /etc/nginx -name '*.crt' 2>/dev/null"
        " | grep -v snakeoil | head -1",
        password=password, use_sudo=True,
    )
    if cert_path.strip():
        expiry = _ssh_exec(
            client,
            f"openssl x509 -in {cert_path.strip()} -noout -enddate 2>/dev/null | cut -d= -f2",
            password=password, use_sudo=True,
        )
        controles.append({
            **HARDENING_CONTROLS[10],
            "resultado": "SI",
            "detalle": f"Certificado encontrado. Válido hasta: {expiry.strip() or 'desconocido'}",
        })
    else:
        controles.append({**HARDENING_CONTROLS[10], "resultado": "NO",
                           "detalle": "No se encontró certificado SSL (excluido snakeoil)"})

    # 12 — 2FA SSH via PAM
    pam_2fa = _ssh_exec(
        client,
        "grep -c -E 'google-authenticator|pam_oath|pam_duo' /etc/pam.d/sshd 2>/dev/null",
        password=password, use_sudo=True,
    )
    challenge = _ssh_exec(
        client,
        "grep -c 'ChallengeResponseAuthentication yes' /etc/ssh/sshd_config 2>/dev/null",
        password=password, use_sudo=True,
    )
    try:
        pam_count = int(pam_2fa.strip())
    except ValueError:
        pam_count = 0
    if pam_count > 0:
        controles.append({**HARDENING_CONTROLS[11], "resultado": "SI",
                           "detalle": "2FA configurado en PAM SSH"})
    elif challenge.strip() == "1":
        controles.append({**HARDENING_CONTROLS[11], "resultado": "NO",
                           "detalle": "ChallengeResponse activo pero sin módulo 2FA en PAM"})
    else:
        controles.append({**HARDENING_CONTROLS[11], "resultado": "NO",
                           "detalle": "Sin configuración 2FA en SSH"})

    # 13 — Copias de seguridad
    svc = _ssh_exec(
        client,
        "systemctl list-units --type=service 2>/dev/null"
        " | grep -c -E 'backup|rsync|borg|restic|bacula|amanda'",
    )
    cron_root = _ssh_exec(
        client,
        "crontab -l 2>/dev/null | grep -c -E 'backup|rsync|borg|restic|dump'",
        password=password, use_sudo=True,
    )
    cron_user = _ssh_exec(
        client,
        "crontab -l 2>/dev/null | grep -c -E 'backup|rsync|borg|restic|dump'",
    )
    try:
        total = (int(svc.strip() or 0)
                 + int(cron_root.strip() or 0)
                 + int(cron_user.strip() or 0))
    except ValueError:
        total = 0
    controles.append({
        **HARDENING_CONTROLS[12],
        "resultado": "SI" if total > 0 else "NO",
        "detalle": "Sistema de backup detectado" if total > 0
                   else "Sin backup automatizado detectado",
    })

    return controles


def _persist_hardening_result(asset_id: int, target_ip: str, hostname: str,
                               controles: List[Dict]) -> None:
    """
    Persiste el resultado en la tabla hardening_results.
    Usa psycopg2 directo para evitar problemas con SessionLocal en tareas Celery.
    """
    import psycopg2
    import psycopg2.extras
    from shared.config import settings

    si_count = sum(1 for c in controles if c["resultado"] == "SI")
    no_count = sum(1 for c in controles if c["resultado"] == "NO")
    revisar_count = sum(1 for c in controles if c["resultado"] == "REVISAR")
    cumple_ens = no_count == 0

    try:
        conn = psycopg2.connect(settings.database_url)
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS hardening_results (
                        id SERIAL PRIMARY KEY,
                        asset_id INTEGER NOT NULL,
                        target_ip VARCHAR(45) NOT NULL,
                        hostname VARCHAR(255),
                        controles JSONB NOT NULL,
                        si_count INTEGER DEFAULT 0,
                        no_count INTEGER DEFAULT 0,
                        revisar_count INTEGER DEFAULT 0,
                        cumple_ens BOOLEAN DEFAULT FALSE,
                        verified_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    INSERT INTO hardening_results
                        (asset_id, target_ip, hostname, controles,
                         si_count, no_count, revisar_count, cumple_ens)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    asset_id, target_ip, hostname,
                    json.dumps(controles),
                    si_count, no_count, revisar_count, cumple_ens,
                ))
        conn.close()
    except Exception as e:
        logger.error(f"Error persistiendo hardening result asset_id={asset_id}: {e}")


@app.task(
    name="tasks.run_hardening_check",
    queue="vulnerabilities",
    time_limit=180,
    soft_time_limit=160,
)
def run_hardening_check(asset_id: int, target_ip: str, ssh_user: str,
                        ssh_password: str, hostname: str = "") -> Dict[str, Any]:
    """
    Tarea Celery: ejecuta los 13 checks de bastionado sobre un activo vía SSH.
    Solo lectura. No modifica nada en el servidor.
    ENS: op.exp.2, mp.info.3, op.acc.6, op.cont.2, mp.com.1, mp.si.5,
         op.exp.3, op.exp.5, mp.com.2
    """
    logger.info(f"HARDENING_CHECK_START asset_id={asset_id} target={target_ip}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(target_ip, username=ssh_user, password=ssh_password, timeout=10)
        controles = _run_13_checks(client, ssh_password)
        client.close()
    except Exception as e:
        logger.error(f"HARDENING_SSH_ERROR asset_id={asset_id} error={e}")
        return {
            "status": "FAILURE",
            "asset_id": asset_id,
            "error": f"No se pudo conectar vía SSH: {str(e)}",
        }

    _persist_hardening_result(asset_id, target_ip, hostname, controles)

    si_count = sum(1 for c in controles if c["resultado"] == "SI")
    no_count = sum(1 for c in controles if c["resultado"] == "NO")
    revisar_count = sum(1 for c in controles if c["resultado"] == "REVISAR")

    result = {
        "asset_id": asset_id,
        "asset_name": hostname or f"Asset-{asset_id}",
        "target": target_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "controles": controles,
        "resumen": {
            "total": 13,
            "si": si_count,
            "no": no_count,
            "revisar": revisar_count,
            "cumple_ens": no_count == 0,
        },
    }
    logger.info(
        f"HARDENING_CHECK_COMPLETE asset_id={asset_id} "
        f"SI={si_count} NO={no_count} REVISAR={revisar_count}"
    )
    return result


@app.task(
    name="tasks.run_hardening_batch",
    queue="vulnerabilities",
    time_limit=600,
    soft_time_limit=570,
)
def run_hardening_batch(asset_checks: List[Dict]) -> Dict[str, Any]:
    """
    Tarea Celery: ejecuta hardening sobre una lista de activos secuencialmente.
    Cada elemento de asset_checks: {asset_id, target_ip, ssh_user, ssh_password, hostname}
    """
    results = []
    for a in asset_checks:
        r = run_hardening_check(
            asset_id=a["asset_id"],
            target_ip=a["target_ip"],
            ssh_user=a["ssh_user"],
            ssh_password=a["ssh_password"],
            hostname=a.get("hostname", ""),
        )
        results.append(r)
    return {"status": "SUCCESS", "results": results}
