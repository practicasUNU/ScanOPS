import paramiko
import json
import os
import sys
import datetime

from shared.scan_logger import ScanLogger
from shared.utils import evaluar_root_bloqueado, evaluar_ufw, evaluar_ssh_root_login, evaluar_parches, evaluar_cifrado_disco, calcular_compliance

logger = ScanLogger("scanner_hardening")

HOST = "10.202.15.100"
USER = "admin"
PASS = "test123" # TODO: migrar a HashiCorp Vault
OUTPUT = "output/tmp_hardening.json"

def audit():
    logger.scan_start(target=HOST, check_type="hardening")
    timestamp = datetime.datetime.now().isoformat()
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(HOST, username=USER, password=PASS)

        hallazgos = []

        # Root bloqueado
        _, stdout, _ = client.exec_command("sudo passwd -S root | awk '{print $2}'")
        root_status = stdout.read().decode().strip()
        hallazgos.append(evaluar_root_bloqueado(root_status))

        # Banner legal
        _, stdout, _ = client.exec_command("ls /etc/update-motd.d/99-custom-welcome")
        banner_present = bool(stdout.read().decode().strip())
        estado = "PRESENTE" if banner_present else "AUSENTE"
        severidad = "INFO" if banner_present else "MEDIA"
        hallazgos.append({
            "check": "banner_legal",
            "estado": estado,
            "severidad": severidad,
            "medida_ens": "op.exp.5",
            "detalle": "Banner legal UNUWARE configurado correctamente" if banner_present else "Banner legal ausente",
            "remediacion": None
        })

        # UFW activo
        _, stdout, _ = client.exec_command("sudo ufw status | head -1")
        ufw_output = stdout.read().decode().strip()
        hallazgos.append(evaluar_ufw(ufw_output))

        # SSH root login
        _, stdout, _ = client.exec_command("grep '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}'")
        permit_root = stdout.read().decode().strip()
        hallazgos.append(evaluar_ssh_root_login(permit_root))

        # Parches pendientes
        _, stdout, _ = client.exec_command(r"apt list --upgradable 2>/dev/null | grep -c '^[^/]*/'")
        count = int(stdout.read().decode().strip())
        hallazgos.append(evaluar_parches(count))

        # Cifrado disco
        _, stdout, _ = client.exec_command("lsblk -o FSTYPE | grep -q crypt && echo 'crypt' || echo ''")
        lsblk_output = stdout.read().decode().strip()
        hallazgos.append(evaluar_cifrado_disco(lsblk_output))

        # Compliance resumen
        compliance_resumen = calcular_compliance(hallazgos)

        res = {
            "timestamp": timestamp,
            "target": HOST,
            "hallazgos": hallazgos,
            "compliance_resumen": compliance_resumen
        }

        with open(OUTPUT, "w", encoding='utf-8') as f:
            json.dump(res, f, ensure_ascii=False, indent=4)

        logger.scan_end(target=HOST, duration="OK", findings=compliance_resumen["checks_total"])
        client.close()
    except Exception as e:
        logger.module_error(str(e), target=HOST)
        print(f"Error SSH Hardening: {e}")

if __name__ == "__main__":
    audit()