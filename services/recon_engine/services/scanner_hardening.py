import paramiko
import json
import os
import sys
import datetime
import time

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

        # IP Forwarding
        _, stdout, _ = client.exec_command("sysctl net.ipv4.ip_forward | awk '{print $3}'")
        ip_forward = stdout.read().decode().strip()
        hallazgos.append({
            "check": "ip_forwarding",
            "estado": "DESACTIVO" if ip_forward == "0" else "ACTIVO",
            "severidad": "INFO" if ip_forward == "0" else "MEDIA",
            "medida_ens": "op.exp.2",
            "detalle": f"IP forwarding habilitado: {ip_forward}",
            "remediacion": "sysctl -w net.ipv4.ip_forward=0" if ip_forward != "0" else None
        })

        # SYN Cookies
        _, stdout, _ = client.exec_command("sysctl net.ipv4.tcp_syncookies | awk '{print $3}'")
        syncookies = stdout.read().decode().strip()
        hallazgos.append({
            "check": "syn_cookies",
            "estado": "ACTIVO" if syncookies == "1" else "INACTIVO",
            "severidad": "INFO" if syncookies == "1" else "MEDIA",
            "medida_ens": "op.exp.2",
            "detalle": f"SYN cookies: {syncookies}",
            "remediacion": "sysctl -w net.ipv4.tcp_syncookies=1" if syncookies != "1" else None
        })

        # SELinux
        _, stdout, _ = client.exec_command("getenforce")
        selinux = stdout.read().decode().strip()
        hallazgos.append({
            "check": "selinux",
            "estado": selinux,
            "severidad": "INFO" if selinux == "Enforcing" else "ALTA",
            "medida_ens": "op.exp.2",
            "detalle": f"SELinux status: {selinux}",
            "remediacion": None if selinux == "Enforcing" else "semanage permissive -d domain_t"
        })

        # AppArmor
        _, stdout, _ = client.exec_command("aa-status 2>&1 | grep 'apparmor module is loaded' | wc -l")
        apparmor = stdout.read().decode().strip()
        hallazgos.append({
            "check": "apparmor",
            "estado": "ACTIVO" if apparmor == "1" else "INACTIVO",
            "severidad": "INFO" if apparmor == "1" else "MEDIA",
            "medida_ens": "op.exp.2",
            "detalle": f"AppArmor: {apparmor}",
            "remediacion": "systemctl enable apparmor" if apparmor != "1" else None
        })

        # Core Dumps
        _, stdout, _ = client.exec_command("sysctl kernel.core_pattern | awk '{print $3}'")
        core_pattern = stdout.read().decode().strip()
        hallazgos.append({
            "check": "core_dumps",
            "estado": "PROTEGIDO" if "/dev/null" in core_pattern else "EXPUESTO",
            "severidad": "INFO" if "/dev/null" in core_pattern else "BAJA",
            "medida_ens": "op.exp.2",
            "detalle": f"Kernel core pattern: {core_pattern}",
            "remediacion": "sysctl -w kernel.core_pattern=/dev/null" if "/dev/null" not in core_pattern else None
        })

        # Umask
        _, stdout, _ = client.exec_command("grep -E '^umask' /etc/login.defs | awk '{print $2}'")
        umask = stdout.read().decode().strip()
        hallazgos.append({
            "check": "umask",
            "estado": "RESTRICTIVO" if umask == "077" else "PERMISIVO",
            "severidad": "INFO" if umask == "077" else "MEDIA",
            "medida_ens": "op.exp.2",
            "detalle": f"Default umask: {umask}",
            "remediacion": "echo 'umask 077' >> /etc/login.defs" if umask != "077" else None
        })

        # SSH Public Key Authentication
        _, stdout, _ = client.exec_command("grep -i 'PubkeyAuthentication yes' /etc/ssh/sshd_config | wc -l")
        pubkey = stdout.read().decode().strip()
        hallazgos.append({
            "check": "ssh_pubkey_auth",
            "estado": "HABILITADO" if pubkey == "1" else "DESHABILITADO",
            "severidad": "INFO" if pubkey == "1" else "ALTA",
            "medida_ens": "op.acc.5",
            "detalle": f"SSH PubkeyAuthentication: {pubkey}",
            "remediacion": "echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config" if pubkey != "1" else None
        })

        # RP Filter (IP Spoofing Protection)
        _, stdout, _ = client.exec_command("sysctl net.ipv4.conf.all.rp_filter | awk '{print $3}'")
        rpfilter = stdout.read().decode().strip()
        hallazgos.append({
            "check": "ip_spoofing_protection",
            "estado": "ACTIVO" if rpfilter == "1" else "INACTIVO",
            "severidad": "INFO" if rpfilter == "1" else "ALTA",
            "medida_ens": "op.exp.2",
            "detalle": f"Reverse path filtering: {rpfilter}",
            "remediacion": "sysctl -w net.ipv4.conf.all.rp_filter=1" if rpfilter != "1" else None
        })

        # SSH Empty Passwords
        _, stdout, _ = client.exec_command("grep -i 'PermitEmptyPasswords no' /etc/ssh/sshd_config | wc -l")
        emptypwd = stdout.read().decode().strip()
        hallazgos.append({
            "check": "ssh_empty_passwords",
            "estado": "BLOQUEADO" if emptypwd == "1" else "PERMITIDO",
            "severidad": "INFO" if emptypwd == "1" else "CRÍTICA",
            "medida_ens": "op.acc.5",
            "detalle": f"SSH empty passwords permitidas: {emptypwd}",
            "remediacion": "echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config" if emptypwd != "1" else None
        })

        # Sudo Logging
        _, stdout, _ = client.exec_command("grep -i 'Defaults logfile' /etc/sudoers | wc -l")
        sudolog = stdout.read().decode().strip()
        hallazgos.append({
            "check": "sudo_logging",
            "estado": "HABILITADO" if sudolog == "1" else "DESHABILITADO",
            "severidad": "INFO" if sudolog == "1" else "MEDIA",
            "medida_ens": "op.exp.5",
            "detalle": f"Sudo logging configurado: {sudolog}",
            "remediacion": "echo 'Defaults logfile=/var/log/sudo.log' >> /etc/sudoers" if sudolog != "1" else None
        })

        # File Integrity (AIDE)
        _, stdout, _ = client.exec_command("which aide | wc -l")
        aide = stdout.read().decode().strip()
        hallazgos.append({
            "check": "aide_installed",
            "estado": "PRESENTE" if aide == "1" else "AUSENTE",
            "severidad": "INFO" if aide == "1" else "MEDIA",
            "medida_ens": "op.exp.2",
            "detalle": f"AIDE (File Integrity Monitor): {aide}",
            "remediacion": "apt-get install aide aide-common" if aide != "1" else None
        })

        # Fail2Ban
        _, stdout, _ = client.exec_command("systemctl is-active fail2ban 2>/dev/null")
        fail2ban = stdout.read().decode().strip()
        hallazgos.append({
            "check": "fail2ban",
            "estado": "ACTIVO" if "active" in fail2ban else "INACTIVO",
            "severidad": "INFO" if "active" in fail2ban else "MEDIA",
            "medida_ens": "op.exp.3",
            "detalle": f"Fail2Ban status: {fail2ban}",
            "remediacion": "systemctl start fail2ban && systemctl enable fail2ban" if "active" not in fail2ban else None
        })

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