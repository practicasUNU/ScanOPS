import paramiko
import json
import os
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scan_logger import ScanLogger
from utils import evaluar_metrica, evaluar_servicio, calcular_estado_global

logger = ScanLogger("scanner_health")

HOST = "10.202.15.100"
USER = "admin"
PASS = "test123" # TODO: migrar a HashiCorp Vault
OUTPUT = "output/tmp_health.json"

def check():
    logger.scan_start(target=HOST, check_type="health")
    timestamp = datetime.datetime.now().isoformat()
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(HOST, username=USER, password=PASS)
        logger.auth_event("SSH_CONNECT", target=HOST, success=True)

        metricas = []
        servicios = []

        # Disco
        _, stdout, _ = client.exec_command("df -h / | awk 'NR==2 {print $5}'")
        disk_str = stdout.read().decode().strip()
        metricas.append(evaluar_metrica("uso_disco", disk_str, 80, 90))

        # RAM
        _, stdout, _ = client.exec_command("free | grep Mem | awk '{printf \"%.0f\", $3/$2 * 100}'")
        ram_str = stdout.read().decode().strip() + "%"
        metricas.append(evaluar_metrica("uso_ram", ram_str, 80, 90))

        # CPU
        _, stdout, _ = client.exec_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
        cpu_str = stdout.read().decode().strip() + "%"
        metricas.append(evaluar_metrica("uso_cpu", cpu_str, 80, 95))

        # Uptime
        _, stdout, _ = client.exec_command("uptime -p")
        uptime_str = stdout.read().decode().strip()
        metricas.append({
            "nombre": "uptime",
            "valor": uptime_str,
            "estado": "OK",
            "severidad": "INFO"
        })

        # Servicios
        for svc in ["apache2", "ssh"]:
            _, stdout, _ = client.exec_command(f"systemctl is-active {svc}")
            svc_estado = stdout.read().decode().strip()
            servicios.append(evaluar_servicio(svc, svc_estado))

        # Estado global
        estado_global = calcular_estado_global(metricas, servicios)

        res = {
            "timestamp": timestamp,
            "target": HOST,
            "metricas": metricas,
            "servicios": servicios,
            "estado_global": estado_global
        }

        with open(OUTPUT, "w", encoding='utf-8') as f:
            json.dump(res, f, ensure_ascii=False, indent=4)

        logger.scan_end(target=HOST, duration="OK", findings=len(metricas) + len(servicios))
        client.close()
    except Exception as e:
        logger.auth_event("SSH_CONNECT", target=HOST, success=False)
        logger.module_error(str(e), target=HOST)
        print(f"Error SSH Health: {e}")

if __name__ == "__main__":
    check()