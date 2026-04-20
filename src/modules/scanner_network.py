import subprocess
import json
import os
import sys
import re
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scan_logger import ScanLogger
from utils import parsear_puerto, calcular_resumen_network

logger = ScanLogger("scanner_network")

# Configuración
TARGET = "10.202.15.100"
NMAP_PATH = "nmap"
OUTPUT = "output/tmp_network.json"

def scan():
    logger.scan_start(target=TARGET, ports="22,80,443,19999")
    timestamp = datetime.datetime.now().isoformat()
    # El comando audita lo que configuraste: SSH (22), Apache (80/443), Netdata (19999)
    cmd = [NMAP_PATH, "-sV", "-Pn", "-p", "22,80,443,19999", TARGET]
    process = subprocess.run(cmd, capture_output=True, text=True)
    out = process.stdout

    hallazgos = []
    puertos_abiertos = 0
    puertos_filtrados = 0
    ssl_activo = False
    firewall_detectado = False

    port_services = {
        "22/tcp": {"servicio": "ssh", "medida_ens": "op.acc.1", "nota": "Servicio SSH accesible — verificar que solo acepta autenticación por clave"},
        "80/tcp": {"servicio": "http", "medida_ens": "op.exp.2", "nota": "HTTP sin cifrar activo — verificar redirección a HTTPS"},
        "443/tcp": {"servicio": "https", "medida_ens": "op.exp.2", "nota": "HTTPS activo con SSL"},
        "19999/tcp": {"servicio": "netdata", "medida_ens": "op.exp.4", "nota": "Puerto filtrado por firewall — correcto"}
    }

    lines = out.split('\n')
    for line in lines:
        if '/tcp' in line and ('open' in line or 'filtered' in line):
            hallazgo = parsear_puerto(line.strip())
            if hallazgo:
                hallazgos.append(hallazgo)
                logger.finding(hallazgo["servicio"].upper(), severity=hallazgo["severidad"], status=hallazgo["estado"])

    resumen = calcular_resumen_network(hallazgos)

    res = {
        "timestamp": timestamp,
        "target": TARGET,
        "hallazgos": hallazgos,
        "resumen": resumen
    }

    with open(OUTPUT, "w", encoding='utf-8') as f:
        json.dump(res, f, ensure_ascii=False, indent=4)

    logger.scan_end(target=TARGET, duration="N/A", findings=len(hallazgos))

if __name__ == "__main__":
    scan()