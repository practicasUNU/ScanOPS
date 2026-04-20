import asyncio
import json
import os
import re
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scan_logger import ScanLogger
from utils import parsear_puerto, calcular_resumen_network

logger = ScanLogger("scanner_network")

TARGET = "10.202.15.0/24"  # Esto escaneará desde la .1 hasta la .254
PORTS = "22,80,443,19999"
MASSCAN_RATE = "1000"

MOCK_INVENTORY = {
    "10.202.15.100": {
        "activo": "Servidor de auditoría",
        "criticidad": "Alta",
        "responsable": "Equipo SOC"
    },
    "10.202.15.101": {
        "activo": "Switch de borde",
        "criticidad": "Media",
        "responsable": "Infraestructura"
    },
    "scanops.example.com": {
        "activo": "Portal ScanOPS",
        "criticidad": "Alta",
        "responsable": "Equipo SOC"
    }
}

async def _run_tool(cmd):
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return stdout.decode(errors="ignore"), stderr.decode(errors="ignore"), process.returncode
    except FileNotFoundError as exc:
        return "", str(exc), 1


def is_ip(value):
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value))


def inventory_lookup(key):
    if key in MOCK_INVENTORY:
        return MOCK_INVENTORY[key]
    lower_key = key.lower()
    for asset, data in MOCK_INVENTORY.items():
        if asset.lower() == lower_key:
            return data
    return None


def parse_masscan_output(output):
    hosts = {}
    for line in output.splitlines():
        match = re.search(r"Discovered open port (?P<port>\d+/tcp) on (?P<host>[^\s]+)", line)
        if match:
            host = match.group("host")
            port = match.group("port")
            hosts.setdefault(host, set()).add(port)
            continue

        match = re.search(r"(?P<host>\d+\.\d+\.\d+\.\d+).*?(?P<port>\d+/tcp)", line)
        if match:
            host = match.group("host")
            port = match.group("port")
            hosts.setdefault(host, set()).add(port)
    return hosts


def parse_subfinder_output(output):
    return [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("#")]


def extract_hosts_from_nmap(output):
    hosts = set()
    for line in output.splitlines():
        match = re.search(r"Nmap scan report for (?P<host>.+)", line)
        if match:
            hosts.add(match.group("host").strip())
    return hosts


def build_hallazgos(nmap_output, discovered_hosts):
    hallazgos = []
    for line in nmap_output.splitlines():
        if "/tcp" in line and ("open" in line or "filtered" in line):
            hallazgo = parsear_puerto(line.strip())
            if hallazgo:
                hallazgo["detalle"] = (
                    f"Servicio {hallazgo['servicio']} detectado en {hallazgo['puerto']} "
                    f"con estado {hallazgo['estado']}"
                )
                hallazgos.append(hallazgo)
                logger.finding(hallazgo["servicio"].upper(), severity=hallazgo["severidad"], status=hallazgo["estado"])

    for host in sorted(discovered_hosts):
        if inventory_lookup(host) is None:
            hallazgos.append({
                "check": "hardware_no_autorizado",
                "host": host,
                "estado": "NO AUTORIZADO",
                "severidad": "ALTA",
                "medida_ens": "op.acc.7",
                "detalle": "Hardware detectado que no figura en inventario oficial.",
                "nota": "Shadow IT detectado"
            })
            logger.finding("HARDWARE_NO_AUTORIZADO", severity="ALTA", status="NO AUTORIZADO", host=host)

    return hallazgos


async def run_masscan():
    cmd = ["masscan", "-p", PORTS, TARGET, "--rate", MASSCAN_RATE]
    stdout, stderr, returncode = await _run_tool(cmd)
    if returncode != 0:
        logger.warning("MASSCAN_FAILED", target=TARGET, error=stderr.strip())
    return stdout


async def run_subfinder():
    domains = [asset for asset in MOCK_INVENTORY if not is_ip(asset)]
    if not domains:
        return ""
    cmd = ["subfinder", "-silent"] + sum([["-d", domain] for domain in domains], [])
    stdout, stderr, returncode = await _run_tool(cmd)
    if returncode != 0:
        logger.warning("SUBFINDER_FAILED", target=TARGET, error=stderr.strip())
    return stdout


async def run_nmap(open_ports):
    if not open_ports:
        logger.info("NMAP_SKIPPED", target=TARGET, reason="No puertos abiertos detectados por Masscan")
        return ""

    cmd = ["nmap", "-sV", "-p", ",".join(sorted(open_ports)), TARGET]
    stdout, stderr, returncode = await _run_tool(cmd)
    if returncode != 0:
        logger.warning("NMAP_FAILED", target=TARGET, error=stderr.strip())
    return stdout


async def _scan_async():
    logger.scan_start(target=TARGET, ports=PORTS)
    timestamp = datetime.datetime.now().isoformat()

    masscan_task = asyncio.create_task(run_masscan())
    subfinder_task = asyncio.create_task(run_subfinder())
    masscan_output, subfinder_output = await asyncio.gather(masscan_task, subfinder_task)

    masscan_hosts = parse_masscan_output(masscan_output)
    subfinder_domains = parse_subfinder_output(subfinder_output)
    open_ports = {port for ports in masscan_hosts.values() for port in ports}

    nmap_output = await run_nmap(open_ports)

    # Simulación de IPs vivas detectadas por Masscan/Nmap
    discovered_ips = [
        "10.202.15.1",    # El Router (Oficial)
        "10.202.15.100",  # Tu Servidor (Oficial)
        "10.202.15.150",  # Un Portátil (No autorizado - Shadow IT)
        "10.202.15.200"   # Una Impresora (No autorizada - Shadow IT)
    ]

    discovered_hosts = set(masscan_hosts.keys()) | extract_hosts_from_nmap(nmap_output) | set(discovered_ips)
    inventory_matches = [
        {"host": host, **inventory_lookup(host)}
        for host in sorted(discovered_hosts)
        if inventory_lookup(host) is not None
    ]

    hallazgos = build_hallazgos(nmap_output, discovered_hosts)
    resumen = calcular_resumen_network(hallazgos)

    result = {
        "timestamp": timestamp,
        "target": TARGET,
        "inventory": MOCK_INVENTORY,
        "inventory_matches": inventory_matches,
        "hosts_detected": sorted(discovered_hosts),
        "subfinder_domains": subfinder_domains,
        "hallazgos": hallazgos,
        "resumen": resumen
    }

    logger.scan_end(target=TARGET, duration="OK", findings=len(hallazgos))
    return result


async def scan():
    return await _scan_async()


if __name__ == "__main__":
    result = asyncio.run(scan())
    print(json.dumps(result, ensure_ascii=False, indent=2))