import subprocess
import ipaddress
from shared.celery_app import app
from shared.database import SessionLocal
from shared.scan_logger import ScanLogger
from services.asset_manager.services import asset_service

logger = ScanLogger("discovery")

def _ping_sweep(cidr: str) -> list[str]:
    """Ejecuta nmap -sn sobre un rango CIDR y devuelve IPs activas."""
    try:
        result = subprocess.run(
            ["nmap", "--unprivileged", "-sn", "-oG", "-", cidr],
            capture_output=True,
            text=True,
            timeout=300,
        )
        ips = []
        for line in result.stdout.splitlines():
            if line.startswith("Host:"):
                parts = line.split()
                if len(parts) >= 2:
                    ips.append(parts[1])
        logger.info("NMAP_SWEEP_DONE", cidr=cidr, found=len(ips))
        return ips
    except FileNotFoundError:
        logger.error("NMAP_NOT_FOUND")
        raise RuntimeError("nmap no está instalado en el sistema")
    except subprocess.TimeoutExpired:
        logger.error("NMAP_TIMEOUT", cidr=cidr)
        return []

@app.task(name="tasks.run_network_discovery", bind=True, max_retries=2)
def run_network_discovery(self, network_range: str):
    """
    Task Celery que ejecuta discovery y devuelve IPs activas SIN registrar nada.
    El registro es responsabilidad del operador desde la UI. [op.acc.1]
    """
    db = SessionLocal()
    try:
        ipaddress.ip_network(network_range, strict=False)
        found_ips = _ping_sweep(network_range)

        existing_ips = set()
        for ip in found_ips:
            if asset_service.get_asset_by_ip(db, ip):
                existing_ips.add(ip)

        new_ips = [ip for ip in found_ips if ip not in existing_ips]

        logger.info("DISCOVERY_DONE", cidr=network_range, found=len(found_ips), new=len(new_ips))
        return {
            "network_range": network_range,
            "hosts_found": len(found_ips),
            "new_ips": new_ips,
            "existing_ips": list(existing_ips),
            "new_assets": 0,
        }

    except ValueError as e:
        logger.error("INVALID_CIDR", cidr=network_range, error=str(e))
        return {"error": f"CIDR inválido: {str(e)}"}
    except Exception as e:
        logger.error("DISCOVERY_TASK_FAILED", error=str(e))
        raise self.retry(exc=e, countdown=30)
    finally:
        db.close()
