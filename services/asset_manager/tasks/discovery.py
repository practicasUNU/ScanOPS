"""
Discovery Task — US-1.4
=======================
Detecta activos nuevos en rangos CIDR usando NMAP.
ENS Alto: [op.acc.1] — Control de dispositivos no autorizados.
"""
import subprocess
import ipaddress
from shared.celery_app import app
from shared.database import SessionLocal
from shared.scan_logger import ScanLogger
from services.asset_manager.services import asset_service
from services.asset_manager.schemas import AssetCreate

logger = ScanLogger("discovery")


def _ping_sweep(cidr: str) -> list[str]:
    """Ejecuta nmap -sn sobre un rango CIDR y devuelve IPs activas."""
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-oG", "-", cidr],
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
    """Task Celery que ejecuta discovery real [op.acc.1]."""
    db = SessionLocal()
    try:
        # Validar CIDR
        ipaddress.ip_network(network_range, strict=False)

        # Escanear
        found_ips = _ping_sweep(network_range)

        # Crear solo los que no existen
        new_count = 0
        new_ids = []
        for ip in found_ips:
            if not asset_service.get_asset_by_ip(db, ip):
                asset = asset_service.create_asset(
                    db=db,
                    data=AssetCreate(
                        ip=ip,
                        hostname=f"discovered-{ip.replace('.', '-')}",
                        responsable="Pendiente asignar",
                        criticidad="PENDIENTE_CLASIFICAR",
                        tipo="OTRO",
                    ),
                    user_id="system-discovery",
                )
                new_ids.append(asset.id)
                new_count += 1
                logger.info("ASSET_DISCOVERED", ip=ip, asset_id=asset.id)

        return {
            "network_range": network_range,
            "hosts_found": len(found_ips),
            "new_assets": new_count,
            "new_asset_ids": new_ids,
        }

    except ValueError as e:
        return {"error": f"CIDR inválido: {str(e)}"}
    except Exception as e:
        raise self.retry(exc=e, countdown=30)
    finally:
        db.close()