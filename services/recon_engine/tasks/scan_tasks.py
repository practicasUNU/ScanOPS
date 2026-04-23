import asyncio
import re
import logging
from shared.celery_app import app
from ..services.scanner_network import start_scan
from ..services.dns_whois import get_domain_recon

logger = logging.getLogger(__name__)

@app.task(bind=True, name="run_recon_complete")
def run_recon_complete(self, target, asset_id=None):
    """
    Orquestación completa de reconocimiento (M2).
    Flujo: Nmap/Masscan -> Subfinder -> Banner Grabbing -> DNS/WHOIS -> M3 Trigger
    """
    logger.info(f"🚀 Iniciando orquestación M2 para: {target}")
    
    try:
        # 1. Escaneo de red, subdominios y banner grabbing (en scanner_network.py)
        # Esto guarda resultados en BD (ReconSnapshot, ReconFinding, ReconSubdomain)
        resultado = asyncio.run(start_scan(target=target))
        
        # 2. Información DNS/WHOIS (US-2.8)
        domains_to_check = []
        is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d+)?$", target)
        if not is_ip:
            domains_to_check.append(target)
        
        dns_whois_results = {}
        for domain in domains_to_check:
            try:
                info = asyncio.run(get_domain_recon(domain))
                dns_whois_results[domain] = info
            except Exception as e:
                logger.error(f"Error en DNS/WHOIS para {domain}: {e}")
                continue
        
        resultado["dns_whois"] = dns_whois_results

        # 3. Disparar M3 (Escaneo de Vulnerabilidades) para cada host descubierto
        # [ENS Alto: op.acc.1] Interconexión de sistemas de auditoría
        hosts_detectados = resultado.get("hosts_detected", [])
        if hosts_detectados:
            logger.info(f"📡 Disparando M3 para {len(hosts_detectados)} hosts descubiertos")
            for ip in hosts_detectados:
                try:
                    # Llamamos a M3 de forma asíncrona vía Celery
                    # Si no tenemos asset_id (es Shadow IT), pasamos None o creamos uno si fuera necesario
                    app.send_task(
                        "services.scanner_engine.tasks.vuln_tasks.scan_asset_parallel",
                        args=[asset_id or 0, ip, f"Discovered_{ip}"],
                        kwargs={"scan_types": ["nuclei", "openvas", "zap"]}
                    )
                except Exception as e:
                    logger.error(f"Error al disparar M3 para {ip}: {e}")

        logger.info(f"✅ Orquestación M2 completada para {target}")
        return resultado

    except Exception as e:
        logger.error(f"❌ Fallo crítico en orquestación M2: {e}", exc_info=True)
        return {"status": "error", "message": str(e)}