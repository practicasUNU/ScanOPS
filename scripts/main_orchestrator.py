import json
import subprocess
import datetime
import os
import sys

# 1. Configuración de Rutas Lógicas
# Obtenemos la raíz del proyecto para que Python encuentre la carpeta 'shared' y 'services'
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

# Importaciones desde el núcleo compartido (shared)
from shared.utils import merge_reports as merge_reports_data
from shared.scan_logger import ScanLogger

# Inicialización del Logger de Auditoría para trazabilidad ENS [op.exp.5]
logger = ScanLogger("main_orchestrator")

MICROSERVICES = {
    "m1": {"url": "http://localhost:8001", "name": "Asset Manager", "port": 8001},
    "m2": {"url": "http://localhost:8003", "name": "Recon Engine", "port": 8003},
    "m8": {"url": "http://localhost:8000", "name": "AI Reasoning", "port": 8000},
}

def run_scanners():
    """Ejecuta de forma secuencial los agentes del Recon Engine (M2)."""
    now = datetime.datetime.now()
    cycle_id = f"{now.year}-W{now.isocalendar()[1]:02d}"

    logger.info("CYCLE_START", cycle=cycle_id)
    print(f"\n--- [CEREBRO] INICIANDO CICLO DE VIGILANCIA {cycle_id} ---")

    # Rutas actualizadas a la nueva estructura de microservicios
    scripts = [
        os.path.join(base_dir, "services", "recon_engine", "services", "scanner_network.py"),
        os.path.join(base_dir, "services", "recon_engine", "services", "scanner_health.py"),
        os.path.join(base_dir, "services", "recon_engine", "services", "scanner_hardening.py")
    ]

    network_data = None
    for script in scripts:
        if not os.path.exists(script):
            logger.error("MODULE_NOT_FOUND", path=script)
            print(f"[!] Error: No se encuentra el script en {script}")
            continue

        logger.info("MODULE_EXEC", script=os.path.basename(script))
        print(f"[*] Ejecutando módulo: {os.path.basename(script)}...")

        if "scanner_network.py" in script:
            # El scanner de red devuelve el JSON por salida estándar (stdout)
            result = subprocess.run([sys.executable, script, cycle_id], capture_output=True, text=True)
            if result.returncode == 0:
                try:
                    network_data = json.loads(result.stdout)
                    logger.info("MODULE_OK", script="scanner_network")
                except json.JSONDecodeError:
                    logger.error("JSON_PARSE_ERROR", script="scanner_network")
            else:
                logger.error("MODULE_FAILED", script="scanner_network", code=result.returncode)
        else:
            # Los módulos de salud y hardening guardan archivos temporales en output/
            result = subprocess.run([sys.executable, script])
            if result.returncode == 0:
                logger.info("MODULE_OK", script=os.path.basename(script))
            else:
                logger.error("MODULE_FAILED", script=os.path.basename(script), code=result.returncode)

    return network_data

def merge_reports(network_data=None):
    """Fusiona los resultados de todos los módulos en el Informe Maestro[cite: 138]."""
    final_report = {
        "project": "UNUWARE Server Audit Master",
        "timestamp": datetime.datetime.now().isoformat(),
        "server_ip": "10.202.15.100",
        "data": {}
    }

    # Ubicaciones de los archivos generados por los scanners
    files = {
        "health": os.path.join(base_dir, "output", "tmp_health.json"),
        "hardening": os.path.join(base_dir, "output", "tmp_hardening.json")
    }
    
    # Integrar datos de Red
    if network_data:
        final_report["data"]["network"] = network_data
        print(f"[√] Integración de Network: OK")
    else:
        final_report["data"]["network"] = {"error": "Sin datos de red"}

    # Integrar Salud y Hardening
    for key, path in files.items():
        if os.path.exists(path):
            with open(path, "r", encoding='utf-8') as f:
                final_report["data"][key] = json.load(f)
                print(f"[√] Integración de {key}: OK")
        else:
            final_report["data"][key] = {"error": "Archivo temporal no encontrado"}

    # Fusión lógica y cálculo de cumplimiento (ENS Alto)
    merged = merge_reports_data(final_report["data"])
    final_report["alertas_criticas"] = merged["alertas_criticas"]
    final_report["compliance_global"] = merged["compliance_global"]

    # Generación del Informe Unificado [cite: 15]
    output_path = os.path.join(base_dir, "output", "master_audit_report.json")
    with open(output_path, "w", encoding='utf-8') as f:
        json.dump(final_report, f, ensure_ascii=False, indent=4)
    
    logger.info("CYCLE_END", report="master_audit_report.json")
    print(f"\n[+] VIGILANCIA COMPLETADA. Informe generado en: {output_path}")

if __name__ == "__main__":
    # Asegurar que existe la carpeta de salida
    output_dir = os.path.join(base_dir, "output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    network_results = run_scanners()
    merge_reports(network_results)