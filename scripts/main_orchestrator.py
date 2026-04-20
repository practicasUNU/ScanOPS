import json
import subprocess
import datetime
import os
import sys

# 1. Configurar rutas para encontrar 'src' y los módulos
# Subimos un nivel desde 'scripts' para llegar a la raíz
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(base_dir, 'src'))

from utils import merge_reports as merge_reports_data

from scan_logger import ScanLogger

logger = ScanLogger("main_orchestrator")

def run_scanners():
    logger.info("CYCLE_START", cycle="semanal")
    print("--- INICIANDO SISTEMA DE AUDITORÍA UNUWARE ---")
    scripts = [
        os.path.join(base_dir, "src", "modules", "scanner_network.py"),
        os.path.join(base_dir, "src", "modules", "scanner_health.py"),
        os.path.join(base_dir, "src", "modules", "scanner_hardening.py")
    ]

    network_data = None
    for script in scripts:
        logger.info("MODULE_EXEC", script=script)
        print(f"[*] Ejecutando módulo: {os.path.basename(script)}...")
        if os.path.basename(script) == "scanner_network.py":
            result = subprocess.run([sys.executable, script], capture_output=True, text=True)
            if result.returncode != 0:
                logger.error("MODULE_FAILED", script=script, returncode=result.returncode)
            else:
                logger.info("MODULE_OK", script=script)
                try:
                    network_data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    logger.error("MODULE_FAILED", script=script, error="JSON parse error")
        else:
            result = subprocess.run([sys.executable, script])
            if result.returncode != 0:
                logger.error("MODULE_FAILED", script=script, returncode=result.returncode)
            else:
                logger.info("MODULE_OK", script=script)

    return network_data

def merge_reports(network_data=None):
    final_report = {
        "project": "UNUWARE Server Audit Master",
        "timestamp": datetime.datetime.now().isoformat(),
        "server_ip": "10.202.15.100",
        "data": {}
    }

    files = {
        "health": "output/tmp_health.json",
        "hardening": "output/tmp_hardening.json"
    }
    
    if network_data is not None:
        final_report["data"]["network"] = network_data
        logger.info("REPORT_MERGED", source="network")
        print(f"[√] Leyendo network: OK")
    else:
        final_report["data"]["network"] = {"error": "Módulo no generó resultados"}
        logger.warning("REPORT_MISSING", source="network")
        print("[!] No se obtuvo resultado directo de scanner_network.py")

    for key, path in files.items():
        if os.path.exists(path):
            with open(path, "r", encoding='utf-8') as f:
                contenido = json.load(f)
                final_report["data"][key] = contenido
                logger.info("REPORT_MERGED", source=key)
                print(f"[√] Leyendo {key}: OK")
        else:
            final_report["data"][key] = {"error": "Módulo no generó resultados"}
            logger.warning("FILE_MISSING", path=path)
            print(f"[!] Archivo no encontrado: {path}")

    # Fusionar reportes usando la función de utils
    merged = merge_reports_data(final_report["data"])
    final_report["alertas_criticas"] = merged["alertas_criticas"]
    final_report["compliance_global"] = merged["compliance_global"]

    # Guardar con indentación para que sea legible
    with open("output/master_audit_report.json", "w", encoding='utf-8') as f:
        json.dump(final_report, f, ensure_ascii=False, indent=4)
    
    logger.info("CYCLE_END", report="master_audit_report.json")
    print("\n[+] REPORTE FINAL ACTUALIZADO. Abre output/master_audit_report.json")

if __name__ == "__main__":
    # Creamos la carpeta output si no existe
    if not os.path.exists("output"):
        os.makedirs("output")
    network_data = run_scanners()
    merge_reports(network_data)