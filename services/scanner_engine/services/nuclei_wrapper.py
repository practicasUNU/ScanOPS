import subprocess
import json
import os
from shared.scan_logger import ScanLogger

logger = ScanLogger("nuclei_wrapper")

def run_nuclei_scan(target_ip: str):
    """
    Ejecuta Nuclei sobre el activo. 
    US-3.2: Uso de plantillas actualizadas para Zero-days.
    """
    logger.info("NUCLEI_START", target=target_ip)
    
    # Lista de templates específicos para optimizar tiempo y enfoque (M3)
    NUCLEI_TEMPLATES = [
        "http/technologies/",       # Detección de tecnologías y WAF
        "http/exposures/",          # Archivos expuestos, configs, backups
        "http/misconfiguration/",   # Misconfigurations web
        "http/vulnerabilities/",    # Vulnerabilidades web conocidas
        "network/detection/",       # Detección de servicios de red
        "ssl/",                     # Problemas SSL/TLS
    ]

    # Comando para ejecución silenciosa con salida en JSON [cite: 120]
    cmd = [
        "nuclei",
        "-target", target_ip,
        "-silent",
        "-jsonl",
        "-timeout", "10",           # timeout por request en segundos
        "-bulk-size", "25",         # requests paralelos
        "-rate-limit", "50",        # requests por segundo
        "-retries", "1",
    ]

    # Añadir templates específicos
    for template in NUCLEI_TEMPLATES:
        cmd.extend(["-t", template])

    try:
        # Timeout del proceso completo reducido a 300s (5 min)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        findings = []
        if result.stdout:
            for line in result.stdout.splitlines():
                raw_vuln = json.loads(line)
                # Normalización del hallazgo (US-3.5) 
                info = raw_vuln.get("info", {})
                classification = info.get("classification", {})
                cve_ids = classification.get("cve-id")
                
                # Asegurar que cve_ids sea una lista iterable
                cve_str = ",".join(cve_ids) if isinstance(cve_ids, list) else ""

                findings.append({
                    "title": info.get("name"),
                    "severity": info.get("severity", "").upper(),
                    "description": info.get("description") or info.get("name"),
                    "cve_id": cve_str,
                    "evidence": raw_vuln.get("matched-at"),
                    "ens_measure": "op.exp.2"  # Mapeo explícito para auditoría ENS
                })
        
        logger.info("NUCLEI_FINISH", target=target_ip, count=len(findings))
        return findings
    except Exception as e:
        logger.error("NUCLEI_ERROR", target=target_ip, error=str(e))
        return []