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
    
    # Comando para ejecución silenciosa con salida en JSON [cite: 120]
    cmd = ["nuclei", "-target", target_ip, "-silent", "-jsonl"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        findings = []
        if result.stdout:
            for line in result.stdout.splitlines():
                raw_vuln = json.loads(line)
                # Normalización del hallazgo (US-3.5) 
                findings.append({
                    "title": raw_vuln.get("info", {}).get("name"),
                    "severity": raw_vuln.get("info", {}).get("severity", "").upper(),
                    "description": raw_vuln.get("info", {}).get("description"),
                    "cve_id": ",".join(raw_vuln.get("info", {}).get("classification", {}).get("cve-id", [])),
                    "evidence": raw_vuln.get("matched-at")
                })
        
        logger.info("NUCLEI_FINISH", target=target_ip, count=len(findings))
        return findings
    except Exception as e:
        logger.error("NUCLEI_ERROR", target=target_ip, error=str(e))
        return []