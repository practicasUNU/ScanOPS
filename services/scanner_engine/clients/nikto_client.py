import subprocess
import json
import os
from typing import List, Dict
from shared.scan_logger import ScanLogger

logger = ScanLogger("nikto_client")

def run_nikto_scan(asset_id: int, target_url: str) -> List[Dict]:
    logger.info("NIKTO_START", target=target_url)
    
    output_file = f"/tmp/nikto_{asset_id}.json"
    
    cmd = [
        "nikto",
        "-h", target_url,
        "-Format", "json",
        "-output", output_file,
        "-Tuning", "1234578",
        "-timeout", "30",
        "-maxtime", "90s"
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                try:
                    data = json.load(f)
                    
                    # Nikto JSON is a top-level array: [ { "host":..., "vulnerabilities": [...] } ]
                    vulns = []
                    if isinstance(data, list) and len(data) > 0:
                        vulns = data[0].get("vulnerabilities", [])
                    elif isinstance(data, dict):
                        vulns = data.get("vulnerabilities", [])

                    for v in vulns:
                        msg = v.get("msg", "")
                        severity = "MEDIUM"
                        if "XSS" in msg.upper() or "INJECTION" in msg.upper():
                            severity = "HIGH"
                            
                        findings.append({
                            "title": f"Nikto Finding: {v.get('id', 'Unknown')}",
                            "severity": severity,
                            "description": msg,
                            "cve_id": "",
                            "evidence": f"URL: {v.get('url', '')} | Method: {v.get('method', '')}",
                            "remediation": v.get("references", "") or "Review Nikto recommendation for this finding."
                        })
                except json.JSONDecodeError:
                    logger.error("NIKTO_JSON_ERROR", target=target_url)
            
            os.remove(output_file)
            
        logger.info("NIKTO_FINISH", target=target_url, count=len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.error("NIKTO_TIMEOUT", target=target_url)
        if os.path.exists(output_file):
            os.remove(output_file)
        return []
    except Exception as e:
        logger.error("NIKTO_ERROR", target=target_url, error=str(e))
        if os.path.exists(output_file):
            os.remove(output_file)
        return []
