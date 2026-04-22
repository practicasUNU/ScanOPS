# services/scanner_engine/tasks/vuln_tasks.py
from shared.celery_app import app
from shared.database import SessionLocal
from ..services.nuclei_wrapper import run_nuclei_scan
from ..models.vulnerability import VulnerabilityFinding

@app.task(name="tasks.run_nuclei_vulnerability_scan")
def run_nuclei_task(asset_id, ip):
    db = SessionLocal()
    try:
        vulns = run_nuclei_scan(ip)
        
        for v in vulns:
            finding = VulnerabilityFinding(
                asset_id=asset_id,
                title=v["title"],
                severity=v["severity"],
                description=v["description"],
                cve_id=v["cve_id"],
                tool_source="nuclei",
                evidence=v["evidence"]
            )
            db.add(finding)
        db.commit()
    finally:
        db.close()