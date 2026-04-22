from shared.celery_app import app as shared_app
from shared.database import SessionLocal
from services.scanner_engine.models.vulnerability import VulnFinding
import subprocess
import json
import time

@shared_app.task(name='tasks.run_nuclei_scan', queue='vulnerabilities', time_limit=1800)
def run_nuclei_scan(asset_id: int, target: str, templates: str = 'high,critical'):
    """Nuclei scan"""
    db = SessionLocal()
    try:
        cmd = ['nuclei', '-u', target, '-json', '-timeout', '10']
        result = subprocess.run(cmd, capture_output=True, timeout=1800, text=True)
        
        if result.returncode == 0:
            return {'status': 'success', 'asset_id': asset_id, 'scanner': 'nuclei'}
        return {'status': 'error', 'message': result.stderr}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
    finally:
        db.close()
