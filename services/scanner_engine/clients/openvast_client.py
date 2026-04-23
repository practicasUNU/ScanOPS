from services.scanner_engine.clients.openvasapi_mock import OpenvasConnection
from shared.celery_app import app as shared_app
from shared.database import SessionLocal
from services.scanner_engine.models.vulnerability import VulnFinding
from services.asset_manager.models.asset import Asset
import json
import time

class OpenVastScanner:
    def __init__(self, host='localhost', username='admin', password='admin'):
        self.conn = OpenvasConnection(host, username, password)
    
    @shared_app.task(name='tasks.run_openvast_scan', queue='heavy_scans', time_limit=7200)
    def scan_for_cves(self, asset_id: int) -> dict:
        db = SessionLocal()
        try:
            asset = db.query(Asset).get(asset_id)
            if not asset:
                return {'status': 'error', 'message': f'Asset {asset_id} no encontrado'}
            
            target_id = self.conn.create_target(
                name=f"asset_{asset_id}_{asset.ip}",
                hosts=[asset.ip]
            )
            task_id = self.conn.start_scan(target_id, "Full and fast")
            
            while int(self.conn.task_status(task_id)) < 100:
                time.sleep(5)
            
            results = self.conn.get_results(task_id)
            saved_count = 0
            
            for finding in results:
                vuln = VulnFinding(
                    asset_id=asset_id,
                    scan_id=f"openvast_{asset_id}_{int(time.time())}",
                    vulnerability_id=finding.get('nvt_oid', 'UNKNOWN'),
                    title=finding.get('nvt_name', 'Unknown'),
                    severity=finding.get('severity', '').lower(),
                    cvss_v3_score=float(finding.get('cvss', 0)),
                    scanner_name='openvast',
                    scanner_reference=finding.get('nvt_oid'),
                    affected_port=int(finding.get('port', 0)) if finding.get('port') else None,
                    evidence={'raw': json.dumps(finding)[:500]}
                )
                db.add(vuln)
                saved_count += 1
            
            db.commit()
            return {'status': 'success', 'findings_count': saved_count, 'scanner': 'openvast'}
        except Exception as e:
            db.rollback()
            return {'status': 'error', 'message': str(e)}
        finally:
            db.close()