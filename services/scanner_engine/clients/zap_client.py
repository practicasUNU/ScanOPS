from services.scanner_engine.clients.zapv2_mock import ZAPv2
from shared.celery_app import app as shared_app
from shared.database import SessionLocal
from services.scanner_engine.models.vulnerability import VulnFinding
import json
import time

class ZAPScanner:
    def __init__(self, proxy='http://localhost:8091'):
        self.zap = ZAPv2(proxies={'http': proxy, 'https': proxy})
    
    @shared_app.task(name='tasks.run_zap_scan', queue='heavy_scans', time_limit=1800)
    def scan_web_application(self, asset_id: int, url: str) -> dict:
        db = SessionLocal()
        try:
            self.zap.spider.scan(url=url)
            while int(self.zap.spider.status()) < 100:
                time.sleep(2)
            
            self.zap.ascan.scan(url=url)
            while int(self.zap.ascan.status()) < 100:
                time.sleep(2)
            
            alerts = self.zap.alert.alerts(baseurl=url)
            saved_count = 0
            
            for alert in alerts:
                vuln = VulnFinding(
                    asset_id=asset_id,
                    scan_id=f"zap_{asset_id}_{int(time.time())}",
                    vulnerability_id=f"OWASP-{alert.get('alertRef', 'UNKNOWN')}",
                    title=alert.get('name', 'Unknown'),
                    severity=alert.get('risk', '').lower(),
                    scanner_name='zap',
                    scanner_reference=alert.get('alertRef'),
                    affected_port=int(alert.get('sourceId', '').split(':')[-1]) if ':' in alert.get('sourceId', '') else None,
                    evidence={'url': alert.get('url'), 'solution': alert.get('solution')}
                )
                db.add(vuln)
                saved_count += 1
            
            db.commit()
            return {'status': 'success', 'findings_count': saved_count, 'scanner': 'zap'}
        except Exception as e:
            db.rollback()
            return {'status': 'error', 'message': str(e)}
        finally:
            db.close()