from typing import Dict, List, Optional

from celery import app



@app.task(
    name="scanner.openvas.scan_asset",
    bind=True,
    timeout=3600,
    max_retries=3,
    queue="scanner_tasks",
)
@app.task(
    name="scanner.openvas.scan_asset",
    bind=True,
    timeout=3600,
    max_retries=3,
    queue="scanner_tasks",
)
def run_openvvas_scan(self, asset_id: int, asset_ip: str, asset_name: str) -> Dict:
    """Execute OpenVAS vulnerability scan."""
    from redis import Redis
    import time
    
    redis_client = Redis(host='redis', port=6379, db=0, decode_responses=True)
    
    # Esperar slot disponible
    while int(redis_client.get('active_scans') or 0) >= 5:
        logger.info("⏳ Esperando slot de escaneo...")
        time.sleep(2)
    
    redis_client.incr('active_scans')
    
    try:
        logger.info(f"→ OpenVAS scan: asset_id={asset_id}")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            client = OpenVASClient()
            findings = loop.run_until_complete(
                client.scan_asset(asset_id, asset_ip, asset_name)
            )
            
            result = {
                "scanner": "OpenVAS",
                "status": "success",
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings],
                "error": None,
            }
            
            logger.info(f"✓ OpenVAS: {len(findings)} hallazgos")
            
            from shared.database import SessionLocal
            from services.scanner_engine.models.vulnerability import VulnFinding
            
            db = SessionLocal()
            try:
                for f in findings:
                    vuln = VulnFinding(asset_id=asset_id, scan_id=f"scan_{int(time.time())}", vulnerability_id=f.cve_id or "UNKNOWN", title=f.title, severity=f.severity.value, cvss_v3_score=f.cvss_score, scanner_name="OpenVAS", evidence={"raw": f.evidence}, created_by="scanner")
                    db.add(vuln)
                db.commit()
                logger.info(f"✓ Saved {len(findings)} findings to BD")
            except Exception as e:
                db.rollback()
                logger.error(f"✗ DB save failed: {e}")
            finally:
                db.close()
            
            return result
        finally:
            loop.close()
    
    except Exception as e:
        logger.error(f"✗ OpenVAS error: {str(e)}")
        
        if self.request.retries < self.max_retries:
            logger.info(f"Reintentando OpenVAS (intento {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))
        
        return {
            "scanner": "OpenVAS",
            "status": "error",
            "findings_count": 0,
            "findings": [],
            "error": str(e),
        }
    
    finally:
        redis_client.decr('active_scans')
        logger.info(f"✓ Escaneo liberado. Activos: {redis_client.get('active_scans')}")