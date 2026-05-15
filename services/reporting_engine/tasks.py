"""
Celery tasks for M7 Reporting Engine.
ENS: op.exp.5, mp.info.4
"""
import logging
import httpx
from shared.celery_app import app

logger = logging.getLogger(__name__)

REPORTING_URL = "http://localhost:8008"


@app.task(name='services.reporting_engine.tasks.generate_weekly_report', bind=True, max_retries=2)
def generate_weekly_report(self):
    """
    Phase 5 — Sunday 08:00.
    Triggers M7 /report/full-audit endpoint to generate and archive weekly report ZIP.
    ENS: op.exp.5 (audit trail), mp.info.4 (integrity — sealed PDF)
    """
    logger.info("[ENS_EVIDENCE] Phase 5 started — generating weekly audit report")
    try:
        response = httpx.get(f"{REPORTING_URL}/report/full-audit", timeout=120)
        if response.status_code == 200:
            logger.info("[ENS_EVIDENCE] Phase 5 — weekly report generated successfully")
            return {"status": "ok", "phase": 5, "bytes": len(response.content)}
        else:
            raise Exception(f"M7 returned {response.status_code}")
    except Exception as e:
        logger.error(f"Phase 5 error: {e}")
        raise self.retry(exc=e, countdown=600)
