"""
US-6.9 — Notificación CCN-CERT vía LUCÍA
ENS: op.exp.7 | Pts: 5
"""
import json
import uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException
from shared.scan_logger import ScanLogger
from .db import get_conn

logger = ScanLogger("siem_engine.lucia")
router = APIRouter(tags=["US-6.9 CCN-CERT LUCÍA"])


def _persist_lucia_notification(notification_id: str, payload: dict, sent: bool, method: str) -> None:
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO siem_lucia_notifications
                    (notification_id, payload, sent, method, notified_at)
                    VALUES (%s, %s, %s, %s, NOW())
                    ON CONFLICT (notification_id) DO NOTHING
                """, (notification_id, json.dumps(payload), sent, method))
    finally:
        conn.close()


@router.post("/siem/lucia/report/{correlation_id}")
async def report_to_lucia(correlation_id: str):
    """
    Exporta una correlación de IA al formato oficial de CCN-CERT LUCÍA.
    ENS: op.exp.7 - Gestión de incidentes (Notificación obligatoria).
    """
    conn = get_conn()
    try:
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM siem_correlations WHERE correlation_id = %s", (correlation_id,))
            corr = cur.fetchone()

            if not corr:
                raise HTTPException(status_code=404, detail="Correlación no encontrada")

            affected_ips = corr['affected_ips']
            if isinstance(affected_ips, str):
                affected_ips = json.loads(affected_ips)

            ens_measures = corr['ens_measures']
            if isinstance(ens_measures, str):
                ens_measures = json.loads(ens_measures)

            lucia_payload = {
                "ticket_id": f"SCANOPS-{corr['id']}",
                "organismo": "UNUWARE - Laboratorio ScanOps",
                "fecha_deteccion": corr['correlated_at'].isoformat() if corr.get('correlated_at') else datetime.utcnow().isoformat(),
                "clasificacion": "INCIDENTE_SEGURIDAD",
                "tipo_incidente": corr['attack_pattern'],
                "nivel_peligrosidad": corr['threat_level'],
                "descripcion": corr['ai_reasoning'],
                "activos_afectados": affected_ips,
                "medidas_ens_incumplidas": ens_measures,
                "accion_tomada": corr['recommended_action'],
                "formato_evidencia": "STIX/JSON",
                "ens_compliance": "op.exp.7 - Notificación LUCÍA autorizada",
            }

            notification_id = str(uuid.uuid4())
            _persist_lucia_notification(notification_id, lucia_payload, False, "sandbox")

            logger.info(f"[US-6.9] INCIDENTE_LUCIA_GENERADO - ID: {correlation_id}")
            return {
                "success": True,
                "notification_id": notification_id,
                "lucia_payload": lucia_payload,
                "destination": "CCN-CERT (Sandbox)",
                "status": "READY_FOR_SUBMISSION",
                "timestamp": datetime.utcnow().isoformat(),
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generando reporte LUCIA: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@router.get("/siem/lucia/notifications")
async def list_lucia_notifications(limit: int = 20):
    """Historial de notificaciones LUCÍA generadas."""
    conn = get_conn()
    try:
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT notification_id, sent, method, notified_at,
                       payload->>'ticket_id' as ticket_id,
                       payload->>'tipo_incidente' as tipo_incidente,
                       payload->>'nivel_peligrosidad' as nivel_peligrosidad
                FROM siem_lucia_notifications
                ORDER BY notified_at DESC
                LIMIT %s
            """, (limit,))
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("notified_at"):
                    r["notified_at"] = r["notified_at"].isoformat()
        return {"total": len(rows), "notifications": rows}
    finally:
        conn.close()


@router.get("/siem/lucia/notifications/{notification_id}")
async def get_lucia_notification(notification_id: str):
    """Detalle completo de una notificación LUCÍA."""
    conn = get_conn()
    try:
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM siem_lucia_notifications WHERE notification_id = %s",
                (notification_id,)
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Notificación no encontrada")
            r = dict(row)
            if r.get("notified_at"):
                r["notified_at"] = r["notified_at"].isoformat()
            if isinstance(r.get("payload"), str):
                r["payload"] = json.loads(r["payload"])
            return r
    finally:
        conn.close()