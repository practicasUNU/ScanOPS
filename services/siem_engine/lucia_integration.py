# FILE: services/siem_engine/lucia_integration.py
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException
from shared.scan_logger import ScanLogger
from .db import get_conn

logger = ScanLogger("siem_engine.lucia")
router = APIRouter(tags=["US-6.9 CCN-CERT LUCÍA"])

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

            # Decodificar JSONs de la base de datos si vienen como string
            affected_ips = corr['affected_ips']
            if isinstance(affected_ips, str):
                affected_ips = json.loads(affected_ips)
                
            ens_measures = corr['ens_measures']
            if isinstance(ens_measures, str):
                ens_measures = json.loads(ens_measures)

            # Mapeo al esquema estándar de LUCÍA / CCN-CERT
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
                "ens_compliance": "op.exp.7 - Notificación LUCÍA autorizada"
            }

            logger.info(f"[US-6.9] INCIDENTE_LUCIA_GENERADO - ID: {correlation_id}")
            return {
                "success": True,
                "lucia_payload": lucia_payload,
                "destination": "CCN-CERT (Sandbox)",
                "status": "READY_FOR_SUBMISSION",
                "timestamp": datetime.utcnow().isoformat()
            }
    except Exception as e:
        logger.error(f"Error generando reporte LUCIA: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()