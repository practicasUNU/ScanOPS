from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from services.ai_reasoning.human_validation import process_human_decision
from services.ai_reasoning.tasks import (
    filter_false_positives_task,
    map_to_ens_task,
    suggest_attack_vector_task,
    generate_preliminary_report_task,
    post_exploitation_analysis_task,
)
import logging
import os
import psycopg2
import psycopg2.extras

_DB_URL = os.getenv("DATABASE_URL", "postgresql://scanops:scanops@postgres:5432/scanops")

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ai", tags=["AI Reasoning M8"])

# Schema de entrada para human validation
class HumanDecisionRequest(BaseModel):
    asset_id: str
    finding_id: str
    decision: str  # "validada", "corregida", "rechazada"
    corrected_module: Optional[str] = None
    operator_id: str

# Schema de entrada para disparo manual de tasks
class FichaUnicaRequest(BaseModel):
    ficha_unica: dict

class ReportRequest(BaseModel):
    hallazgos: list
    activos: list
    fecha_ciclo: str
    fecha_sabado: str

# Endpoint US-4.8: Human-in-the-loop — validar/corregir/rechazar sugerencia IA
@router.post("/decision", summary="US-4.8 Human-in-the-loop: validar decisión de IA")
async def submit_human_decision(request: HumanDecisionRequest):
    try:
        result = await process_human_decision(
            asset_id=request.asset_id,
            finding_id=request.finding_id,
            decision=request.decision,
            corrected_module=request.corrected_module,
            operator_id=request.operator_id
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error en human decision: {e}")
        raise HTTPException(status_code=500, detail="Error interno procesando decisión")

# Endpoint US-4.7: Disparar sugerencia de vector de ataque manualmente
@router.post("/attack-vector", summary="US-4.7 Sugerir vector de ataque para un activo")
async def trigger_attack_vector(request: FichaUnicaRequest):
    try:
        task = suggest_attack_vector_task.delay(request.ficha_unica)
        return {"task_id": task.id, "status": "queued"}
    except Exception as e:
        logger.error(f"Error disparando attack_vector task: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint US-4.6: Generar informe preliminar manualmente
@router.post("/report/preliminary", summary="US-4.6 Generar informe ejecutivo preliminar")
async def trigger_preliminary_report(request: ReportRequest):
    try:
        task = generate_preliminary_report_task.delay(
            request.hallazgos, request.activos,
            request.fecha_ciclo, request.fecha_sabado
        )
        return {"task_id": task.id, "status": "queued"}
    except Exception as e:
        logger.error(f"Error disparando preliminary report task: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint US-8.1: Post-explotación con qwen2.5:14b
class PostExploitRequest(BaseModel):
    approval_id: int
    asset_id: int

@router.post(
    "/post-exploit-analysis",
    summary="US-8.1 Análisis post-explotación con qwen2.5:14b sobre resultados reales de M4",
)
async def trigger_post_exploit_analysis(request: PostExploitRequest):
    """
    Lanza análisis forense post-explotación sobre la evidencia real de M4.
    Usa qwen2.5:14b vía Ollama local. Persiste en m8_post_exploit_analysis.
    ENS: op.exp.2, mp.info.3, op.exp.5
    """
    try:
        task = post_exploitation_analysis_task.delay(request.approval_id, request.asset_id)
        return {
            "task_id": task.id,
            "status": "queued",
            "approval_id": request.approval_id,
            "asset_id": request.asset_id,
            "model": "qwen2.5:14b",
            "ens": ["op.exp.2", "mp.info.3", "op.exp.5"],
        }
    except Exception as e:
        logger.error(
            "Error disparando post_exploit_analysis_task (approval_id=%d): %s",
            request.approval_id, e,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/post-exploit-analysis/{approval_id}",
    summary="US-8.1 Obtener análisis post-explotación por approval_id",
)
async def get_post_exploit_analysis(approval_id: int):
    """
    Devuelve el análisis post-explotación más reciente para un approval_id.
    Usado por el frontend para hacer polling tras encolar la task.
    Responde {"status": "found"|"not_found", "data": {...}|null}
    """
    try:
        conn = psycopg2.connect(_DB_URL, connect_timeout=5)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name='m8_post_exploit_analysis'"
            )
            if not cur.fetchone():
                conn.close()
                return {"status": "not_found", "data": None}
            cur.execute(
                """
                SELECT id, approval_id, asset_ip, risk_score,
                       critical_findings, ens_violations, remediation_priority,
                       analyst_notes, model_used,
                       LEFT(integrity_hash, 16) AS integrity_hash,
                       created_at
                FROM m8_post_exploit_analysis
                WHERE approval_id = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (approval_id,),
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return {"status": "not_found", "data": None}
        data = dict(row)
        if data.get("created_at"):
            data["created_at"] = data["created_at"].isoformat()
        return {"status": "found", "data": data}
    except Exception as e:
        logger.error("Error leyendo m8_post_exploit_analysis (approval_id=%d): %s", approval_id, e)
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint de salud del módulo M8
@router.get("/health", summary="Health check del módulo M8")
async def health_check():
    return {"module": "M8 AI Reasoning", "status": "ok"}
