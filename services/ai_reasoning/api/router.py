from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from services.ai_reasoning.human_validation import process_human_decision
from services.ai_reasoning.tasks import (
    filter_false_positives_task,
    map_to_ens_task,
    suggest_attack_vector_task,
    generate_preliminary_report_task
)
import logging

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

# Endpoint de salud del módulo M8
@router.get("/health", summary="Health check del módulo M8")
async def health_check():
    return {"module": "M8 AI Reasoning", "status": "ok"}
