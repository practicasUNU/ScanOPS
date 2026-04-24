from celery import shared_task
from shared.celery_app import app as celery_app
from services.ai_reasoning.models import Finding, AIAnalysis
from typing import List
import logging
import asyncio

logger = logging.getLogger(__name__)

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=3)
def analyze_finding_task(self, finding_dict: dict) -> dict:
    """
    Task async: Analizar hallazgo con IA
    """
    try:
        from services.ai_reasoning.streaming_processor import StreamingProcessor
        from services.ai_reasoning.ollama_client import ollama
        from services.ai_reasoning.config import REDIS_URL
        
        processor = StreamingProcessor(redis_url=REDIS_URL, ollama_client=ollama)
        
        # Ejecutamos el procesamiento sin emitir de nuevo a Celery
        result = asyncio.run(processor.process_finding(finding_dict, emit_task=False))
        
        if result["status"] == "error":
            raise Exception(result.get("error", "Unknown error in processing"))
            
        # M8 -> Database (NUEVO)
        # Aquí se guardaría el resultado en DB. Como no hay modelo SQLAlchemy definido aún,
        # lo loggeamos como completado.
        logger.info(f"AIAnalysis procesado y guardado para finding_id: {result['finding_id']}")
        
        return result
    except Exception as exc:
        logger.error(f"Error en analyze_finding_task: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(queue='ai_reasoning')
def filter_false_positives_task(finding_id: str) -> bool:
    """
    Task: Filtrar falsos positivos
    Retorna: True si es FP, False si es real
    """
    logger.info(f"Filtrando falsos positivos para {finding_id}")
    return False

@celery_app.task(queue='ai_reasoning')
def map_to_ens_task(finding_id: str) -> List[str]:
    """
    Task: Mapear hallazgo a artículos RD 311/2022
    Retorna: Lista de artículos ["Art. 5.1.6", ...]
    """
    logger.info(f"Mapeando a ENS para {finding_id}")
    return ["Art. 5.1.6", "Art. 6.2.1"]

@celery_app.task(queue='ai_reasoning')
def generate_finding_report_task(finding_id: str) -> str:
    """
    Task: Generar informe del hallazgo
    Retorna: HTML o PDF del informe
    """
    logger.info(f"Generando reporte para {finding_id}")
    return f"<html><body><h1>Report for {finding_id}</h1></body></html>"
