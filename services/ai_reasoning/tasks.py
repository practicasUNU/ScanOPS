from celery import shared_task
from shared.celery_app import app as celery_app
from services.ai_reasoning.models import Finding, AIAnalysis
from services.ai_reasoning.report_generator import report_generator
from services.ai_reasoning.false_positive_filter import FalsePositiveFilter
from services.ai_reasoning.ollama_client import ollama
from services.ai_reasoning.ens_mapper import map_to_ens
from services.ai_reasoning.attack_vector import suggest_attack_vector
from typing import List, Dict
import logging
import asyncio
import os

logger = logging.getLogger(__name__)

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=3)
def analyze_finding_task(self, finding_id: str, analysis_dict: dict) -> dict:
    """
    Task async: Procesar resultado de análisis de IA
    Recibe el hallazgo ya analizado por el StreamingProcessor y lo persiste/procesa.
    """
    try:
        logger.info(f"Recibido análisis para finding_id: {finding_id}")
        
        # Aquí se guardaría el resultado en DB. 
        # Como no hay modelo SQLAlchemy definido aún, lo loggeamos.
        logger.info(f"AIAnalysis procesado y guardado para finding_id: {finding_id}")
        
        return {
            "finding_id": finding_id,
            "status": "success",
            "analysis": analysis_dict
        }
    except Exception as exc:
        logger.error(f"Error en analyze_finding_task: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=2)
def filter_false_positives_task(self, finding_dict: dict, asset_dict: dict = None) -> dict:
    """
    Task: Filtrar falsos positivos usando FalsePositiveFilter (IA Experta)
    """
    try:
        finding = Finding(**finding_dict)
        fp_filter = FalsePositiveFilter(ollama_client=ollama)
        
        # Ejecutar análisis async en entorno sync de Celery
        result = asyncio.run(fp_filter.filter(finding, asset_context=asset_dict))
        
        return result.model_dump()
    except Exception as exc:
        logger.error(f"Error en filter_false_positives_task: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=2)
def map_to_ens_task(self, finding_dict: dict, asset_dict: dict) -> dict:
    """
    Task: Mapear hallazgo a artículos RD 311/2022 (ENS Alto)
    """
    try:
        result = asyncio.run(map_to_ens(finding_dict, asset_dict))
        return result
    except Exception as exc:
        logger.error(f"Error en map_to_ens_task: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=1)
def suggest_attack_vector_task(self, ficha_unica_dict: dict) -> dict:
    """
    Task: Sugerir vector de ataque (MSF Suggestion para Human-in-the-loop)
    """
    try:
        result = asyncio.run(suggest_attack_vector(ficha_unica_dict))
        return result
    except Exception as exc:
        logger.error(f"Error en suggest_attack_vector_task: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=1)
def generate_preliminary_report_task(self, hallazgos: list, activos: list, fecha_ciclo: str, fecha_sabado: str) -> str:
    """
    Task: Generar informe ejecutivo preliminar semanal (ENS op.exp.2)
    """
    try:
        result = asyncio.run(report_generator.generate_preliminary_report(
            hallazgos, activos, fecha_ciclo=fecha_ciclo, fecha_sabado=fecha_sabado
        ))
        return result
    except Exception as exc:
        logger.error(f"Error en generate_preliminary_report_task: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(queue='ai_reasoning')
def generate_finding_report_task(finding_id: str) -> str:
    """
    Task: Generar informe del hallazgo
    Retorna: HTML o PDF del informe
    """
    logger.info(f"Generando reporte para {finding_id}")
    return f"<html><body><h1>Report for {finding_id}</h1></body></html>"

@celery_app.task(queue='ai_reasoning')
def generate_report_task(findings: List[Dict], scan_id: str, scan_date: str) -> Dict:
    """
    Task: Generar informe preliminar
    
    Args:
        findings: Lista de hallazgos
        scan_id: ID escaneo
        scan_date: Fecha escaneo
    
    Returns:
        Dict con paths HTML y PDF
    """
    try:
        html = report_generator.generate_html(findings, scan_id, scan_date)
        
        # Asegurar directorio de reportes
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
            
        # Guardar HTML
        html_path = f"{reports_dir}/{scan_id}_report.html"
        report_generator.save_html(html, html_path)
        
        # Guardar PDF (si weasyprint disponible)
        pdf_path = f"{reports_dir}/{scan_id}_report.pdf"
        pdf_success = report_generator.generate_pdf(html, pdf_path)
        
        return {
            "scan_id": scan_id,
            "html_path": html_path,
            "pdf_path": pdf_path if pdf_success else None,
            "status": "success"
        }
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return {"status": "error", "error": str(e)}
