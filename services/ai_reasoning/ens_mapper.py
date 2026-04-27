# services/ai_reasoning/ens_mapper.py

import logging
import json
import os
import yaml
from typing import Dict, Any, Optional
from services.ai_reasoning.ollama_client import ollama, OllamaConnectionError
from services.ai_reasoning.rag_engine import rag_engine

logger = logging.getLogger(__name__)

async def map_to_ens(finding: Dict[str, Any], asset: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mapea una vulnerabilidad técnica al artículo exacto del Anexo II del RD 311/2022 (ENS Alto).
    
    Este proceso utiliza un motor RAG para obtener el contexto legal relevante del RD 311/2022
    inyectándolo dinámicamente en el system prompt, y luego emplea el modelo LLM Ollama 
    para realizar el mapeo jurídico-técnico preciso.
    
    Args:
        finding: Diccionario con los datos del hallazgo (cve, title, description, etc.)
        asset: Diccionario con los datos del activo (criticidad, servicios, etc.)
        
    Returns:
        Dict con el mapeo ENS enriquecido con metadatos para el módulo de reporting (M7).
    """
    finding_id = finding.get("finding_id", "unknown")
    asset_id = asset.get("asset_id", 0)
    
    # Extraer campos para el prompt
    cve_id = finding.get("cve", "N/A")
    vuln_type = finding.get("title", "Vulnerabilidad técnica")
    affected_service = asset.get("hostname", "Desconocido")
    impact_description = finding.get("description", "Sin descripción de impacto")
    ens_criticality = asset.get("criticidad", "MEDIO")
    sensitive_data = "SÍ" if asset.get("sensitive_data") else "NO"

    # PASO 1: Obtener contexto RAG
    # Query construida según especificación: {cve_id} {vuln_type} {affected_service}
    query = f"{cve_id} {vuln_type} {affected_service}"
    rag_context = ""
    try:
        rag_context = await rag_engine.get_ens_context(query)
    except Exception as e:
        logger.error(f"[{finding_id}] Error obteniendo contexto RAG: {e}")
        # Fallback: rag_context vacío, el LLM usará su conocimiento base

    # PASO 2: Cargar y construir System Prompt desde YAML
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        yaml_path = os.path.join(base_dir, "prompts", "system_ens_mapper.yaml")
        with open(yaml_path, "r", encoding="utf-8") as f:
            prompt_config = yaml.safe_load(f)
        
        system_base = prompt_config.get("system", "")
        system_prompt = system_base.replace("{rag_context}", rag_context)
        temperature = prompt_config.get("temperature", 0.0)
        top_p = prompt_config.get("top_p", 0.95)
    except Exception as e:
        logger.error(f"Error cargando system_ens_mapper.yaml: {e}")
        # Fallback manual si el YAML falla
        system_prompt = f"Eres un experto en ENS Alto. Contexto: {rag_context}"
        temperature = 0.0
        top_p = 0.95

    # PASO 3: Construir User Prompt
    user_prompt = f"""
VULNERABILIDAD A MAPEAR:
- CVE: {cve_id}
- Tipo técnico: {vuln_type}
- Servicio afectado: {affected_service}
- Impacto potencial: {impact_description}
- Criticidad del activo (ENS): {ens_criticality}
- ¿Datos sensibles o clasificados expuestos?: {sensitive_data}

¿Qué medidas del Anexo II del RD 311/2022 incumple esta vulnerabilidad?
"""

    # PASO 4: Llamada a Ollama (Parámetros: temp=0.0, top_p=0.95, model=llama3)
    try:
        response_text = await ollama.analyze(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            top_p=top_p
        )
        
        if not response_text:
            raise ValueError("Respuesta vacía de Ollama")

        # Limpiar posibles bloques de código markdown
        clean_json = response_text.strip()
        if "```json" in clean_json:
            clean_json = clean_json.split("```json")[1].split("```")[0].strip()
        elif "```" in clean_json:
            clean_json = clean_json.split("```")[1].strip()
            
        result = json.loads(clean_json)
        
        # Enriquecer con metadatos para consumo directo por M7
        result.update({
            "asset_id": asset_id,
            "finding_id": finding_id
        })
        
        logger.info(f"[{finding_id}] Mapeo ENS exitoso: {result.get('medida_principal')}")
        return result

    except Exception as e:
        # Propagar errores de conexión para reintento en Celery
        if isinstance(e, (OllamaConnectionError, ConnectionError)):
            logger.error(f"[{finding_id}] Error de conexión con Ollama (propagar para retry): {e}")
            raise
            
        logger.error(f"[{finding_id}] Error en procesamiento de mapeo ENS (usando fallback): {e}")
        return {
            "asset_id": asset_id,
            "finding_id": finding_id,
            "medidas_ens": ["op.exp.2"],
            "medida_principal": "op.exp.2",
            "nivel_incumplimiento": "parcial",
            "confianza_mapeo": "baja",
            "descripcion_incumplimiento": "parse_error — mapeo por defecto"
        }
