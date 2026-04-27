# services/ai_reasoning/attack_vector.py

import logging
import json
import os
import yaml
from datetime import datetime
from typing import Dict, Any
from services.ai_reasoning.ollama_client import ollama

logger = logging.getLogger(__name__)

async def suggest_attack_vector(ficha_unica: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sugiere el módulo de Metasploit y el vector de ataque óptimo.
    
    Este es el último paso automatizado (Paso 5) antes del proceso human-in-the-loop 
    obligatorio (US-4.8). Analiza el contexto completo del activo y sus vulnerabilidades 
    confirmadas para proponer una validación segura y efectiva.
    
    Args:
        ficha_unica: Diccionario con todos los datos del activo, hallazgos,
                     servicios y restricciones operacionales.
        
    Returns:
        Dict con la propuesta de ataque estructurada para Metasploit y metadatos de auditoría.
    """
    asset_id = ficha_unica.get("asset_id")
    cve_id = ficha_unica.get("cve_id")
    
    # Cargar Prompt desde YAML (Mantenimiento de prompts fuera del código)
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        yaml_path = os.path.join(base_dir, "prompts", "system_attack_vector.yaml")
        
        with open(yaml_path, "r", encoding="utf-8") as f:
            prompt_config = yaml.safe_load(f)
            
    except Exception as e:
        logger.error(f"Error crítico cargando configuración de prompt YAML: {e}")
        raise

    # Construir User Prompt inyectando variables de la ficha única
    user_template = prompt_config["user_template"]
    user_prompt = user_template.format(
        asset_id=asset_id,
        hostname=ficha_unica.get("hostname", "N/A"),
        target_ip=ficha_unica.get("target_ip", "N/A"),
        os=ficha_unica.get("os", "Unknown"),
        os_version=ficha_unica.get("os_version", "Unknown"),
        ens_criticality=ficha_unica.get("ens_criticality", "MEDIO"),
        exposure_level=ficha_unica.get("exposure_level", "INTERNAL"),
        open_services=ficha_unica.get("open_services", "Ninguno"),
        confirmed_cves=ficha_unica.get("confirmed_cves", "Ninguno"),
        exploitation_history=ficha_unica.get("exploitation_history", "Sin historial previo"),
        maintenance_window=ficha_unica.get("maintenance_window", "No definida"),
        sandbox_available=ficha_unica.get("sandbox_available", "NO"),
        critical_services_no_touch=ficha_unica.get("critical_services_no_touch", "Ninguno")
    )

    # Llamada a Ollama (Parámetros desde YAML)
    try:
        response_text = await ollama.analyze(
            prompt=user_prompt,
            system_prompt=prompt_config["system"],
            temperature=prompt_config.get("temperature", 0.2),
            top_p=prompt_config.get("top_p", 0.9)
        )
        
        if not response_text:
            raise ValueError("Respuesta vacía de Ollama")

        # Limpiar posibles restos de bloques de código markdown
        clean_json = response_text.strip()
        if "```json" in clean_json:
            clean_json = clean_json.split("```json")[1].split("```")[0].strip()
        elif "```" in clean_json:
            clean_json = clean_json.split("```")[1].strip()
            
        result = json.loads(clean_json)
        
        # VALIDACIÓN OBLIGATORIA DEL OUTPUT
        msf_module = result.get("msf_module")
        if not msf_module or not msf_module.strip():
            raise ValueError("El LLM devolvió un msf_module vacío o inválido")
            
        # Lógica de revisión manual (Human-in-the-loop)
        requires_manual_review = False
        if msf_module == "UNKNOWN":
            requires_manual_review = True
            logger.info(f"[{asset_id}] Módulo sugerido como UNKNOWN - Marcado para revisión manual")
            
        confidence = str(result.get("confidence", "bajo")).lower()
        if confidence == "bajo":
            requires_manual_review = True
            logger.warning(f"[{asset_id}] Baja confianza en la sugerencia - Requiere revisión manual")
        
        # Enriquecer resultado con metadatos de auditoría ENS
        final_result = {
            **result,
            "asset_id": asset_id,
            "cve_id": cve_id,
            "status": "pending_human_approval",
            "requires_manual_review": requires_manual_review,
            "prompt_version": prompt_config.get("version", "unknown"),
            "generated_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"[{asset_id}] Vector de ataque sugerido: {msf_module} (Confianza: {confidence})")
        return final_result

    except Exception as e:
        # Errores de parseo o conexión se propagan para reintento en Celery
        logger.error(f"[{asset_id}] Error en suggest_attack_vector: {e}")
        raise
