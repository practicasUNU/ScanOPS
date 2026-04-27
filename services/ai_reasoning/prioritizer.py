import logging
import json
import os
import yaml
from typing import List, Optional, Dict, Any
from services.ai_reasoning.models import Finding, PriorityResult
from services.ai_reasoning.ollama_client import OllamaClient

logger = logging.getLogger(__name__)

class Prioritizer:
    """Calcula la prioridad REAL basada en impacto y exposición"""
    
    def __init__(self, ollama_client: Optional[OllamaClient] = None):
        self.ollama_client = ollama_client
        self.logger = logging.getLogger(__name__)
        
        # Cargar configuración de prompt desde YAML
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            yaml_path = os.path.join(base_dir, "prompts", "system_prioritizer.yaml")
            with open(yaml_path, "r", encoding="utf-8") as f:
                self._prompt_config = yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"No se pudo cargar system_prioritizer.yaml: {e}")
            self._prompt_config = {}
            
        # Escalas base para lógica local (fallback)
        self.criticality_scale = {
            "CRITICO": 1.0,
            "ALTO": 0.8,
            "MEDIO": 0.5,
            "BAJO": 0.2
        }
        
        self.exposure_scale = {
            "INTERNET": 1.5,
            "DMZ": 1.2,
            "INTERNAL": 1.0,
            "ISOLATED": 0.5
        }

    async def prioritize(self, finding: Finding, asset_context: Optional[Dict] = None) -> Dict:
        """
        Priorizar hallazgo usando el Arquitecto Experto de IA
        
        Args:
            finding: Hallazgo
            asset_context: Contexto del activo (criticidad, red, tipo)
            
        Returns:
            Dict con prioridad_real, cvss_ajustado, etc.
        """
        if not self.ollama_client or not await self.ollama_client.is_available():
            self.logger.warning("OllamaClient not available, using local calculation")
            return self._calculate_local_priority(finding, asset_context)

        context_str = json.dumps(asset_context, indent=2) if asset_context else "No disponible"
        
        prompt = f"""
Eres un arquitecto de seguridad especializado en ENS Alto. Tu función es calcular la prioridad REAL de una vulnerabilidad. El CVSS genérico no es suficiente: debes cruzarlo con la criticidad real del activo y su exposición.

HALLAZGO:
- Título: {finding.title}
- Descripción: {finding.description}
- CVSS Base: {finding.cvss}
- CWE: {finding.cwe}

CONTEXTO DEL ACTIVO:
{context_str}

FÓRMULA OBLIGATORIA:
prioridad_real = criticidad_activo × cvss_ajustado × factor_exposicion

ESCALA criticidad_activo:
- CRÍTICO (Active Directory, firewall perimetral, BBDD producción) = 1.0
- ALTO (servidor web producción, VPN, proxy) = 0.8
- MEDIO (servidor interno, aplicación interna) = 0.5
- BAJO (equipo de usuario, impresora, dispositivo no crítico) = 0.2

ESCALA factor_exposicion:
- Expuesto directamente a internet = 1.5
- En DMZ = 1.2
- Solo red interna = 1.0
- Aislado o sandbox = 0.5

ESCALA accion_recomendada según prioridad_real:
- >= 8.0 → "explotar_inmediato"
- >= 5.0 → "explotar_ciclo"
- >= 2.0 → "monitorizar"
- < 2.0  → "descartar"

Responde ÚNICAMENTE con JSON válido. Sin texto antes ni después. Sin markdown.

SCHEMA DE RESPUESTA:
{{"prioridad_real": float, "cvss_ajustado": float, "factor_exposicion": float, "accion_recomendada": "string", "justificacion": "una línea"}}
"""
        try:
            # Obtener system_prompt y temperatura desde el YAML cargado
            system_prompt = self._prompt_config.get(
                "system",
                "Eres un arquitecto experto en priorización de riesgos para ENS Alto."
            )
            temperature = self._prompt_config.get("temperature", 0.1)
            top_p = self._prompt_config.get("top_p", 0.9)

            response_text = await self.ollama_client.analyze(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                top_p=top_p
            )
            
            # Limpiar posibles restos de markdown
            clean_json = response_text.strip()
            if "```json" in clean_json:
                clean_json = clean_json.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_json:
                clean_json = clean_json.split("```")[1].strip()
            
            return json.loads(clean_json)
            
        except Exception as e:
            self.logger.error(f"Error en priorización experta: {e}")
            return self._calculate_local_priority(finding, asset_context)

    def _calculate_local_priority(self, finding: Finding, asset_context: Optional[Dict] = None) -> Dict:
        """Cálculo matemático local como fallback"""
        # Extraer criticidad del contexto o usar MEDIO
        crit_key = (asset_context or {}).get("criticidad", "MEDIO").upper()
        criticidad = self.criticality_scale.get(crit_key, 0.5)
        
        # Extraer exposición o usar INTERNAL
        exp_key = (asset_context or {}).get("exposure", "INTERNAL").upper()
        exposicion = self.exposure_scale.get(exp_key, 1.0)
        
        # CVSS ajustado (usamos el CVSS base para el fallback)
        cvss_ajustado = finding.cvss
        
        prioridad_real = criticidad * cvss_ajustado * exposicion
        
        # Determinar acción
        if prioridad_real >= 8.0: accion = "explotar_inmediato"
        elif prioridad_real >= 5.0: accion = "explotar_ciclo"
        elif prioridad_real >= 2.0: accion = "monitorizar"
        else: accion = "descartar"
        
        return {
            "prioridad_real": round(prioridad_real, 2),
            "cvss_ajustado": cvss_ajustado,
            "factor_exposicion": exposicion,
            "accion_recomendada": accion,
            "justificacion": f"Cálculo automático (Fall-back): {crit_key} Asset, {exp_key} Network"
        }

    async def rank_findings(self, findings: List[Finding], contexts: Optional[Dict[str, Dict]] = None) -> List[Dict[str, Any]]:
        """
        Ordenar hallazgos por prioridad real
        """
        results = []
        for finding in findings:
            asset_context = (contexts or {}).get(finding.finding_id)
            priority_data = await self.prioritize(finding, asset_context)
            
            results.append({
                "finding_id": finding.finding_id,
                "title": finding.title,
                "priority_score": priority_data["prioridad_real"],
                "details": priority_data
            })
            
        # Ordenar por score
        results.sort(key=lambda x: x["priority_score"], reverse=True)
        
        # Agregar rank
        for idx, result in enumerate(results, 1):
            result["rank"] = idx
            
        return results

# Instancia global (requiere inyectar cliente después si se usa IA)
prioritizer = Prioritizer()
