import logging
import json
import os
import yaml
from typing import Optional, Dict
from datetime import datetime
from services.ai_reasoning.ollama_client import OllamaClient
from services.ai_reasoning.models import Finding, FilterResult

class FalsePositiveFilter:
    """Filtra hallazgos falsos (no reales)"""
    
    def __init__(self, ollama_client: OllamaClient):
        """
        Inicializar filtro
        
        Args:
            ollama_client: Cliente Ollama para análisis
        """
        self.ollama_client = ollama_client
        self.logger = logging.getLogger(__name__)
        
        # Cargar configuración de prompt desde YAML
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            yaml_path = os.path.join(base_dir, "prompts", "system_filter_fp.yaml")
            with open(yaml_path, "r", encoding="utf-8") as f:
                self._prompt_config = yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"No se pudo cargar system_filter_fp.yaml: {e}")
            self._prompt_config = {}
        
        # Reglas manuales para detectar FP
        self.rules = {
            "headers": ["x-frame-options", "content-security-policy", "strict-transport-security"],
            "common_fp": ["test", "dev", "development", "staging", "mock", "localhost"],
            "security_headers": ["x-content-type-options", "x-xss-protection"],
        }
    
    async def filter(self, finding: Finding, asset_context: Optional[Dict] = None) -> FilterResult:
        """
        Analizar hallazgo completo y retornar decisión
        
        Args:
            finding: Hallazgo a filtrar
            asset_context: Datos del activo (SO, servicios, versiones)
        
        Returns:
            FilterResult
        """
        method = "rules"
        is_fp = await self._check_rules(finding)
        
        # Si las reglas básicas no filtran, usamos el análisis experto de IA
        if is_fp is None:
            method = "expert_ai_analysis"
            ai_decision = await self._analyze_with_expert_ai(finding, asset_context)
            is_fp = ai_decision.get("is_false_positive", False)
            confidence_str = ai_decision.get("confidence", "medio")
            
            # Mapeo de confianza texto -> float
            confidence_map = {"alto": 0.95, "medio": 0.7, "bajo": 0.4}
            confidence = confidence_map.get(confidence_str.lower(), 0.5)
            reason = ai_decision.get("reason", "Análisis experto completado")
        else:
            confidence = self._calculate_confidence(finding, method)
            reason = self._extract_reason(finding, is_fp, method)
            
        status = "rejected" if is_fp else "passed"
        
        return FilterResult(
            finding_id=finding.finding_id,
            is_false_positive=is_fp,
            confidence=confidence,
            reason=reason,
            filter_method=method,
            status=status
        )

    async def _check_rules(self, finding: Finding) -> Optional[bool]:
        """Aplicar reglas deterministas rápidas"""
        desc_lower = finding.description.lower()
        title_lower = finding.title.lower()
        
        # Regla: Headers de seguridad presentes (Si dice que está, no es FP de 'missing')
        security_headers = ["x-frame-options", "content-security-policy", "strict-transport-security"]
        if any(h in desc_lower for h in security_headers):
             if any(w in desc_lower for w in ["set", "configured", "present"]):
                 return False # Es REAL (se detectó la configuración)
        
        # Regla: Ambiente de test/dev (FP casi seguro)
        if any(env in desc_lower or env in title_lower for env in self.rules["common_fp"]):
            return True
            
        # Regla: CVSS insignificante
        if finding.cvss < 2.0:
            return True
            
        # Regla: Confirmación explícita del scanner
        confirmed_words = ["confirmed", "verified", "successfully exploited", "vulnerability exists"]
        if any(word in desc_lower for word in confirmed_words):
            return False
            
        return None

    async def _analyze_with_expert_ai(self, finding: Finding, asset_context: Optional[Dict] = None) -> Dict:
        """
        Análisis experto usando el perfil de Analista ENS Alto
        """
        if not await self.ollama_client.is_available():
            self.logger.warning("OllamaClient not available, assuming real (Safe default for ENS Alto)")
            return {"is_false_positive": False, "confidence": "bajo", "reason": "Ollama no disponible, fallback a REAL por seguridad"}

        context_str = json.dumps(asset_context, indent=2) if asset_context else "No disponible"
        
        prompt = f"""
Eres un analista de seguridad experto en ENS Alto (RD 311/2022). Tu única función es determinar si una vulnerabilidad detectada es un falso positivo dado el contexto real del activo.

HALLAZGO:
- Título: {finding.title}
- Descripción: {finding.description}
- CVSS: {finding.cvss}
- CWE: {finding.cwe}
- Scanner: {finding.scanner}

CONTEXTO DEL ACTIVO:
{context_str}

REGLAS ESTRICTAS:
- Si el servicio vulnerable NO aparece en los servicios activos del activo → falso positivo.
- Si el CVE afecta a una versión distinta a la instalada en el activo → falso positivo.
- Si el sistema operativo del activo es incompatible con el exploit → falso positivo.
- En caso de duda → NO es falso positivo. En ENS Alto preferimos investigar de más que ignorar.
- Responde ÚNICAMENTE con JSON válido. Sin texto antes ni después. Sin markdown. Sin explicaciones fuera del JSON.

SCHEMA DE RESPUESTA:
{{"is_false_positive": true/false, "confidence": "alto/medio/bajo", "reason": "una línea"}}
"""
        try:
            # Obtener system_prompt y temperatura desde el YAML cargado
            system_prompt = self._prompt_config.get(
                "system",
                "Eres un experto en ciberseguridad y normativa ENS Alto."
            )
            temperature = self._prompt_config.get("temperature", 0.0)
            top_p = self._prompt_config.get("top_p", 0.9)

            response_text = await self.ollama_client.analyze(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                top_p=top_p
            )
            
            if not response_text:
                raise ValueError("Respuesta vacía de Ollama")
                
            # Limpiar posibles restos de markdown si el modelo no hizo caso
            clean_json = response_text.strip()
            if "```json" in clean_json:
                clean_json = clean_json.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_json:
                clean_json = clean_json.split("```")[1].strip()
            
            return json.loads(clean_json)
            
        except Exception as e:
            self.logger.error(f"Error en análisis experto de IA: {e}")
            return {
                "is_false_positive": False, 
                "confidence": "bajo", 
                "reason": f"Error en procesamiento: {str(e)}"
            }

    def _calculate_confidence(self, finding: Finding, method: str) -> float:
        """Calcular confianza de reglas manuales"""
        if finding.cvss > 9.0: return 0.95
        if finding.scanner.lower() == "nuclei": return 0.9
        return 0.7

    def _extract_reason(self, finding: Finding, is_fp: bool, method: str) -> str:
        """
        Generar explicación de por qué es FP o real
        """
        if is_fp:
            if finding.cvss < 3.0:
                return f"CVSS too low ({finding.cvss}) - likely false positive"
            if any(env in finding.description.lower() for env in self.rules["common_fp"]):
                return f"Finding found in non-production environment ({finding.description[:20]}...)"
            return "Analysis identified this as a false positive"
        else:
            if finding.scanner.lower() == "nuclei":
                return f"{finding.title} confirmed by Nuclei (high confidence)"
            if "confirmed" in finding.description.lower():
                return f"Vulnerability confirmed in description: {finding.title}"
            if method == "rules":
                return f"Security rule matched for {finding.title}"
            return f"Vulnerability {finding.title} analyzed as real issue"
