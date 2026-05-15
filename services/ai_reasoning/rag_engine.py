# services/ai_reasoning/rag_engine.py

import json
import logging
import os
from typing import Optional
from services.ai_reasoning.ollama_client import OllamaClient

logger = logging.getLogger(__name__)

class RAGEngine:
    """
    Motor de contexto legal para el pipeline de IA de ScanOps.
    Única responsabilidad: leer el texto del RD 311/2022 y devolver
    el fragmento más relevante para una query dada, para que ens_mapper.py
    lo inyecte en el system prompt del LLM.
    """

    def __init__(self, ollama_client: OllamaClient):
        self.ollama_client = ollama_client

    async def get_ens_context(self, query: str) -> str:
        """
        Devuelve el fragmento del RD 311/2022 más relevante para la query.
        Busca por coincidencia de palabras clave en el texto legal indexado.
        Si el archivo está vacío o no existe, devuelve string vacío y el
        llamador (ens_mapper.py) continúa con conocimiento base del LLM.
        """
        try:
            import os
            base_dir = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_dir, "rag_data", "rd_311_2022.txt")

            if not os.path.exists(file_path):
                logger.warning(f"RAG data file not found: {file_path}")
                return ""

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if not content.strip():
                logger.warning("rd_311_2022.txt está vacío — el mapeo ENS usará conocimiento base del LLM")
                return ""

            sections = content.split("\n\n")
            query_words = set(query.lower().split())

            best_section = ""
            max_matches = 0

            for section in sections:
                matches = sum(1 for word in query_words if word in section.lower())
                if matches > max_matches:
                    max_matches = matches
                    best_section = section

            return best_section if best_section else content[:2000]

        except Exception as e:
            logger.error(f"Error reading RAG context: {e}")
            return ""

    def get_ens_context_from_mapping(self, cve_id: str, vuln_description: str) -> dict | None:
        """
        Fast lookup in vulnerability_mapping.json before calling the LLM.
        Returns a dict with ens_measures, primary_measure, incumplimiento if found.
        Returns None if no match found — caller should fall back to LLM.
        Priority: 1) direct CVE match, 2) keyword pattern match
        """
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            mapping_path = os.path.join(base_dir, "rag_data", "vulnerability_mapping.json")
            with open(mapping_path, "r", encoding="utf-8") as f:
                mapping = json.load(f)

            # Priority 1: direct CVE match
            direct = mapping.get("direct_cve_mappings", {}).get(cve_id)
            if direct:
                return {
                    "ens_measures": direct["measures"],
                    "primary_measure": direct["primary"],
                    "incumplimiento": "directo",
                    "source": "direct_cve_match",
                    "pattern_id": cve_id,
                }

            # Priority 2: keyword pattern match
            desc_lower = vuln_description.lower()
            best_match = None
            best_score = 0

            for pattern in mapping.get("vulnerability_patterns", []):
                score = sum(1 for kw in pattern["keywords"] if kw in desc_lower)
                if score > best_score:
                    best_score = score
                    best_match = pattern

            if best_match and best_score > 0:
                return {
                    "ens_measures": best_match["ens_measures"],
                    "primary_measure": best_match["primary_measure"],
                    "incumplimiento": best_match["incumplimiento"],
                    "source": "keyword_pattern_match",
                    "pattern_id": best_match["pattern_id"],
                }

            return None

        except Exception as e:
            logger.error(f"Error reading vulnerability_mapping.json: {e}")
            return None

# Instancia global
from services.ai_reasoning.ollama_client import ollama
rag_engine = RAGEngine(ollama)
