# services/ai_reasoning/rag_engine.py

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

# Instancia global
from services.ai_reasoning.ollama_client import ollama
rag_engine = RAGEngine(ollama)
