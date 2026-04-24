import json
import logging
import asyncio
from typing import Optional, Callable, Dict, Any
import redis.asyncio as redis

from services.ai_reasoning.config import REDIS_URL, REDIS_FINDINGS_CHANNEL
from services.ai_reasoning.ollama_client import OllamaClient
from services.ai_reasoning.models import Finding, AIAnalysis, ProcessingResult
from shared.celery_app import app as celery_app
from pydantic import ValidationError
from datetime import datetime

logger = logging.getLogger(__name__)

class StreamingProcessor:
    def __init__(self, redis_url: str = None, ollama_client: OllamaClient = None):
        """
        Inicializa StreamingProcessor
        
        Args:
            redis_url: URL de Redis (default: config.REDIS_URL)
            ollama_client: Cliente Ollama para análisis (default: OllamaClient())
        """
        self.redis_url = redis_url or REDIS_URL
        self.redis = None
        self.channel = REDIS_FINDINGS_CHANNEL  # "findings:scan:*"
        self.running = False
        self.ollama_client = ollama_client or OllamaClient()
        self.process_callback: Optional[Callable] = None
        logger.info(f"StreamingProcessor initialized: redis={self.redis_url}, ollama={self.ollama_client.model}")

    async def initialize(self) -> bool:
        """
        Inicializa conexión a Redis
        """
        try:
            if not self.redis:
                self.redis = await redis.from_url(self.redis_url, decode_responses=True)
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Redis connection: {e}")
            return False

    async def start(self, process_callback: Callable = None) -> None:
        """
        Inicia listener de hallazgos en Redis
        
        Escucha canal 'findings:scan:*' y procesa cada hallazgo
        
        Args:
            process_callback: Función async para procesar (default: self.process_finding)
        """
        if not await self.initialize():
            logger.error("Failed to initialize Redis connection")
            return
        
        self.process_callback = process_callback or self.process_finding
        self.running = True
        
        try:
            # Crear subscription
            pubsub = self.redis.pubsub()
            await pubsub.psubscribe(self.channel)
            
            logger.info(f"StreamingProcessor started - listening on {self.channel}")
            
            # Loop de escucha
            while self.running:
                try:
                    # Esperar mensaje
                    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    
                    if message:
                        # Procesar mensaje
                        if message['type'] == 'pmessage':
                            await self._handle_message(message['data'])
                        
                except asyncio.CancelledError:
                    logger.info("Streaming cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    # Continuar escuchando a pesar del error
                    continue
        
        except Exception as e:
            logger.error(f"Critical error in streaming processor: {e}")
            self.running = False
        finally:
            await self.stop()

    async def stop(self) -> None:
        """
        Detiene listener limpiamente
        """
        self.running = False
        if self.redis:
            await self.redis.close()
        logger.info("StreamingProcessor stopped")

    async def process_finding(self, finding: dict) -> ProcessingResult:
        """
        Procesa un hallazgo individual
        
        Pasos:
        1. Validar estructura (Finding model)
        2. Analizar con OllamaClient
        3. Filtrar falsos positivos
        4. Mapear a RD 311/2022
        5. Emitir a Celery para async processing
        6. Retornar resultado
        
        Args:
            finding: Dict con hallazgo de M3
        
        Returns:
            ProcessingResult: {finding_id, status, analysis, error, processed_at}
        """
        finding_id = finding.get("finding_id", "unknown")
        
        try:
            # PASO 1: Validar Finding
            validated_finding = await self._validate_finding(finding)
            logger.debug(f"Finding {finding_id} validated")
            
            # PASO 2: Analizar con OllamaClient
            if not await self.ollama_client.is_available():
                logger.warning("OllamaClient not available - skipping analysis")
                return ProcessingResult(
                    finding_id=finding_id,
                    status="skipped",
                    error="OllamaClient not available"
                )
            
            # Preparar prompt de análisis
            prompt = f"""
Analiza este hallazgo de seguridad:

Título: {validated_finding.title}
Descripción: {validated_finding.description}
CVSS: {validated_finding.cvss}
CWE: {validated_finding.cwe}
Scanner: {validated_finding.scanner}

Por favor responde:
1. ¿Es este hallazgo un falso positivo? (Sí/No)
2. Si es real, ¿cuál es el riesgo real? (en 1-2 frases)
3. ¿Qué artículos de RD 311/2022 aplican?
4. ¿Cuál es la acción recomendada?
        """
            
            analysis_text = await self.ollama_client.analyze(
                prompt=prompt,
                system_prompt="Eres un experto en ciberseguridad ENS Alto. Analiza hallazgos de pentesting."
            )
            
            # PASO 3: Parsear análisis (falsos positivos, confidence, etc.)
            is_false_positive = "falso positivo" in analysis_text.lower() or "no es real" in analysis_text.lower()
            confidence = 0.8 if not is_false_positive else 0.6  # Simplificado
            
            # PASO 4: Mapear a RD 311/2022
            ens_articles = await self._map_to_ens_articles(validated_finding, analysis_text)
            
            # PASO 5: Crear AIAnalysis model
            ai_analysis = AIAnalysis(
                finding_id=finding_id,
                is_false_positive=is_false_positive,
                confidence=confidence,
                priority_score=validated_finding.cvss if not is_false_positive else 0,
                ens_articles=ens_articles,
                recommended_action=self._extract_recommendation(analysis_text),
                analysis_text=analysis_text
            )
            
            logger.info(f"Finding {finding_id} analyzed - FP:{is_false_positive}, Priority:{ai_analysis.priority_score}")
            
            # PASO 6: Emitir a Celery para async processing
            await self._emit_to_celery(validated_finding, ai_analysis)
            
            # Retornar resultado exitoso
            return ProcessingResult(
                finding_id=finding_id,
                status="success",
                analysis=ai_analysis,
                processed_at=datetime.utcnow()
            )
        
        except ValidationError as e:
            logger.warning(f"Finding {finding_id} validation failed: {e}")
            return ProcessingResult(
                finding_id=finding_id,
                status="error",
                error=f"Validation error: {str(e)}"
            )
        
        except Exception as e:
            logger.error(f"Error processing finding {finding_id}: {e}", exc_info=True)
            return ProcessingResult(
                finding_id=finding_id,
                status="error",
                error=str(e)
            )

    async def emit_finding(self, finding_data: dict) -> bool:
        """
        Emitir hallazgo a Redis stream (usado por M3)
        """
        try:
            if not self.redis:
                # Intentar inicializar si no está conectado
                if not await self.initialize():
                    logger.warning("Redis not connected and initialization failed")
                    return False
            
            message = json.dumps(finding_data)
            await self.redis.publish(self.channel.replace("*", "direct"), message)
            logger.debug(f"Finding {finding_data.get('finding_id')} emitted to Redis")
            return True
        
        except Exception as e:
            logger.error(f"Error emitting finding: {e}")
            return False

    async def _validate_finding(self, finding: dict) -> Finding:
        """
        Validar hallazgo con Pydantic
        
        Raises:
            ValidationError si hallazgo es inválido
        """
        return Finding(**finding)

    async def _handle_message(self, message: Any) -> None:
        """
        Handler de mensaje Redis
        
        Parsea JSON y procesa el hallazgo
        """
        try:
            if isinstance(message, bytes):
                message = message.decode('utf-8')
            
            finding_dict = json.loads(message)
            result = await self.process_callback(finding_dict)
            logger.debug(f"Message processed: {result.status}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in message: {e}")
        except Exception as e:
            logger.error(f"Error handling message: {e}")

    async def _emit_to_celery(self, finding: Finding, analysis: AIAnalysis) -> None:
        """
        Emitir análisis a Celery para async processing
        """
        try:
            # Emitir task a Celery
            celery_app.send_task(
                'services.ai_reasoning.tasks.analyze_finding_task',
                args=[finding.finding_id, analysis.dict()],
                queue='ai_reasoning'
            )
            logger.debug(f"Finding {finding.finding_id} emitted to Celery")
        except Exception as e:
            logger.error(f"Error emitting to Celery: {e}")

    async def _map_to_ens_articles(self, finding: Finding, analysis_text: str) -> list:
        """
        Mapear hallazgo a artículos RD 311/2022
        
        Simplificado: buscar palabras clave en el análisis
        En producción, usar RAG engine
        """
        articles = []
        
        # Mapeo simplificado CWE → Artículos ENS
        cwe_mapping = {
            "CWE-89": ["Art. 5.1.6"],  # SQL Injection → Control de entrada
            "CWE-79": ["Art. 5.1.6"],  # XSS → Control de entrada
            "CWE-22": ["Art. 5.1.6"],  # Path Traversal → Control de entrada
            "CWE-434": ["Art. 6.2.1"], # File Upload → Gestión de archivos
            "CWE-200": ["Art. 5.1.5"], # Information Disclosure → Restricción acceso
        }
        
        if finding.cwe in cwe_mapping:
            articles = cwe_mapping[finding.cwe]
        
        return articles

    def _extract_recommendation(self, analysis_text: str) -> str:
        """
        Extraer acción recomendada del análisis
        
        Simplificado: primeras 200 caracteres
        En producción, usar NLP/IA más sofisticado
        """
        return analysis_text[:200] if analysis_text else "Review by security team"

# Instancia global
processor = StreamingProcessor()
