# services/ai_reasoning/streaming_processor.py

import json
import logging
import asyncio
from typing import Optional, Callable, Dict, Any
import redis.asyncio as redis

from services.ai_reasoning import config
from services.ai_reasoning.ollama_client import OllamaClient
from services.ai_reasoning.models import Finding, AIAnalysis, ProcessingResult
from shared.celery_app import app as celery_app
from pydantic import ValidationError
from datetime import datetime

# Nuevos imports para conectar el pipeline real de IA (US-4.2)
from services.ai_reasoning.false_positive_filter import FalsePositiveFilter
from services.ai_reasoning.prioritizer import Prioritizer
from services.ai_reasoning.ens_mapper import map_to_ens

logger = logging.getLogger(__name__)

class StreamingProcessor:
    def __init__(self, redis_url: str = None, ollama_client: OllamaClient = None):
        """
        Inicializa StreamingProcessor
        
        Args:
            redis_url: URL de Redis (default: config.REDIS_URL)
            ollama_client: Cliente Ollama para análisis (default: OllamaClient())
        """
        self.redis_url = redis_url or config.REDIS_URL
        self.redis = None
        self.channel = config.REDIS_FINDINGS_CHANNEL  # "findings:scan:*"
        self.running = False
        self.ollama_client = ollama_client or OllamaClient()
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
        Procesa un hallazgo individual a través del pipeline completo de IA (US-4.2).

        Pipeline:
        1. Validar estructura con Pydantic (Finding model)
        2. Paso 1 IA: FalsePositiveFilter — si es FP, termina aquí
        3. Paso 2 IA: Prioritizer — calcula prioridad real y accion_recomendada
        4. Paso 3 IA: ENSMapper — mapea al artículo exacto del RD 311/2022
        5. Construir AIAnalysis y emitir a Celery para persistencia

        Args:
            finding: Dict con hallazgo de M3. Puede incluir asset_context como campo extra.

        Returns:
            ProcessingResult con status "success", "false_positive", "skipped" o "error"
        """
        finding_id = finding.get("finding_id", "unknown")

        try:
            # PASO 1: Validar Finding con Pydantic
            validated_finding = await self._validate_finding(finding)
            asset_context = finding.get("asset_context") or {}

            # PASO 2: Filtro de falso positivo (FalsePositiveFilter)
            fp_filter = FalsePositiveFilter(ollama_client=self.ollama_client)
            filter_result = await fp_filter.filter(validated_finding, asset_context=asset_context)

            if filter_result.is_false_positive:
                logger.info(f"[{finding_id}] Descartado como FP: {filter_result.reason}")
                return ProcessingResult(
                    finding_id=finding_id,
                    status="false_positive",
                    error=filter_result.reason
                )

            # PASO 3: Priorización (Prioritizer)
            prio = Prioritizer(ollama_client=self.ollama_client)
            priority_data = await prio.prioritize(validated_finding, asset_context=asset_context)

            # Si la acción es descartar, terminar sin pasar a ENS ni Celery
            if priority_data.get("accion_recomendada") == "descartar":
                logger.info(f"[{finding_id}] Descartado por prioridad baja: {priority_data.get('justificacion')}")
                return ProcessingResult(
                    finding_id=finding_id,
                    status="skipped",
                    error=f"Prioridad baja: {priority_data.get('justificacion')}"
                )

            # PASO 4: Mapeo ENS (ENSMapper)
            ens_result = await map_to_ens(finding, asset_context)
            medidas = ens_result.get("medidas_ens", ["op.exp.2"])

            # PASO 5: Construir AIAnalysis con los datos de los tres pasos
            # priority_score se limita a 10.0 para cumplir el campo del modelo
            raw_score = priority_data.get("prioridad_real", validated_finding.cvss)
            priority_score = min(float(raw_score), 10.0)

            ai_analysis = AIAnalysis(
                finding_id=finding_id,
                is_false_positive=False,
                confidence=filter_result.confidence,
                priority_score=priority_score,
                ens_articles=medidas,
                recommended_action=priority_data.get("accion_recomendada", "monitorizar"),
                analysis_text=priority_data.get("justificacion", "")
            )

            logger.info(
                f"[{finding_id}] Pipeline completo: "
                f"prioridad={priority_score} accion={ai_analysis.recommended_action} "
                f"ens={medidas[0] if medidas else 'N/A'}"
            )

            # PASO 6: Emitir a Celery para persistencia
            await self._emit_to_celery(validated_finding, ai_analysis)

            return ProcessingResult(
                finding_id=finding_id,
                status="success",
                analysis=ai_analysis,
                processed_at=datetime.utcnow()
            )

        except ValidationError as e:
            logger.warning(f"[{finding_id}] Validación fallida: {e}")
            return ProcessingResult(finding_id=finding_id, status="error", error=f"Validation: {str(e)}")

        except Exception as e:
            logger.error(f"[{finding_id}] Error en pipeline: {e}", exc_info=True)
            return ProcessingResult(finding_id=finding_id, status="error", error=str(e))

    async def emit_finding(self, finding_data: dict) -> bool:
        """
        Emitir hallazgo a Redis stream (usado por M3)
        """
        try:
            if not self.redis:
                # Intentar inicializar si no está conectado
                if not await self.initialize():
                    logger.warning("Redis not connected")
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
                args=[finding.finding_id, analysis.model_dump()],
                queue='ai_reasoning'
            )
            logger.debug(f"Finding {finding.finding_id} emitted to Celery")
        except Exception as e:
            logger.error(f"Error emitting to Celery: {e}")

# Instancia global
processor = StreamingProcessor()
