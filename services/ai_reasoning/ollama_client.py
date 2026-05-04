"""
ollama_client.py — Cliente asíncrono para la API local de Ollama.

Módulo: M8 - AI Reasoning (ScanOPS)
User Story: US-4.1 — Integración LLM local mediante Ollama
Licencia: ENS Alto
"""

from __future__ import annotations

import json
import logging
from typing import AsyncGenerator, Dict, List, Optional

import httpx

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

import os

# ---------------------------------------------------------------------------
# Constantes por defecto
# ---------------------------------------------------------------------------
DEFAULT_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen3.5:latest")
DEFAULT_EMBED_MODEL: str = "nomic-embed-text"
DEFAULT_TEMPERATURE: float = 0.7
DEFAULT_TOP_P: float = 0.9
DEFAULT_TIMEOUT: float = 120.0  # segundos


# ---------------------------------------------------------------------------
# Excepciones personalizadas
# ---------------------------------------------------------------------------
class OllamaConnectionError(Exception):
    """Excepción lanzada cuando no se puede establecer conexión con Ollama.

    Se utiliza para diferenciar errores de conectividad de otros errores
    de la API, facilitando el manejo específico en capas superiores.
    """

    def __init__(self, message: str = "No se puede conectar con el servidor Ollama", url: str = "") -> None:
        self.url = url
        full_message = f"{message}" + (f" [{url}]" if url else "")
        super().__init__(full_message)


# ---------------------------------------------------------------------------
# Cliente principal
# ---------------------------------------------------------------------------
class OllamaClient:
    """Cliente asíncrono de alto nivel para interactuar con Ollama.

    Proporciona métodos para generación de texto, streaming, gestión de
    modelos y generación de embeddings, todo a través de la API REST
    local de Ollama (http://localhost:11434 por defecto).

    Attributes:
        base_url: URL base del servidor Ollama.
        model: Nombre del modelo predeterminado para inferencia.
        embed_model: Nombre del modelo predeterminado para embeddings.
        timeout: Tiempo máximo de espera para las peticiones HTTP.

    Example::

        from services.ai_reasoning.ollama_client import ollama

        if await ollama.is_available():
            result = await ollama.analyze("Explica qué es un CVE.")
            print(result)
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        embed_model: str = DEFAULT_EMBED_MODEL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Inicializa el cliente con la configuración de conexión.

        Args:
            base_url: URL base del servidor Ollama. Por defecto
                ``http://localhost:11434``.
            model: Modelo de lenguaje predeterminado para inferencia.
            embed_model: Modelo de embeddings predeterminado.
            timeout: Tiempo límite en segundos para las peticiones HTTP.
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.embed_model = embed_model
        self.timeout = timeout
        logger.info(
            "OllamaClient inicializado | base_url=%s | model=%s | embed_model=%s | timeout=%ss",
            self.base_url,
            self.model,
            self.embed_model,
            self.timeout,
        )

    # ------------------------------------------------------------------
    # Helpers privados
    # ------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        """Crea un cliente HTTP asíncrono configurado.

        Returns:
            Instancia de ``httpx.AsyncClient`` lista para usar.
        """
        return httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)

    # ------------------------------------------------------------------
    # Métodos públicos
    # ------------------------------------------------------------------

    async def is_available(self) -> bool:
        """Comprueba si el servidor Ollama está disponible y responde.

        Realiza una petición GET al endpoint raíz (``/``) y verifica que
        la respuesta sea 200 OK.

        Returns:
            ``True`` si Ollama está activo y responde correctamente,
            ``False`` en cualquier otro caso.

        Raises:
            OllamaConnectionError: Si hay un error de red inesperado que
                no sea simplemente "servidor no disponible".
        """
        logger.debug("Verificando disponibilidad de Ollama en %s", self.base_url)
        try:
            async with self._client() as client:
                response = await client.get("/")
                available = response.status_code == 200
                logger.info("Ollama disponible: %s (HTTP %s)", available, response.status_code)
                return available
        except httpx.ConnectError as exc:
            logger.warning("Ollama no disponible — error de conexión: %s", exc)
            return False
        except httpx.TimeoutException as exc:
            logger.warning("Ollama no disponible — timeout: %s", exc)
            return False
        except httpx.RequestError as exc:
            logger.error("Error de red inesperado al verificar Ollama: %s", exc)
            raise OllamaConnectionError(str(exc), url=self.base_url) from exc

    async def analyze(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
    ) -> Optional[str]:
        """Envía un prompt al modelo y devuelve la respuesta completa.

        Utiliza el endpoint ``/api/generate`` de Ollama en modo
        no-streaming (``stream: false``).

        Args:
            prompt: Texto de entrada para el modelo. Si está vacío,
                retorna ``None`` sin realizar ninguna petición.
            system_prompt: Instrucción de sistema opcional que condiciona
                el comportamiento del modelo.
            temperature: Controla la aleatoriedad de la salida
                (0.0 = determinista, 1.0 = máxima creatividad).
            top_p: Muestreo por núcleo. Solo se consideran los tokens
                cuya probabilidad acumulada supera este umbral.

        Returns:
            Texto generado por el modelo, o ``None`` si el prompt está
            vacío o se produce algún error.
        """
        if not prompt or not prompt.strip():
            logger.warning("analyze() llamado con prompt vacío — se omite la petición")
            return None

        payload: Dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": top_p,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt
            logger.debug("analyze() con system_prompt de %d caracteres", len(system_prompt))

        logger.info(
            "analyze() → model=%s | prompt_len=%d | temperature=%.2f | top_p=%.2f",
            self.model,
            len(prompt),
            temperature,
            top_p,
        )

        try:
            async with self._client() as client:
                response = await client.post("/api/generate", json=payload)
                response.raise_for_status()
                data = response.json()
                result: str = data.get("response", "")
                logger.info("analyze() completado — respuesta de %d caracteres", len(result))
                return result
        except httpx.ConnectError as exc:
            logger.error("analyze() — error de conexión con Ollama: %s", exc)
            raise OllamaConnectionError(str(exc), url=self.base_url) from exc
        except httpx.HTTPStatusError as exc:
            logger.error(
                "analyze() — error HTTP %s: %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
            return None
        except (httpx.RequestError, json.JSONDecodeError) as exc:
            logger.error("analyze() — error inesperado: %s", exc)
            return None

    async def stream_analyze(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = DEFAULT_TEMPERATURE,
    ) -> AsyncGenerator[str, None]:
        """Envía un prompt y produce la respuesta token a token (streaming).

        Utiliza el endpoint ``/api/generate`` con ``stream: true``.
        Cada fragmento de texto se cede (``yield``) en cuanto llega,
        lo que permite mostrar la respuesta de forma progresiva.

        Args:
            prompt: Texto de entrada para el modelo.
            system_prompt: Instrucción de sistema opcional.
            temperature: Controla la aleatoriedad de la salida.

        Yields:
            Fragmentos de texto según los genera el modelo.

        Raises:
            OllamaConnectionError: Si no se puede conectar con el servidor.
        """
        payload: Dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": True,
            "options": {"temperature": temperature},
        }
        if system_prompt:
            payload["system"] = system_prompt

        logger.info(
            "stream_analyze() → model=%s | prompt_len=%d | temperature=%.2f",
            self.model,
            len(prompt),
            temperature,
        )

        try:
            async with self._client() as client:
                async with client.stream("POST", "/api/generate", json=payload) as response:
                    response.raise_for_status()
                    token_count = 0
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                            text: str = chunk.get("response", "")
                            if text:
                                token_count += 1
                                yield text
                            if chunk.get("done", False):
                                break
                        except json.JSONDecodeError:
                            logger.warning("stream_analyze() — línea no JSON ignorada: %r", line[:80])
                    logger.info("stream_analyze() completado — %d fragmentos emitidos", token_count)
        except httpx.ConnectError as exc:
            logger.error("stream_analyze() — error de conexión: %s", exc)
            raise OllamaConnectionError(str(exc), url=self.base_url) from exc
        except httpx.HTTPStatusError as exc:
            logger.error(
                "stream_analyze() — error HTTP %s: %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
            return

    async def pull_model(self, model_name: str) -> bool:
        """Descarga un modelo desde el registro de Ollama.

        Invoca ``/api/pull`` y espera la respuesta completa (puede tardar
        varios minutos para modelos grandes).

        Args:
            model_name: Nombre del modelo a descargar, p.ej. ``"llama2"``
                o ``"mistral:7b"``.

        Returns:
            ``True`` si la descarga finalizó correctamente,
            ``False`` en caso de error.
        """
        logger.info("pull_model() → descargando modelo '%s'", model_name)
        payload = {"name": model_name, "stream": False}
        try:
            async with self._client() as client:
                response = await client.post("/api/pull", json=payload, timeout=600.0)
                response.raise_for_status()
                data = response.json()
                status: str = data.get("status", "")
                success = "success" in status.lower()
                logger.info("pull_model('%s') → status='%s' | éxito=%s", model_name, status, success)
                return success
        except httpx.ConnectError as exc:
            logger.error("pull_model() — error de conexión: %s", exc)
            raise OllamaConnectionError(str(exc), url=self.base_url) from exc
        except httpx.HTTPStatusError as exc:
            logger.error(
                "pull_model('%s') — error HTTP %s: %s",
                model_name,
                exc.response.status_code,
                exc.response.text[:200],
            )
            return False
        except (httpx.RequestError, json.JSONDecodeError) as exc:
            logger.error("pull_model('%s') — error inesperado: %s", model_name, exc)
            return False

    async def list_models(self) -> List[Dict]:
        """Obtiene la lista de modelos instalados localmente en Ollama.

        Invoca ``/api/tags`` y devuelve la lista de modelos con sus
        metadatos (nombre, tamaño, familia, etc.).

        Returns:
            Lista de diccionarios con información de cada modelo.
            Lista vacía si hay algún error.
        """
        logger.debug("list_models() → consultando modelos disponibles")
        try:
            async with self._client() as client:
                response = await client.get("/api/tags")
                response.raise_for_status()
                data = response.json()
                models: List[Dict] = data.get("models", [])
                logger.info("list_models() → %d modelos encontrados", len(models))
                return models
        except httpx.ConnectError as exc:
            logger.error("list_models() — error de conexión: %s", exc)
            raise OllamaConnectionError(str(exc), url=self.base_url) from exc
        except httpx.HTTPStatusError as exc:
            logger.error("list_models() — error HTTP %s", exc.response.status_code)
            return []
        except (httpx.RequestError, json.JSONDecodeError) as exc:
            logger.error("list_models() — error inesperado: %s", exc)
            return []

    async def get_model_info(self, model_name: str) -> Optional[Dict]:
        """Obtiene los metadatos detallados de un modelo específico.

        Invoca ``/api/show`` con el nombre del modelo.

        Args:
            model_name: Nombre del modelo, p.ej. ``"llama2"`` o
                ``"mistral:7b"``.

        Returns:
            Diccionario con los metadatos del modelo (modelfile, params,
            template, details…), o ``None`` si el modelo no existe o
            hay un error.
        """
        logger.debug("get_model_info('%s') → solicitando metadatos", model_name)
        try:
            async with self._client() as client:
                response = await client.post("/api/show", json={"name": model_name})
                response.raise_for_status()
                data = response.json()
                logger.info("get_model_info('%s') → OK", model_name)
                return data
        except httpx.ConnectError as exc:
            logger.error("get_model_info() — error de conexión: %s", exc)
            raise OllamaConnectionError(str(exc), url=self.base_url) from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.warning("get_model_info('%s') — modelo no encontrado (404)", model_name)
            else:
                logger.error(
                    "get_model_info('%s') — error HTTP %s",
                    model_name,
                    exc.response.status_code,
                )
            return None
        except (httpx.RequestError, json.JSONDecodeError) as exc:
            logger.error("get_model_info('%s') — error inesperado: %s", model_name, exc)
            return None

    async def generate_embedding(
        self,
        text: str,
        model: Optional[str] = None,
    ) -> Optional[List[float]]:
        """Genera un vector de embedding para el texto dado.

        Utilizado por el motor RAG (``rag_engine.py``) para convertir
        textos en representaciones vectoriales densas. Invoca
        ``/api/embeddings``.

        Args:
            text: Texto a vectorizar.
            model: Nombre del modelo de embeddings. Si es ``None`` se
                utiliza ``self.embed_model`` (``nomic-embed-text``
                por defecto).

        Returns:
            Lista de floats con el vector de embedding, o ``None``
            si ocurre algún error.
        """
        embed_model = model or self.embed_model
        logger.debug(
            "generate_embedding() → model=%s | text_len=%d",
            embed_model,
            len(text),
        )
        try:
            async with self._client() as client:
                response = await client.post(
                    "/api/embeddings",
                    json={"model": embed_model, "prompt": text},
                )
                response.raise_for_status()
                data = response.json()
                embedding: List[float] = data.get("embedding", [])
                logger.info(
                    "generate_embedding() → vector de %d dimensiones generado",
                    len(embedding),
                )
                return embedding if embedding else None
        except httpx.ConnectError as exc:
            logger.error("generate_embedding() — error de conexión: %s", exc)
            raise OllamaConnectionError(str(exc), url=self.base_url) from exc
        except httpx.HTTPStatusError as exc:
            logger.error(
                "generate_embedding() — error HTTP %s: %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
            return None
        except (httpx.RequestError, json.JSONDecodeError) as exc:
            logger.error("generate_embedding() — error inesperado: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Instancia global
# ---------------------------------------------------------------------------
ollama = OllamaClient(
    model=os.getenv("OLLAMA_MODEL", "qwen3.5:latest")
)
"""Instancia global de OllamaClient lista para importar.

Uso::

    from services.ai_reasoning.ollama_client import ollama

    result = await ollama.analyze("¿Qué es un CVE?")
"""
