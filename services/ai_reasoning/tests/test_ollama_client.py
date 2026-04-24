"""
test_ollama_client.py — Suite de tests para OllamaClient.

Módulo: M8 - AI Reasoning (ScanOPS)
User Story: US-4.1
Cobertura objetivo: > 90 %

Estructura:
    TestOllamaClientUnit        — 11 tests unitarios con mocks (sin Ollama real)
    TestOllamaClientIntegration — 5 tests E2E (requieren Ollama activo)
"""

from __future__ import annotations

import json
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from services.ai_reasoning.ollama_client import OllamaClient, OllamaConnectionError

# ---------------------------------------------------------------------------
# Fixtures compartidas
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> OllamaClient:
    """Fixture que proporciona una instancia de OllamaClient para tests unitarios.

    No realiza ninguna petición real al servidor.
    """
    return OllamaClient(
        base_url="http://localhost:11434",
        model="llama2",
        embed_model="nomic-embed-text",
        timeout=30.0,
    )


@pytest.fixture
def mock_httpx_client():
    """Fixture que parchea ``httpx.AsyncClient`` con un mock asíncrono.

    Yields:
        Mock del cliente HTTP listo para configurar respuestas.
    """
    with patch("services.ai_reasoning.ollama_client.httpx.AsyncClient") as mock_cls:
        mock_instance = AsyncMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        yield mock_instance


def _make_response(status_code: int = 200, json_data: dict | None = None, text: str = "") -> MagicMock:
    """Helper para construir respuestas HTTP falsas.

    Args:
        status_code: Código HTTP de la respuesta.
        json_data: Datos JSON que devolverá ``.json()``.
        text: Texto plano de la respuesta.

    Returns:
        MagicMock configurado como respuesta httpx.
    """
    response = MagicMock()
    response.status_code = status_code
    response.text = text or json.dumps(json_data or {})
    response.json = MagicMock(return_value=json_data or {})
    if status_code >= 400:
        response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                message=f"HTTP {status_code}",
                request=MagicMock(),
                response=response,
            )
        )
    else:
        response.raise_for_status = MagicMock(return_value=None)
    return response


# ---------------------------------------------------------------------------
# TestOllamaClientUnit — Tests unitarios con mocks
# ---------------------------------------------------------------------------


class TestOllamaClientUnit:
    """Tests unitarios para OllamaClient que no requieren Ollama activo.

    Todos los métodos HTTP son reemplazados por mocks para garantizar
    ejecución aislada y determinista.
    """

    def test_client_init(self, client: OllamaClient) -> None:
        """Verifica que el cliente se inicializa con los valores correctos.

        Comprueba que ``base_url``, ``model``, ``embed_model`` y
        ``timeout`` se almacenan según los parámetros recibidos.
        """
        assert client.base_url == "http://localhost:11434"
        assert client.model == "llama2"
        assert client.embed_model == "nomic-embed-text"
        assert client.timeout == 30.0

    @pytest.mark.asyncio
    async def test_is_available_success(self, mock_httpx_client) -> None:
        """Verifica que ``is_available()`` retorna ``True`` cuando Ollama responde 200."""
        mock_httpx_client.get = AsyncMock(return_value=_make_response(200))
        c = OllamaClient()
        result = await c.is_available()
        assert result is True
        mock_httpx_client.get.assert_awaited_once_with("/")

    @pytest.mark.asyncio
    async def test_is_available_failure(self, mock_httpx_client) -> None:
        """Verifica que ``is_available()`` retorna ``False`` cuando Ollama responde 503."""
        mock_httpx_client.get = AsyncMock(return_value=_make_response(503))
        c = OllamaClient()
        result = await c.is_available()
        assert result is False

    @pytest.mark.asyncio
    async def test_is_available_connection_error(self, mock_httpx_client) -> None:
        """Verifica que ``is_available()`` retorna ``False`` ante ``ConnectError``.

        Un error de conexión no debe propagar excepción, sino retornar
        ``False`` para que el caller pueda degradar graciosamente.
        """
        mock_httpx_client.get = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        c = OllamaClient()
        result = await c.is_available()
        assert result is False

    @pytest.mark.asyncio
    async def test_analyze_success(self, mock_httpx_client) -> None:
        """Verifica que ``analyze()`` devuelve el texto generado por el modelo."""
        expected = "Un CVE es un identificador de vulnerabilidad conocida."
        mock_httpx_client.post = AsyncMock(
            return_value=_make_response(200, {"response": expected})
        )
        c = OllamaClient()
        result = await c.analyze("¿Qué es un CVE?")
        assert result == expected

    @pytest.mark.asyncio
    async def test_analyze_with_system_prompt(self, mock_httpx_client) -> None:
        """Verifica que ``analyze()`` incluye ``system`` en el payload cuando se proporciona.

        Comprueba que el campo ``system`` llega al cuerpo de la petición
        POST correctamente.
        """
        mock_httpx_client.post = AsyncMock(
            return_value=_make_response(200, {"response": "Respuesta segura."})
        )
        c = OllamaClient()
        result = await c.analyze(
            prompt="Describe el riesgo.",
            system_prompt="Eres un experto en ciberseguridad ENS.",
        )
        assert result == "Respuesta segura."
        call_kwargs = mock_httpx_client.post.call_args
        payload = call_kwargs[1]["json"]
        assert "system" in payload
        assert payload["system"] == "Eres un experto en ciberseguridad ENS."

    @pytest.mark.asyncio
    async def test_analyze_empty_prompt(self, client: OllamaClient) -> None:
        """Verifica que ``analyze()`` retorna ``None`` para prompts vacíos.

        Un prompt vacío o solo espacios no debe generar ninguna petición HTTP.
        """
        result = await client.analyze("")
        assert result is None

        result_spaces = await client.analyze("   ")
        assert result_spaces is None

    @pytest.mark.asyncio
    async def test_analyze_api_error(self, mock_httpx_client) -> None:
        """Verifica que ``analyze()`` retorna ``None`` ante un error HTTP 500.

        Los errores del servidor no deben propagar excepciones,
        sino ser capturados y registrados.
        """
        mock_httpx_client.post = AsyncMock(
            return_value=_make_response(500, text="Internal Server Error")
        )
        c = OllamaClient()
        result = await c.analyze("Prompt de prueba")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_models_success(self, mock_httpx_client) -> None:
        """Verifica que ``list_models()`` devuelve la lista de modelos correctamente."""
        models_data = {
            "models": [
                {"name": "llama2", "size": 3_800_000_000},
                {"name": "mistral:7b", "size": 7_200_000_000},
            ]
        }
        mock_httpx_client.get = AsyncMock(
            return_value=_make_response(200, models_data)
        )
        c = OllamaClient()
        result = await c.list_models()
        assert len(result) == 2
        assert result[0]["name"] == "llama2"
        assert result[1]["name"] == "mistral:7b"

    @pytest.mark.asyncio
    async def test_pull_model_success(self, mock_httpx_client) -> None:
        """Verifica que ``pull_model()`` retorna ``True`` cuando la descarga es exitosa."""
        mock_httpx_client.post = AsyncMock(
            return_value=_make_response(200, {"status": "success"})
        )
        c = OllamaClient()
        result = await c.pull_model("llama2")
        assert result is True

    @pytest.mark.asyncio
    async def test_stream_analyze_success(self, mock_httpx_client) -> None:
        """Verifica que ``stream_analyze()`` produce fragmentos de texto en orden.

        Simula una respuesta de streaming con dos fragmentos y un chunk
        final ``done: true``.
        """
        chunks = [
            json.dumps({"response": "Hola", "done": False}),
            json.dumps({"response": " mundo", "done": False}),
            json.dumps({"response": "", "done": True}),
        ]

        async def _aiter_lines():
            for chunk in chunks:
                yield chunk

        mock_stream_response = AsyncMock()
        mock_stream_response.raise_for_status = MagicMock(return_value=None)
        mock_stream_response.aiter_lines = _aiter_lines
        mock_stream_response.__aenter__ = AsyncMock(return_value=mock_stream_response)
        mock_stream_response.__aexit__ = AsyncMock(return_value=False)

        mock_httpx_client.stream = MagicMock(return_value=mock_stream_response)

        c = OllamaClient()
        collected: list[str] = []
        async for token in c.stream_analyze("Di hola"):
            collected.append(token)

        assert collected == ["Hola", " mundo"]


# ---------------------------------------------------------------------------
# TestOllamaClientIntegration — Tests E2E (requieren Ollama real)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOllamaClientIntegration:
    """Tests de integración end-to-end que requieren un servidor Ollama activo.

    Ejecutar solo en entornos donde Ollama esté instalado y corriendo::

        pytest -m integration services/ai_reasoning/tests/test_ollama_client.py

    Los tests asumen que el modelo ``llama2`` está descargado.
    """

    @pytest.mark.asyncio
    async def test_ollama_available(self) -> None:
        """Verifica (E2E) que Ollama está activo y responde en localhost:11434."""
        c = OllamaClient()
        available = await c.is_available()
        assert available is True, (
            "Ollama no está disponible. Asegúrate de que el servicio esté corriendo: "
            "`ollama serve`"
        )

    @pytest.mark.asyncio
    async def test_ollama_list_models(self) -> None:
        """Verifica (E2E) que ``list_models()`` devuelve al menos un modelo instalado."""
        c = OllamaClient()
        models = await c.list_models()
        assert isinstance(models, list)
        assert len(models) >= 1, "No hay modelos instalados en Ollama."

    @pytest.mark.asyncio
    async def test_ollama_analyze_simple(self) -> None:
        """Verifica (E2E) que ``analyze()`` genera una respuesta no vacía con llama2."""
        c = OllamaClient()
        result = await c.analyze("Responde solo con 'OK' y nada más.")
        assert result is not None
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_ollama_analyze_with_system_prompt(self) -> None:
        """Verifica (E2E) que el system_prompt condiciona correctamente la respuesta."""
        c = OllamaClient()
        result = await c.analyze(
            prompt="¿Cómo te llamas?",
            system_prompt="Eres un asistente de seguridad llamado ScanBot. Preséntate siempre así.",
        )
        assert result is not None
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_ollama_has_llama2_model(self) -> None:
        """Verifica (E2E) que el modelo llama2 está disponible en la instalación local."""
        c = OllamaClient()
        models = await c.list_models()
        model_names = [m.get("name", "") for m in models]
        assert any("llama2" in name for name in model_names), (
            f"El modelo llama2 no está instalado. Modelos disponibles: {model_names}. "
            "Ejecuta: `ollama pull llama2`"
        )
