"""
Tests para scanner_network.py — Módulo 2 de ScanOps
=====================================================
Estos tests verifican que el parseo de Nmap funciona correctamente
sin necesidad de tener Nmap instalado ni un servidor real.

Ejecutar: pytest tests/test_scanner_network.py -v
"""
import asyncio
import pytest
import json
import os
import sys
from unittest.mock import patch, MagicMock, AsyncMock

# Añadir el directorio raíz al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.modules import scanner_network


# ============================================================
# FIXTURES: Datos de ejemplo que simulan la salida real de Nmap
# ============================================================

@pytest.fixture
def nmap_output_normal():
    """Simula una salida típica de Nmap con puertos abiertos y filtrados."""
    return """Starting Nmap 7.94 ( https://nmap.org ) at 2026-04-20 10:25 CEST
Nmap scan report for 10.202.15.100
Host is up (0.0012s latency).

PORT      STATE    SERVICE  VERSION
22/tcp    open     ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13
80/tcp    open     http     Apache httpd 2.4.58
443/tcp   open     https    Apache httpd 2.4.58 (SSL)
19999/tcp filtered netdata

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds"""


@pytest.fixture
def nmap_output_all_closed():
    """Simula una salida donde todos los puertos están cerrados."""
    return """Starting Nmap 7.94 ( https://nmap.org ) at 2026-04-20 10:25 CEST
Nmap scan report for 10.202.15.100
Host is up (0.0012s latency).

PORT      STATE  SERVICE VERSION
22/tcp    closed ssh
80/tcp    closed http
443/tcp   closed https
19999/tcp closed netdata

Nmap done: 1 IP address (1 host up) scanned in 5.00 seconds"""


@pytest.fixture
def nmap_output_spacing_variable():
    """Simula la salida real de Nmap con espacios variables (el bug original)."""
    return """Starting Nmap 7.94 ( https://nmap.org )
PORT      STATE         SERVICE    VERSION
22/tcp    open          ssh        OpenSSH 9.6p1
80/tcp    open          http       Apache httpd
443/tcp   open          https      Apache httpd
19999/tcp filtered      netdata"""


# ============================================================
# FUNCIÓN AUXILIAR: Extraer la lógica de parseo para testearla
# ============================================================

from src.utils import parsear_puerto, calcular_resumen_network


def parse_nmap_output(output):
    """
    Extrae hallazgos de la salida de Nmap usando las funciones de utils.
    """
    hallazgos = []
    lines = output.split('\n')
    for line in lines:
        if '/tcp' in line and ('open' in line or 'filtered' in line):
            hallazgo = parsear_puerto(line.strip())
            if hallazgo:
                hallazgos.append(hallazgo)

    resumen = calcular_resumen_network(hallazgos)
    return hallazgos, resumen


# ============================================================
# TESTS UNITARIOS: Parseo de salida Nmap
# ============================================================

class TestNmapParsing:
    """Tests que verifican que el parseo de Nmap detecta correctamente
    puertos, servicios y estados."""

    def test_detecta_puertos_abiertos(self, nmap_output_normal):
        """Debe detectar los 3 puertos abiertos (22, 80, 443)."""
        hallazgos, resumen = parse_nmap_output(nmap_output_normal)
        assert resumen["puertos_abiertos"] == 3

    def test_detecta_puerto_filtrado(self, nmap_output_normal):
        """Debe detectar el puerto 19999 como filtrado."""
        hallazgos, resumen = parse_nmap_output(nmap_output_normal)
        assert resumen["puertos_filtrados"] == 1

    def test_detecta_ssl_activo(self, nmap_output_normal):
        """Si el puerto 443 está abierto, ssl_activo debe ser True."""
        hallazgos, resumen = parse_nmap_output(nmap_output_normal)
        assert resumen["ssl_activo"] is True

    def test_detecta_firewall(self, nmap_output_normal):
        """Si 19999 está filtrado, firewall_detectado debe ser True."""
        hallazgos, resumen = parse_nmap_output(nmap_output_normal)
        assert resumen["firewall_detectado"] is True

    def test_genera_4_hallazgos(self, nmap_output_normal):
        """Debe generar exactamente 4 hallazgos (uno por puerto escaneado)."""
        hallazgos, _ = parse_nmap_output(nmap_output_normal)
        assert len(hallazgos) == 4

    def test_espacios_variables_no_rompen_parseo(self, nmap_output_spacing_variable):
        """BUG ORIGINAL: Nmap usa tabs/espacios variables.
        El parseo con regex debe funcionar igual."""
        hallazgos, resumen = parse_nmap_output(nmap_output_spacing_variable)
        assert resumen["puertos_abiertos"] == 3
        assert resumen["puertos_filtrados"] == 1

    def test_puertos_cerrados_no_generan_hallazgos(self, nmap_output_all_closed):
        """Los puertos cerrados no deben aparecer como hallazgos."""
        hallazgos, resumen = parse_nmap_output(nmap_output_all_closed)
        assert len(hallazgos) == 0
        assert resumen["puertos_abiertos"] == 0

    def test_sin_salida_nmap_no_falla(self):
        """Si Nmap no devuelve nada, no debe lanzar excepción."""
        hallazgos, resumen = parse_nmap_output("")
        assert len(hallazgos) == 0
        assert resumen["puertos_abiertos"] == 0


# ============================================================
# TESTS DE ESTRUCTURA: Verifican el formato del JSON de salida
# ============================================================

class TestNetworkJsonStructure:
    """Tests que verifican que el JSON generado tiene los campos
    obligatorios para el ENS y para el orquestador."""

    def test_hallazgo_tiene_campos_obligatorios(self, nmap_output_normal):
        """Cada hallazgo debe tener: puerto, servicio, estado, version,
        severidad, medida_ens, nota."""
        hallazgos, _ = parse_nmap_output(nmap_output_normal)
        campos_requeridos = ["puerto", "servicio", "estado", "version",
                             "severidad", "medida_ens", "nota", "detalle"]
        for h in hallazgos:
            for campo in campos_requeridos:
                assert campo in h, f"Falta campo '{campo}' en hallazgo {h}"

    def test_severidad_valores_validos(self, nmap_output_normal):
        """La severidad debe ser uno de los valores permitidos."""
        hallazgos, _ = parse_nmap_output(nmap_output_normal)
        valores_validos = {"INFO", "BAJA", "MEDIA", "ALTA", "CRITICA"}
        for h in hallazgos:
            assert h["severidad"] in valores_validos, \
                f"Severidad '{h['severidad']}' no válida en {h['puerto']}"

    def test_medida_ens_no_vacia(self, nmap_output_normal):
        """Cada hallazgo debe tener una medida ENS asociada."""
        hallazgos, _ = parse_nmap_output(nmap_output_normal)
        for h in hallazgos:
            assert h["medida_ens"] != "", \
                f"medida_ens vacía en {h['puerto']}"

    def test_ssh_tiene_severidad_info(self, nmap_output_normal):
        """SSH abierto debe tener severidad INFO (es esperado)."""
        hallazgos, _ = parse_nmap_output(nmap_output_normal)
        ssh = next(h for h in hallazgos if h["puerto"] == "22/tcp")
        assert ssh["severidad"] == "INFO"

    def test_resumen_tiene_campos_obligatorios(self, nmap_output_normal):
        """El resumen debe tener los 4 campos esperados."""
        _, resumen = parse_nmap_output(nmap_output_normal)
        assert "puertos_abiertos" in resumen
        assert "puertos_filtrados" in resumen
        assert "ssl_activo" in resumen
        assert "firewall_detectado" in resumen


# ============================================================
# TESTS DE INTEGRACIÓN: Simulan la ejecución completa del módulo
# ============================================================

class TestNetworkModuleIntegration:
    """Tests que simulan la ejecución completa de scanner_network.py
    usando mocks para las herramientas externas."""

    @patch('src.modules.scanner_network._run_tool', new_callable=AsyncMock)
    def test_genera_dict_valido(self, mock_run, nmap_output_normal):
        """El módulo debe devolver un diccionario bien formado sin usar un tmp JSON."""
        mock_run.side_effect = [
            (
                "Discovered open port 22/tcp on 10.202.15.100\n"
                "Discovered open port 80/tcp on 10.202.15.100\n"
                "Discovered open port 443/tcp on 10.202.15.100\n",
                "",
                0
            ),
            ("scanops.example.com\n", "", 0),
            (nmap_output_normal, "", 0)
        ]

        result = asyncio.run(scanner_network.scan())

        assert result["target"] == scanner_network.TARGET
        assert "hallazgos" in result
        assert isinstance(result["hallazgos"], list)
        assert result["resumen"]["puertos_abiertos"] == 3
        assert "inventory" in result
        assert "subfinder_domains" in result

    @patch('src.modules.scanner_network._run_tool', new_callable=AsyncMock)
    def test_nmap_falla_no_rompe(self, mock_run):
        """Si Nmap falla, el módulo no debe lanzar excepción."""
        mock_run.side_effect = [
            ("", "", 0),
            ("", "", 0),
            ("", "nmap: command not found", 1)
        ]

        result = asyncio.run(scanner_network.scan())
        assert isinstance(result, dict)
        assert "hallazgos" in result
        assert isinstance(result["hallazgos"], list)
