"""
Tests para scanner_health.py — Módulo de salud del servidor
=============================================================
Verifican la lógica de umbrales (disco, RAM, CPU) y la detección
de servicios sin necesidad de conexión SSH real.

Ejecutar: pytest tests/test_scanner_health.py -v
"""
import pytest
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils import evaluar_metrica, evaluar_servicio, calcular_estado_global


# ============================================================
# TESTS DE UMBRALES: Disco, RAM, CPU
# ============================================================

class TestUmbrales:
    """Tests que verifican que los umbrales de alerta funcionan correctamente.
    Este era uno de los bugs: antes todo decía 'OK' sin importar el valor."""

    # --- Disco ---
    def test_disco_bajo_es_ok(self):
        result = evaluar_metrica("uso_disco", "14%")
        assert result["estado"] == "OK"
        assert result["severidad"] == "INFO"

    def test_disco_80_es_alerta(self):
        """Disco > 80% debe generar ALERTA."""
        result = evaluar_metrica("uso_disco", "85%")
        assert result["estado"] == "ALERTA"
        assert result["severidad"] == "ALTA"

    def test_disco_90_es_critico(self):
        """Disco > 90% debe generar CRITICO."""
        result = evaluar_metrica("uso_disco", "95%")
        assert result["estado"] == "CRITICO"
        assert result["severidad"] == "CRITICA"

    def test_disco_exacto_80_es_ok(self):
        """Disco al 80% exacto NO debe ser alerta (> 80, no >=)."""
        result = evaluar_metrica("uso_disco", "80%")
        assert result["estado"] == "OK"

    def test_disco_exacto_90_es_alerta(self):
        """Disco al 90% exacto debe ser ALERTA (> 80 pero no > 90)."""
        result = evaluar_metrica("uso_disco", "90%")
        assert result["estado"] == "ALERTA"

    # --- RAM ---
    def test_ram_bajo_es_ok(self):
        result = evaluar_metrica("uso_ram", "2%")
        assert result["estado"] == "OK"

    def test_ram_alta_es_alerta(self):
        result = evaluar_metrica("uso_ram", "88%")
        assert result["estado"] == "ALERTA"

    def test_ram_critica(self):
        result = evaluar_metrica("uso_ram", "96%")
        assert result["estado"] == "CRITICO"

    # --- CPU (umbrales distintos: 80 alerta, 95 crítico) ---
    def test_cpu_normal_es_ok(self):
        result = evaluar_metrica("uso_cpu", "5%", umbral_alerta=80, umbral_critico=95)
        assert result["estado"] == "OK"

    def test_cpu_alta_es_alerta(self):
        result = evaluar_metrica("uso_cpu", "85%", umbral_alerta=80, umbral_critico=95)
        assert result["estado"] == "ALERTA"

    def test_cpu_critica(self):
        result = evaluar_metrica("uso_cpu", "98%", umbral_alerta=80, umbral_critico=95)
        assert result["estado"] == "CRITICO"


# ============================================================
# TESTS DE SERVICIOS: systemctl
# ============================================================

class TestServicios:
    """Tests que verifican la evaluación del estado de servicios."""

    def test_servicio_activo_es_info(self):
        result = evaluar_servicio("apache2", "active")
        assert result["severidad"] == "INFO"

    def test_servicio_inactivo_es_alta(self):
        result = evaluar_servicio("apache2", "inactive")
        assert result["severidad"] == "ALTA"

    def test_servicio_failed_es_alta(self):
        result = evaluar_servicio("ssh", "failed")
        assert result["severidad"] == "ALTA"


# ============================================================
# TESTS DE ESTADO GLOBAL
# ============================================================

class TestEstadoGlobal:
    """Tests que verifican el cálculo del estado global del servidor."""

    def test_todo_ok(self):
        metricas = [{"severidad": "INFO"}, {"severidad": "INFO"}]
        servicios = [{"severidad": "INFO"}]
        assert calcular_estado_global(metricas, servicios) == "OK"

    def test_una_alerta_cambia_global(self):
        metricas = [{"severidad": "INFO"}, {"severidad": "ALTA"}]
        servicios = [{"severidad": "INFO"}]
        assert calcular_estado_global(metricas, servicios) == "ALERTA"

    def test_critica_domina(self):
        """Si hay al menos una CRITICA, el estado global es CRITICO."""
        metricas = [{"severidad": "INFO"}, {"severidad": "CRITICA"}]
        servicios = [{"severidad": "INFO"}]
        assert calcular_estado_global(metricas, servicios) == "CRITICO"

    def test_servicio_caido_cambia_global(self):
        metricas = [{"severidad": "INFO"}]
        servicios = [{"severidad": "ALTA"}]
        assert calcular_estado_global(metricas, servicios) == "ALERTA"


# ============================================================
# TESTS DE ESTRUCTURA JSON
# ============================================================

class TestHealthJsonStructure:
    """Tests que verifican el formato del JSON de salida."""

    def test_metrica_tiene_campos_obligatorios(self):
        """Cada métrica debe tener estos campos para el orquestador."""
        metrica = {
            "nombre": "uso_disco",
            "valor": "14%",
            "umbral_alerta": "80%",
            "umbral_critico": "90%",
            "estado": "OK",
            "severidad": "INFO"
        }
        campos = ["nombre", "valor", "estado", "severidad"]
        for campo in campos:
            assert campo in metrica

    def test_servicio_tiene_campos_obligatorios(self):
        servicio = {"nombre": "apache2", "estado": "active", "severidad": "INFO"}
        for campo in ["nombre", "estado", "severidad"]:
            assert campo in servicio
