"""
Tests para main_orchestrator.py — Fusión de reportes
=====================================================
Verifican que el orquestador fusiona correctamente los JSON
de los 3 módulos y calcula el compliance global.

Ejecutar: pytest tests/test_orchestrator.py -v
"""
import pytest
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# FIXTURES: JSONs de ejemplo de cada módulo
# ============================================================

@pytest.fixture
def network_data():
    return {
        "timestamp": "2026-04-20T10:25:00",
        "target": "10.202.15.100",
        "hallazgos": [
            {"puerto": "22/tcp", "servicio": "ssh", "estado": "Abierto",
             "severidad": "INFO", "medida_ens": "op.acc.1"},
            {"puerto": "80/tcp", "servicio": "http", "estado": "Abierto",
             "severidad": "INFO", "medida_ens": "op.exp.2"},
        ],
        "resumen": {"puertos_abiertos": 2, "ssl_activo": True}
    }


@pytest.fixture
def health_data():
    return {
        "timestamp": "2026-04-20T10:25:00",
        "target": "10.202.15.100",
        "metricas": [
            {"nombre": "uso_disco", "valor": "14%", "estado": "OK", "severidad": "INFO"},
            {"nombre": "uso_ram", "valor": "2%", "estado": "OK", "severidad": "INFO"},
        ],
        "servicios": [
            {"nombre": "apache2", "estado": "active", "severidad": "INFO"},
            {"nombre": "ssh", "estado": "active", "severidad": "INFO"},
        ],
        "estado_global": "OK"
    }


@pytest.fixture
def hardening_data_con_fallo():
    return {
        "timestamp": "2026-04-20T10:25:00",
        "target": "10.202.15.100",
        "hallazgos": [
            {"check": "root_bloqueado", "estado": "RIESGO",
             "severidad": "CRITICA", "medida_ens": "op.acc.6",
             "detalle": "El usuario root NO está bloqueado"},
            {"check": "ufw_activo", "estado": "ACTIVO",
             "severidad": "INFO", "medida_ens": "op.exp.4",
             "detalle": "Firewall activo"},
        ]
    }


@pytest.fixture
def hardening_data_ok():
    return {
        "timestamp": "2026-04-20T10:25:00",
        "target": "10.202.15.100",
        "hallazgos": [
            {"check": "root_bloqueado", "estado": "SEGURO",
             "severidad": "INFO", "medida_ens": "op.acc.6"},
            {"check": "ufw_activo", "estado": "ACTIVO",
             "severidad": "INFO", "medida_ens": "op.exp.4"},
        ]
    }


from src.utils import merge_reports


# ============================================================
# TESTS: Alertas críticas
# ============================================================

class TestAlertasCriticas:
    def test_detecta_alerta_critica_hardening(self, network_data, health_data, hardening_data_con_fallo):
        data = {"network": network_data, "health": health_data, "hardening": hardening_data_con_fallo}
        result = merge_reports(data)
        assert len(result["alertas_criticas"]) == 1
        assert result["alertas_criticas"][0]["origen"] == "hardening"
        assert result["alertas_criticas"][0]["check"] == "root_bloqueado"

    def test_sin_alertas_criticas(self, network_data, health_data, hardening_data_ok):
        data = {"network": network_data, "health": health_data, "hardening": hardening_data_ok}
        result = merge_reports(data)
        assert len(result["alertas_criticas"]) == 0

    def test_alerta_incluye_medida_ens(self, network_data, health_data, hardening_data_con_fallo):
        data = {"network": network_data, "health": health_data, "hardening": hardening_data_con_fallo}
        result = merge_reports(data)
        for alerta in result["alertas_criticas"]:
            assert "medida_ens" in alerta
            assert alerta["medida_ens"] != ""


# ============================================================
# TESTS: Compliance global
# ============================================================

class TestComplianceGlobal:
    def test_no_cumple_con_fallo(self, network_data, health_data, hardening_data_con_fallo):
        data = {"network": network_data, "health": health_data, "hardening": hardening_data_con_fallo}
        result = merge_reports(data)
        assert result["compliance_global"]["estado"] == "NO CUMPLE"
        assert result["compliance_global"]["checks_riesgo"] > 0

    def test_cumple_sin_fallos(self, network_data, health_data, hardening_data_ok):
        data = {"network": network_data, "health": health_data, "hardening": hardening_data_ok}
        result = merge_reports(data)
        assert result["compliance_global"]["estado"] == "CUMPLE"
        assert result["compliance_global"]["checks_riesgo"] == 0

    def test_cuenta_checks_correctamente(self, network_data, health_data, hardening_data_ok):
        """2 network + 2 health metricas + 2 health servicios + 2 hardening = 8."""
        data = {"network": network_data, "health": health_data, "hardening": hardening_data_ok}
        result = merge_reports(data)
        assert result["compliance_global"]["checks_total"] == 8

    def test_modulo_faltante_no_rompe(self, network_data, health_data):
        """Si hardening no generó resultados, la fusión no debe fallar."""
        data = {
            "network": network_data,
            "health": health_data,
            "hardening": {"error": "Módulo no generó resultados"}
        }
        result = merge_reports(data)
        # No debe lanzar excepción y debe contar solo los checks disponibles
        assert result["compliance_global"]["checks_total"] == 6


# ============================================================
# TESTS: Estructura del master report
# ============================================================

class TestMasterReportStructure:
    def test_campos_obligatorios(self, network_data, health_data, hardening_data_ok):
        data = {"network": network_data, "health": health_data, "hardening": hardening_data_ok}
        result = merge_reports(data)
        assert "alertas_criticas" in result
        assert "compliance_global" in result
        assert "estado" in result["compliance_global"]
        assert "checks_total" in result["compliance_global"]
        assert "checks_ok" in result["compliance_global"]
        assert "checks_riesgo" in result["compliance_global"]

    def test_compliance_global_valores_coherentes(self, network_data, health_data, hardening_data_con_fallo):
        data = {"network": network_data, "health": health_data, "hardening": hardening_data_con_fallo}
        result = merge_reports(data)
        cg = result["compliance_global"]
        assert cg["checks_total"] == cg["checks_ok"] + cg["checks_riesgo"]
