"""
Tests para scanner_hardening.py — Módulo de bastionado
=======================================================
Verifican la lógica de cada check de hardening sin conexión SSH.

Ejecutar: pytest tests/test_scanner_hardening.py -v
"""
import pytest
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils import evaluar_root_bloqueado, evaluar_ufw, evaluar_ssh_root_login, evaluar_parches, evaluar_cifrado_disco, calcular_compliance


# ============================================================
# TESTS: Root bloqueado
# ============================================================

class TestRootBloqueado:
    def test_root_bloqueado_es_seguro(self):
        result = evaluar_root_bloqueado("L")
        assert result["estado"] == "SEGURO"
        assert result["severidad"] == "INFO"
        assert result["remediacion"] is None

    def test_root_no_bloqueado_es_critico(self):
        result = evaluar_root_bloqueado("P")
        assert result["estado"] == "RIESGO"
        assert result["severidad"] == "CRITICA"
        assert result["remediacion"] == "sudo passwd -l root"

    def test_root_sin_password_tambien_riesgo(self):
        """Si el estado es NP (no password), también es riesgo."""
        result = evaluar_root_bloqueado("NP")
        assert result["estado"] == "RIESGO"


# ============================================================
# TESTS: UFW Firewall
# ============================================================

class TestUFW:
    def test_ufw_activo(self):
        result = evaluar_ufw("Status: active")
        assert result["estado"] == "ACTIVO"
        assert result["severidad"] == "INFO"

    def test_ufw_inactivo(self):
        result = evaluar_ufw("Status: inactive")
        assert result["estado"] == "INACTIVO"
        assert result["severidad"] == "CRITICA"
        assert result["remediacion"] == "sudo ufw enable"

    def test_ufw_salida_vacia(self):
        """Si no se puede leer el estado, se asume inactivo."""
        result = evaluar_ufw("")
        assert result["estado"] == "INACTIVO"


# ============================================================
# TESTS: SSH PermitRootLogin
# ============================================================

class TestSSHRootLogin:
    def test_root_login_no_es_seguro(self):
        result = evaluar_ssh_root_login("no")
        assert result["estado"] == "SEGURO"
        assert result["severidad"] == "INFO"

    def test_root_login_yes_es_riesgo(self):
        result = evaluar_ssh_root_login("yes")
        assert result["estado"] == "RIESGO"
        assert result["severidad"] == "ALTA"

    def test_root_login_prohibit_password_es_riesgo(self):
        """prohibit-password no es 'no', así que es riesgo."""
        result = evaluar_ssh_root_login("prohibit-password")
        assert result["estado"] == "RIESGO"

    def test_root_login_vacio_es_riesgo(self):
        result = evaluar_ssh_root_login("")
        assert result["estado"] == "RIESGO"


# ============================================================
# TESTS: Parches pendientes
# ============================================================

class TestParches:
    def test_sin_parches_es_ok(self):
        result = evaluar_parches(0)
        assert result["severidad"] == "INFO"
        assert result["remediacion"] is None

    def test_con_parches_es_alta(self):
        result = evaluar_parches(12)
        assert result["severidad"] == "ALTA"
        assert result["remediacion"] is not None

    def test_un_parche_es_alta(self):
        result = evaluar_parches(1)
        assert result["severidad"] == "ALTA"


# ============================================================
# TESTS: Cifrado de disco
# ============================================================

class TestCifradoDisco:
    def test_luks_activo(self):
        result = evaluar_cifrado_disco("sda1  crypto_LUKS  \nsda2  ext4  /")
        assert result["estado"] == "ACTIVO"
        assert result["severidad"] == "INFO"

    def test_sin_cifrado(self):
        result = evaluar_cifrado_disco("sda1  ext4  /\nsda2  swap  [SWAP]")
        assert result["estado"] == "AUSENTE"
        assert result["severidad"] == "CRITICA"


# ============================================================
# TESTS: Compliance resumen
# ============================================================

class TestComplianceResumen:
    def test_todo_ok_cumple(self):
        hallazgos = [
            {"severidad": "INFO"},
            {"severidad": "INFO"},
            {"severidad": "INFO"},
        ]
        result = calcular_compliance(hallazgos)
        assert result["cumple_ens"] is True
        assert result["checks_riesgo"] == 0

    def test_un_fallo_no_cumple(self):
        hallazgos = [
            {"severidad": "INFO"},
            {"severidad": "CRITICA"},
            {"severidad": "INFO"},
        ]
        result = calcular_compliance(hallazgos)
        assert result["cumple_ens"] is False
        assert result["checks_riesgo"] == 1

    def test_multiples_fallos(self):
        hallazgos = [
            {"severidad": "CRITICA"},
            {"severidad": "ALTA"},
            {"severidad": "INFO"},
            {"severidad": "ALTA"},
        ]
        result = calcular_compliance(hallazgos)
        assert result["checks_total"] == 4
        assert result["checks_ok"] == 1
        assert result["checks_riesgo"] == 3


# ============================================================
# TESTS: Estructura JSON completa del módulo
# ============================================================

class TestHardeningJsonStructure:
    def test_hallazgo_tiene_campos_ens(self):
        """Cada hallazgo de hardening DEBE tener medida_ens y remediacion."""
        hallazgo = evaluar_root_bloqueado("P")
        assert "medida_ens" in hallazgo
        assert "remediacion" in hallazgo
        assert "severidad" in hallazgo
        assert "estado" in hallazgo

    def test_todos_los_checks_tienen_medida_ens(self):
        """Verificar que ningún check se quede sin mapeo ENS."""
        checks = [
            evaluar_root_bloqueado("L"),
            evaluar_ufw("Status: active"),
            evaluar_ssh_root_login("no"),
            evaluar_parches(0),
            evaluar_cifrado_disco("sda crypt"),
        ]
        for check in checks:
            assert "medida_ens" in check
            assert check["medida_ens"] != ""
