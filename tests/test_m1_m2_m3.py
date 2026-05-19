"""
Tests de validación funcional para M1, M2, M3.

Verifica que los 3 microservicios están correctamente estructurados.
"""

import importlib

import pytest


@pytest.mark.parametrize("name,module,attr", [
    ("M1 - Asset Manager Main", "services.asset_manager.main", "app"),
    ("M1 - Asset Model", "services.asset_manager.models.asset", "Asset"),
    ("M1 - Asset Router", "services.asset_manager.api.router", "router"),
    ("M1 - Asset Service", "services.asset_manager.services.asset_service", None),
    ("M2 - Recon Engine Main", "services.recon_engine.main", "app"),
    ("M2 - Recon Model", "services.recon_engine.models.recon", "ReconFinding"),
    ("M2 - Recon API", "services.recon_engine.api.recon_api", "router"),
    ("M2 - Scanner Network", "services.recon_engine.services.scanner_network", None),
    ("M3 - Scanner Engine Main", "services.scanner_engine.main", "app"),
    ("M3 - Scan Endpoints", "services.scanner_engine.endpoints.scan", "router"),
    ("M3 - OpenVAS Client", "services.scanner_engine.clients.openvas_client", "OpenVASClient"),
    ("M3 - Nuclei Client", "services.scanner_engine.clients.nuclei_client", "NucleiClient"),
    ("M3 - ZAP Client", "services.scanner_engine.clients.zap_client", "ZAPClient"),
    ("M3 - Vulnerability Model", "services.scanner_engine.models.vulnerability", "VulnFinding"),
])
def test_imports(name, module, attr):
    """Test 1: Verificar que todos los módulos se importan sin errores."""
    mod = importlib.import_module(module)
    if attr:
        assert hasattr(mod, attr), f"{name}: atributo '{attr}' no encontrado en {module}"


def test_database_models():
    """Test 2: Verificar que los modelos de BD están definidos."""
    from services.asset_manager.models.asset import Asset
    assert len(Asset.__table__.columns) > 0

    from services.recon_engine.models.recon import ReconFinding
    assert len(ReconFinding.__table__.columns) > 0

    from services.scanner_engine.models.vulnerability import VulnFinding
    assert len(VulnFinding.__table__.columns) > 0


@pytest.mark.parametrize("name,module_name,attr_name", [
    ("M1 - Asset Manager", "services.asset_manager.main", "app"),
    ("M2 - Recon Engine", "services.recon_engine.main", "app"),
    ("M3 - Scanner Engine", "services.scanner_engine.main", "app"),
])
def test_fastapi_apps(name, module_name, attr_name):
    """Test 3: Verificar que las apps FastAPI están correctamente configuradas."""
    mod = importlib.import_module(module_name)
    app = getattr(mod, attr_name)
    assert hasattr(app, "openapi"), f"{name}: el objeto no es una FastAPI app"
    assert len(app.routes) > 0, f"{name}: la app no tiene rutas registradas"


def test_routers_m1():
    """Test 4a: Verificar que M1 incluye rutas de assets."""
    from services.asset_manager.main import app as m1_app
    routes = [r.path for r in m1_app.routes]
    assert any("/assets" in r or "/scan" in r for r in routes), \
        f"M1 - No asset/scan endpoints found. Routes: {routes}"


def test_routers_m2():
    """Test 4b: Verificar que M2 incluye rutas de recon."""
    from services.recon_engine.main import app as m2_app
    all_routes = []
    for r in m2_app.routes:
        all_routes.append(r.path)
        if hasattr(r, "app") and hasattr(r.app, "routes"):
            for sr in r.app.routes:
                all_routes.append(f"{r.path}{sr.path}")
    assert any("/recon" in r or "/scan" in r for r in all_routes), \
        f"M2 - No recon/scan endpoints found. Routes: {all_routes}"


def test_routers_m3():
    """Test 4c: Verificar que M3 incluye rutas de scan."""
    from services.scanner_engine.main import app as m3_app
    all_routes = []
    for r in m3_app.routes:
        all_routes.append(r.path)
        if hasattr(r, "app") and hasattr(r.app, "routes"):
            for sr in r.app.routes:
                all_routes.append(f"{r.path}{sr.path}")
    assert any("/scan" in r or "/status" in r for r in all_routes), \
        f"M3 - No scan/status endpoints found. Routes: {all_routes}"


@pytest.mark.integration
@pytest.mark.parametrize("name,module_name,task_name", [
    ("M1 - Discovery Task", "services.asset_manager.tasks.discovery", "run_network_discovery"),
    ("M2 - Scan Tasks", "services.recon_engine.tasks.scan_tasks", "run_recon_complete"),
    ("M3 - Parallel Scan", "services.scanner_engine.tasks.vuln_tasks", "scan_asset_parallel"),
    ("M3 - Nuclei Task", "services.scanner_engine.tasks.vuln_tasks", "run_nuclei_task"),
])
def test_celery(name, module_name, task_name):
    """Test 5: Verificar que Celery tasks están disponibles (requiere Redis)."""
    mod = importlib.import_module(module_name)
    assert hasattr(mod, task_name), f"{name}: tarea '{task_name}' no encontrada en {module_name}"


@pytest.mark.integration
@pytest.mark.parametrize("name,module_name,attrs", [
    ("Database", "shared.database", ["engine", "get_db"]),
    ("Vault Client", "shared.vault_client", ["vault_client"]),
    ("Auth", "shared.auth", ["get_current_user"]),
    ("Celery App", "shared.celery_app", ["app"]),
    ("Logger", "shared.scan_logger", ["get_logger"]),
])
def test_vault_and_shared(name, module_name, attrs):
    """Test 6: Verificar que dependencias compartidas existen (puede requerir servicios)."""
    mod = importlib.import_module(module_name)
    for attr in attrs:
        assert hasattr(mod, attr), f"{name}: atributo '{attr}' no encontrado en {module_name}"
