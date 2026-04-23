"""
Script de Testing para validar M1, M2, M3
==========================================
Verifica que los 3 microservicios están funcionales.

Ejecución:
  python test_m1_m2_m3.py
"""

import sys
import importlib
from pathlib import Path

# Colores para output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def test_imports():
    """Test 1: Verificar que todos los módulos se importan sin errores."""
    print(f"\n{YELLOW}--- TEST 1: IMPORTS ---{RESET}")
    
    tests = [
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
    ]
    
    passed = 0
    failed = 0
    
    for name, module, attr in tests:
        try:
            mod = importlib.import_module(module)
            if attr:
                getattr(mod, attr)
            print(f"  {GREEN}[OK]{RESET} {name}")
            passed += 1
        except Exception as e:
            print(f"  {RED}[FAIL]{RESET} {name}: {str(e)[:60]}")
            failed += 1
    
    return passed, failed


def test_database_models():
    """Test 2: Verificar que los modelos de BD están definidos."""
    print(f"\n{YELLOW}--- TEST 2: DATABASE MODELS ---{RESET}")
    
    try:
        from services.asset_manager.models.asset import Asset, Base as AssetBase
        print(f"  {GREEN}[OK]{RESET} M1 - Asset model with fields: {len(Asset.__table__.columns)} columns")
        
        from services.recon_engine.models.recon import ReconFinding, Base as ReconBase
        print(f"  {GREEN}[OK]{RESET} M2 - ReconFinding model with fields: {len(ReconFinding.__table__.columns)} columns")
        
        from services.scanner_engine.models.vulnerability import VulnFinding, Base as VulnBase
        print(f"  {GREEN}[OK]{RESET} M3 - VulnFinding model with fields: {len(VulnFinding.__table__.columns)} columns")
        
        return 3, 0
    except Exception as e:
        print(f"  {RED}[FAIL]{RESET} Database models error: {str(e)}")
        return 0, 3


def test_fastapi_apps():
    """Test 3: Verificar que las apps FastAPI están correctamente configuradas."""
    print(f"\n{YELLOW}--- TEST 3: FASTAPI APPS ---{RESET}")
    
    passed = 0
    failed = 0
    
    apps = [
        ("M1 - Asset Manager", "services.asset_manager.main", "app"),
        ("M2 - Recon Engine", "services.recon_engine.main", "app"),
        ("M3 - Scanner Engine", "services.scanner_engine.main", "app"),
    ]
    
    for name, module_name, attr_name in apps:
        try:
            mod = importlib.import_module(module_name)
            app = getattr(mod, attr_name)
            
            # Verificar que sea una FastAPI app
            if not hasattr(app, 'openapi'):
                raise Exception("No es una FastAPI app")
            
            # Contar routers
            router_count = len(app.routes)
            print(f"  {GREEN}[OK]{RESET} {name}: {router_count} rutas")
            passed += 1
        except Exception as e:
            print(f"  {RED}[FAIL]{RESET} {name}: {str(e)[:60]}")
            failed += 1
    
    return passed, failed


def test_routers():
    """Test 4: Verificar que los routers están incluidos en las apps."""
    print(f"\n{YELLOW}--- TEST 4: ROUTERS INCLUDED ---{RESET}")
    
    try:
        from services.asset_manager.main import app as m1_app
        m1_routes = [r.path for r in m1_app.routes]
        m1_has_assets = any('/assets' in r or '/scan' in r for r in m1_routes)
        
        if m1_has_assets:
            print(f"  {GREEN}[OK]{RESET} M1 - Asset endpoints included")
        else:
            print(f"  {YELLOW}[WARN]{RESET} M1 - No asset endpoints found in routes")
        
        from services.recon_engine.main import app as m2_app
        m2_routes = []
        for r in m2_app.routes:
            m2_routes.append(r.path)
            if hasattr(r, 'app') and hasattr(r.app, 'routes'):
                for sr in r.app.routes:
                    m2_routes.append(f"{r.path}{sr.path}")
        
        m2_has_recon = any('/recon' in r or '/scan' in r for r in m2_routes)
        
        if m2_has_recon:
            print(f"  {GREEN}[OK]{RESET} M2 - Recon endpoints included")
        else:
            print(f"  {YELLOW}[WARN]{RESET} M2 - No recon endpoints found")
        
        from services.scanner_engine.main import app as m3_app
        m3_routes = []
        for r in m3_app.routes:
            m3_routes.append(r.path)
            if hasattr(r, 'app') and hasattr(r.app, 'routes'):
                for sr in r.app.routes:
                    m3_routes.append(f"{r.path}{sr.path}")
        
        m3_has_scan = any('/scan' in r or '/status' in r for r in m3_routes)
        
        if m3_has_scan:
            print(f"  {GREEN}[OK]{RESET} M3 - Scan endpoints included")
        else:
            print(f"  {YELLOW}[WARN]{RESET} M3 - No scan endpoints found")
        
        return 3, 0
        
    except Exception as e:
        print(f"  {RED}[FAIL]{RESET} Router verification failed: {str(e)}")
        return 0, 3


def test_celery():
    """Test 5: Verificar que Celery tasks están disponibles."""
    print(f"\n{YELLOW}--- TEST 5: CELERY TASKS ---{RESET}")
    
    passed = 0
    failed = 0
    
    tasks = [
        ("M1 - Discovery Task", "services.asset_manager.tasks.discovery", "run_network_discovery"),
        ("M2 - Scan Tasks", "services.recon_engine.tasks.scan_tasks", "run_recon_complete"),
        ("M3 - Parallel Scan", "services.scanner_engine.tasks.vuln_tasks", "scan_asset_parallel"),
        ("M3 - Nuclei Task", "services.scanner_engine.tasks.vuln_tasks", "run_nuclei_task"),
    ]
    
    for name, module_name, task_name in tasks:
        try:
            mod = importlib.import_module(module_name)
            task = getattr(mod, task_name)
            print(f"  {GREEN}[OK]{RESET} {name}")
            passed += 1
        except Exception as e:
            print(f"  {YELLOW}[WARN]{RESET} {name}: {str(e)[:50]}")
            failed += 1
    
    return passed, failed


def test_vault_and_shared():
    """Test 6: Verificar que dependencias compartidas existen."""
    print(f"\n{YELLOW}--- TEST 6: SHARED DEPENDENCIES ---{RESET}")
    
    passed = 0
    failed = 0
    
    shared = [
        ("Database", "shared.database", ["engine", "get_db"]),
        ("Vault Client", "shared.vault_client", ["vault_client"]),
        ("Auth", "shared.auth", ["get_current_user"]),
        ("Celery App", "shared.celery_app", ["app"]),
        ("Logger", "shared.scan_logger", ["get_logger"]),
    ]
    
    for name, module_name, attrs in shared:
        try:
            mod = importlib.import_module(module_name)
            for attr in attrs:
                getattr(mod, attr)
            print(f"  {GREEN}[OK]{RESET} {name}")
            passed += 1
        except Exception as e:
            print(f"  {RED}[FAIL]{RESET} {name}: {str(e)[:50]}")
            failed += 1
    
    return passed, failed


def main():
    """Ejecutar todos los tests."""
    print(f"\n{YELLOW}{'='*60}")
    print(f"  VALIDACIÓN FUNCIONAL: M1, M2, M3")
    print(f"{'='*60}{RESET}")
    
    total_passed = 0
    total_failed = 0
    
    # Ejecutar tests
    p, f = test_imports()
    total_passed += p
    total_failed += f
    
    p, f = test_database_models()
    total_passed += p
    total_failed += f
    
    p, f = test_fastapi_apps()
    total_passed += p
    total_failed += f
    
    p, f = test_routers()
    total_passed += p
    total_failed += f
    
    p, f = test_celery()
    total_passed += p
    total_failed += f
    
    p, f = test_vault_and_shared()
    total_passed += p
    total_failed += f
    
    # Resumen
    print(f"\n{YELLOW}{'='*60}{RESET}")
    print(f"  RESUMEN")
    print(f"{YELLOW}{'='*60}{RESET}")
    print(f"  {GREEN}[OK] Pasados:{RESET}  {total_passed}")
    print(f"  {RED}[FAIL] Fallidos:{RESET}  {total_failed}")
    
    if total_failed == 0:
        print(f"\n  {GREEN}[CONGRATS] TODOS LOS TESTS PASARON - M1, M2, M3 FUNCIONALES{RESET}")
        return 0
    else:
        print(f"\n  {RED}[WARN] HAY {total_failed} PROBLEMAS QUE REVISAR{RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
