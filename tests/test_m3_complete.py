import pytest

def test_celery_configured():
    """Celery + colas OK"""
    from shared.celery_app import app as celery_app
    assert celery_app.conf.task_queues is not None
    print(f"✓ {len(celery_app.tasks)} tasks en Celery")

def test_vuln_tasks_importable():
    """vuln_tasks module existe e importa"""
    from services.scanner_engine.tasks import vuln_tasks
    assert hasattr(vuln_tasks, 'run_nuclei_task')
    print("✓ run_nuclei_task function existe")

def test_openvast_client_exists():
    """OpenVAS client importable"""
    try:
        from services.scanner_engine.clients.openvast_client import OpenVastScanner
        assert OpenVastScanner is not None
        print("✓ OpenVastScanner importada")
    except (ImportError, ModuleNotFoundError):
        pytest.skip("OpenVAS lib no instalada")

def test_zap_client_exists():
    """ZAP client importable"""
    try:
        from services.scanner_engine.clients.zap_client import ZAPScanner
        assert ZAPScanner is not None
        print("✓ ZAPScanner importada")
    except (ImportError, ModuleNotFoundError):
        pytest.skip("ZAP lib no instalada")
