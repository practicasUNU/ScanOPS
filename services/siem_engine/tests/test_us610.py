"""
US-6.10 — Alertas Telegram + Email
Run: pytest services/siem_engine/tests/test_us610.py -v
"""
import os
import pytest
import httpx

M5_BASE = os.getenv("M5_URL", "http://localhost:8006")


# ---------------------------------------------------------------------------

def test_alert_config_endpoint():
    """GET /siem/alert-config devuelve 200 con campos telegram y email."""
    r = httpx.get(f"{M5_BASE}/siem/alert-config", timeout=10)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert "telegram" in body, f"Falta campo 'telegram': {body}"
    assert "email" in body, f"Falta campo 'email': {body}"
    assert isinstance(body["telegram"], bool)
    assert isinstance(body["email"], bool)


def test_test_alert_endpoint():
    """POST /siem/test-alert devuelve 200 aunque canales estén vacíos."""
    r = httpx.post(f"{M5_BASE}/siem/test-alert", timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("sent") is True


def test_send_alert_no_crash():
    """send_alert({}) con tokens vacíos no lanza excepción."""
    # Importamos directamente para test unitario
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
    os.environ.setdefault("TELEGRAM_BOT_TOKEN", "")
    os.environ.setdefault("SMTP_USER", "")

    from services.siem_engine.alerting import send_alert
    try:
        send_alert({})
        send_alert({"severity": "TEST", "description": "unit test", "ip": "1.1.1.1"})
    except Exception as e:
        pytest.fail(f"send_alert lanzó excepción: {e}")


def test_telegram_skip_if_no_token():
    """Si TELEGRAM_BOT_TOKEN vacío, función retorna sin error."""
    os.environ["TELEGRAM_BOT_TOKEN"] = ""
    os.environ["TELEGRAM_CHAT_ID"] = ""
    from services.siem_engine.alerting import send_telegram
    try:
        send_telegram("test message")
    except Exception as e:
        pytest.fail(f"send_telegram lanzó excepción con token vacío: {e}")


def test_email_skip_if_no_config():
    """Si SMTP_USER vacío, función retorna sin error."""
    os.environ["SMTP_USER"] = ""
    os.environ["SMTP_PASSWORD"] = ""
    from services.siem_engine.alerting import send_email
    try:
        send_email("Test subject", "Test body")
    except Exception as e:
        pytest.fail(f"send_email lanzó excepción con config vacía: {e}")
