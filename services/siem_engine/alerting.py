"""
US-6.10 — Alertas Telegram + Email
ENS: op.exp.7

Uso: send_alert(alert_dict) — silencioso si canales no configurados.
"""
import os
import smtplib
import ssl
import urllib.request
import urllib.parse
import json
from datetime import datetime
from fastapi import APIRouter
from shared.scan_logger import ScanLogger

logger = ScanLogger("siem_engine.alerting")
router = APIRouter(tags=["US-6.10 Alerting"])

# --- Variables de entorno ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")
GRAYLOG_URL = os.getenv("GRAYLOG_API_URL", "http://localhost:9000")


def _telegram_configured() -> bool:
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def _email_configured() -> bool:
    return bool(SMTP_USER and SMTP_PASSWORD and ALERT_EMAIL_TO)


def send_telegram(message: str) -> None:
    if not _telegram_configured():
        return
    try:
        payload = json.dumps({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML",
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(f"[Telegram] Alerta enviada, status={resp.status}")
    except Exception as e:
        logger.warning(f"[Telegram] Error al enviar alerta: {e}")


def send_email(subject: str, body: str) -> None:
    if not _email_configured():
        return
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as srv:
            srv.ehlo()
            srv.starttls(context=ctx)
            srv.login(SMTP_USER, SMTP_PASSWORD)
            msg = f"Subject: {subject}\nFrom: {SMTP_USER}\nTo: {ALERT_EMAIL_TO}\n\n{body}"
            srv.sendmail(SMTP_USER, ALERT_EMAIL_TO, msg)
        logger.info(f"[Email] Alerta enviada a {ALERT_EMAIL_TO}")
    except Exception as e:
        logger.warning(f"[Email] Error al enviar alerta: {e}")


def send_alert(alert: dict) -> None:
    """Orquesta Telegram + Email. Silencioso si no configurados."""
    severity = alert.get("severity", "INFO")
    description = alert.get("description", "Alerta ScanOPS")
    timestamp = alert.get("timestamp", datetime.utcnow().isoformat())
    ip = alert.get("ip", "")
    graylog_link = f"{GRAYLOG_URL}/search"

    tg_msg = (
        f"🚨 <b>ScanOPS Alert [{severity}]</b>\n"
        f"<b>Descripción:</b> {description}\n"
        f"<b>IP:</b> {ip or 'N/A'}\n"
        f"<b>Timestamp:</b> {timestamp}\n"
        f"<b>Graylog:</b> <a href='{graylog_link}'>Ver logs</a>"
    )

    email_body = (
        f"ScanOPS Alert [{severity}]\n"
        f"Descripción: {description}\n"
        f"IP: {ip or 'N/A'}\n"
        f"Timestamp: {timestamp}\n"
        f"Graylog: {graylog_link}\n"
    )

    send_telegram(tg_msg)
    send_email(f"[ScanOPS {severity}] {description[:80]}", email_body)


# --- Endpoints REST ---

@router.post("/siem/test-alert")
async def test_alert():
    """Envía alerta de prueba a todos los canales configurados."""
    import asyncio
    await asyncio.to_thread(send_alert, {
        "severity": "TEST",
        "description": "Alerta de prueba ScanOPS — ENS op.exp.7",
        "ip": "0.0.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    })
    return {
        "sent": True,
        "channels": {
            "telegram": _telegram_configured(),
            "email": _email_configured(),
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/siem/alert-config")
async def alert_config():
    """Devuelve qué canales están configurados (sin exponer tokens)."""
    return {
        "telegram": _telegram_configured(),
        "email": _email_configured(),
        "smtp_host": SMTP_HOST if _email_configured() else None,
        "graylog": GRAYLOG_URL,
    }
