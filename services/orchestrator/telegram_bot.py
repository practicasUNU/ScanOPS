"""
Proceso independiente de polling del bot de Telegram para ScanOPS.
Ejecutar: python telegram_bot.py
Comandos: /ayuda, /estado, /parar, /reanudar, /pausar
"""
import asyncio
import logging
import os
import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [BOT] %(message)s")
logger = logging.getLogger("telegram_bot")

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = str(os.getenv("TELEGRAM_CHAT_ID", ""))
PLATFORM_URL = os.getenv("PLATFORM_URL", "")
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_INTERNAL_URL", "http://localhost:8009")


def platform_buttons() -> list | None:
    if PLATFORM_URL and "localhost" not in PLATFORM_URL:
        return [{"text": "📊 Dashboard", "url": f"{PLATFORM_URL}/dashboard"}]
    return None


async def reply(client: httpx.AsyncClient, chat_id: str, text: str, buttons: list | None = None) -> None:
    payload: dict = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if buttons:
        payload["reply_markup"] = {"inline_keyboard": [buttons]}
    try:
        await client.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage", json=payload, timeout=10)
    except Exception as e:
        logger.warning(f"Error enviando mensaje: {e}")


async def get_system_status(client: httpx.AsyncClient) -> str:
    try:
        r = await client.get(f"{ORCHESTRATOR_URL}/orchestrator/modules/health", timeout=8)
        data = r.json()
        modules = data.get("modules", {})
        lines = ["📊 <b>Estado de módulos</b>\n"]
        for mod, state in modules.items():
            icon = "🟢" if state == "online" else "🔴"
            lines.append(f"{icon} {mod.upper()} — {state}")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Error obteniendo estado: {e}"


async def activate_kill_switch(client: httpx.AsyncClient) -> bool:
    try:
        r = await client.post(f"{ORCHESTRATOR_URL}/orchestrator/cycle/kill-switch",
                              params={"totp_code": "000000"}, timeout=8)
        return r.status_code == 200
    except Exception:
        return False


async def deactivate_kill_switch(client: httpx.AsyncClient) -> bool:
    try:
        r = await client.post(f"{ORCHESTRATOR_URL}/orchestrator/cycle/kill-switch/deactivate", timeout=8)
        return r.status_code == 200
    except Exception:
        return False


async def toggle_pause(client: httpx.AsyncClient) -> str:
    try:
        r = await client.post(f"{ORCHESTRATOR_URL}/orchestrator/cycle/pause", timeout=8)
        paused = r.json().get("paused", False)
        return "pausado ⏸️" if paused else "activo ▶️"
    except Exception:
        return "error"


async def handle_command(client: httpx.AsyncClient, chat_id: str, text: str) -> None:
    btns = platform_buttons()
    cmd = text.lower().strip().split("@")[0]

    if cmd in ("/ayuda", "/help", "/start"):
        await reply(client, chat_id,
            "🤖 <b>ScanOPS Bot — Comandos disponibles</b>\n\n"
            "/estado — Estado del sistema y módulos\n"
            "/parar — Activar Kill Switch (detener ciclo)\n"
            "/reanudar — Desactivar Kill Switch\n"
            "/pausar — Pausar/reanudar el ciclo\n"
            "/ayuda — Mostrar este mensaje"
        )

    elif cmd == "/estado":
        status_text = await get_system_status(client)
        await reply(client, chat_id, status_text, btns)

    elif cmd == "/parar":
        ok = await activate_kill_switch(client)
        if ok:
            await reply(client, chat_id,
                "🛑 <b>Kill Switch activado</b>\n\nCiclo detenido. Usa /reanudar para activarlo.",
                btns)
        else:
            await reply(client, chat_id, "❌ Error activando Kill Switch. Comprueba los logs.")

    elif cmd == "/reanudar":
        ok = await deactivate_kill_switch(client)
        if ok:
            await reply(client, chat_id,
                "✅ <b>Kill Switch desactivado</b>\n\nEl sistema puede volver a ejecutar exploits.",
                btns)
        else:
            await reply(client, chat_id, "❌ Error desactivando Kill Switch.")

    elif cmd == "/pausar":
        estado = await toggle_pause(client)
        await reply(client, chat_id, f"🔄 Ciclo ahora: <b>{estado}</b>")

    else:
        await reply(client, chat_id, "❓ Comando no reconocido. Usa /ayuda.")


async def poll_loop() -> None:
    if not TOKEN or not CHAT_ID:
        logger.error("TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID no configurados — bot detenido")
        return

    offset = 0
    logger.info(f"Bot iniciado. Escuchando chat {CHAT_ID}...")

    async with httpx.AsyncClient(timeout=15) as client:
        # Eliminar webhook si existía
        await client.post(f"https://api.telegram.org/bot{TOKEN}/deleteWebhook",
                          json={"drop_pending_updates": False})
        logger.info("Webhook eliminado, modo polling activo")

        while True:
            try:
                r = await client.get(
                    f"https://api.telegram.org/bot{TOKEN}/getUpdates",
                    params={"offset": offset, "timeout": 5, "allowed_updates": ["message"]},
                )
                if r.status_code != 200:
                    await asyncio.sleep(5)
                    continue

                for update in r.json().get("result", []):
                    offset = update["update_id"] + 1
                    msg = update.get("message", {})
                    chat_id = str(msg.get("chat", {}).get("id", ""))
                    text = (msg.get("text") or "").strip()

                    if not text or chat_id != CHAT_ID:
                        continue

                    logger.info(f"Comando recibido: '{text}' de chat {chat_id}")
                    await handle_command(client, chat_id, text)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Error en poll loop: {e}")
                await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(poll_loop())
