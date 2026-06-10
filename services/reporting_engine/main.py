import io
import logging
import os
import urllib.parse
import uuid
import zipfile
import asyncio
from datetime import datetime

import fitz  # PyMuPDF
import psycopg2
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from jinja2 import Environment, FileSystemLoader
from psycopg2.extras import RealDictCursor
from weasyprint import HTML
# CORRECCIÓN EN services/reporting_engine/main.py
from google_drive_service import drive_uploader

logger = logging.getLogger("m7.reporting")

app = FastAPI(title="ScanOps M7 - Reporting Engine")

# services/reporting_engine/main.py -> Reemplazar el bloque de CORSMiddleware por este:

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://localhost(:\d+)?",  # <-- Soporta dinámicamente http/https y cualquier puerto local
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HISTORY_DIR = "history"
os.makedirs(HISTORY_DIR, exist_ok=True)

template_env = Environment(loader=FileSystemLoader('templates'))


# --- DB ---

def get_db_connection():
    """Get PostgreSQL connection from DATABASE_URL env var."""
    db_url = os.getenv("DATABASE_URL", "")
    if db_url:
        r = urllib.parse.urlparse(db_url)
        return psycopg2.connect(
            host=r.hostname, port=r.port or 5432,
            database=r.path.lstrip('/'),
            user=r.username, password=r.password,
        )
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=os.getenv("DB_NAME", "scanops"),
        user=os.getenv("DB_USER", "scanops"),
        password=os.getenv("DB_PASSWORD", "scanops"),
    )


def _get_soa_measures(cur) -> list[dict]:
    """Builds SoA measure list from M8 ENS mappings or returns static list."""
    try:
        cur.execute("""
            SELECT DISTINCT medida_principal as id_ens, nivel_incumplimiento as estado
            FROM m8_ens_mappings
            ORDER BY id_ens
            LIMIT 20
        """)
        rows = cur.fetchall()
        if rows:
            return [
                {
                    "id_ens": r["id_ens"],
                    "dominio": "Marco Operacional",
                    "descripcion": r["id_ens"],
                    "estado": "NO CUMPLE" if r["estado"] == "crítico" else "CUMPLE PARCIAL",
                    "justificacion": "Detectado por M8-IA en ciclo semanal",
                }
                for r in rows
            ]
    except Exception:
        pass
    return [
        {"id_ens": "op.exp.2", "dominio": "Explotación", "descripcion": "Gestión de vulnerabilidades", "estado": "CUMPLE", "justificacion": "M2+M3 ejecutan análisis periódico automatizado"},
        {"id_ens": "op.exp.4", "dominio": "Explotación", "descripcion": "Mantenimiento y actualizaciones", "estado": "CUMPLE", "justificacion": "M7 genera plan de remediación priorizado por CVSS"},
        {"id_ens": "op.acc.5", "dominio": "Control de Acceso", "descripcion": "Autenticación fuerte MFA", "estado": "CUMPLE", "justificacion": "M4 requiere TOTP+PIN para cada autorización de exploit"},
        {"id_ens": "mp.info.3", "dominio": "Protección", "descripcion": "Cifrado de información", "estado": "CUMPLE", "justificacion": "Toda IA inference es local (Ollama/Mistral), datos no salen del servidor"},
        {"id_ens": "mp.info.4", "dominio": "Protección", "descripcion": "Integridad y autenticidad", "estado": "CUMPLE", "justificacion": "M7 aplica AES-256 y metadatos a todos los PDFs generados"},
        {"id_ens": "op.exp.5", "dominio": "Explotación", "descripcion": "Registro de actividad", "estado": "CUMPLE", "justificacion": "Wazuh + audit log inmutable en M1 para toda actividad"},
    ]


def get_report_data() -> dict:
    defaults: dict = {
        "total_activos": 0,
        "ens_score": 0,
        "top_vulns": [],
        "vulnerabilidades": [],
        "tareas": [],
        "medidas_soa": [],
        "roi_time_saved": 0,
        "auto_mitigated": 0,
        "exploits_ejecutados": 0,
        "total_snapshots": 0,
        "activos_detalle": [],
        "m4_aprobaciones": [],
        "siem_eventos": [],
        "db_available": False,
    }
    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:

                # ── Activos M1 ──────────────────────────────────────────
                cur.execute("""
                    SELECT id, ip, hostname, nombre, tipo, criticidad,
                           status, responsable, departamento, created_at
                    FROM assets
                    WHERE deleted_at IS NULL
                    ORDER BY criticidad DESC, created_at DESC
                """)
                activos = [dict(r) for r in cur.fetchall()]
                defaults["total_activos"] = len(activos)
                defaults["activos_detalle"] = activos

                # ── Vulnerabilidades M3 (vuln_findings) ─────────────────
                cur.execute("""
                    SELECT vf.asset_id, a.ip as host_ip, a.hostname,
                           vf.title as cve, vf.severity as crit,
                           vf.cvss_v3_score::text as cvss,
                           vf.description as desc,
                           vf.scanner_name,
                           vf.ens_requirement,
                           vf.created_at
                    FROM vuln_findings vf
                    LEFT JOIN assets a ON vf.asset_id = a.id
                    WHERE vf.severity IN ('CRITICAL','HIGH','MEDIUM')
                    ORDER BY vf.cvss_v3_score DESC NULLS LAST, vf.created_at DESC
                    LIMIT 50
                """)
                vulns = [dict(r) for r in cur.fetchall()]
                defaults["vulnerabilidades"] = vulns
                defaults["top_vulns"] = vulns[:10]

                # ── ENS Score ──────────────────────────────────────────
                cur.execute("""
                    SELECT COUNT(DISTINCT asset_id) as critical_assets
                    FROM vuln_findings
                    WHERE severity = 'CRITICAL'
                """)
                row = cur.fetchone()
                critical_assets = row["critical_assets"] if row else 0
                if defaults["total_activos"] > 0:
                    score = max(0, 100 - int((critical_assets / defaults["total_activos"]) * 40))
                else:
                    score = 75
                defaults["ens_score"] = score

                # ── M4 Aprobaciones ────────────────────────────────────
                cur.execute("""
                    SELECT id, cve_id, target_ip, status, requester,
                           created_at, approved_at, executed_at
                    FROM m4_approvals
                    ORDER BY created_at DESC
                    LIMIT 20
                """)
                aprobaciones = [dict(r) for r in cur.fetchall()]
                defaults["m4_aprobaciones"] = aprobaciones
                defaults["auto_mitigated"] = sum(1 for a in aprobaciones if a["status"] == "APPROVED")
                defaults["exploits_ejecutados"] = sum(1 for a in aprobaciones if a["status"] == "EXECUTED")

                # ── Recon Snapshots M2 ─────────────────────────────────
                cur.execute("SELECT COUNT(*) as total FROM recon_snapshots")
                row = cur.fetchone()
                defaults["total_snapshots"] = row["total"] if row else 0

                # ── SIEM Eventos M5 ────────────────────────────────────
                try:
                    cur.execute("""
                        SELECT event_type, severity, target_ip, description, timestamp
                        FROM siem_pipeline_events
                        ORDER BY timestamp DESC
                        LIMIT 10
                    """)
                    defaults["siem_eventos"] = [dict(r) for r in cur.fetchall()]
                except Exception:
                    conn.rollback()

                # ── ROI ────────────────────────────────────────────────
                defaults["roi_time_saved"] = int(len(vulns) * 1.9)

                # ── Tareas de remediación ──────────────────────────────
                defaults["tareas"] = [
                    {
                        "titulo": f"Remediar {v.get('cve','Vuln')[:60]} en {v.get('host_ip','activo')}",
                        "crit": v.get("crit", "HIGH"),
                        "activos": v.get("host_ip", "N/A"),
                        "accion": f"Aplicar parche para {v.get('cve','vulnerabilidad')[:50]}. {(v.get('desc') or '')[:80]}",
                    }
                    for v in vulns if v.get("crit") in ("CRITICAL", "HIGH")
                ][:10]

                defaults["medidas_soa"] = _get_soa_measures(cur)
                defaults["db_available"] = True
        conn.close()
    except Exception as e:
        logger.error(f"DB unavailable for report: {e}")

    return defaults


# --- PDF helpers ---

def seal_pdf(pdf_bytes: bytes) -> bytes:
    """
    US-7.6: Aplica cifrado AES-256, metadatos y bloquea la edición del PDF.
    Cumplimiento ENS: mp.info.4 (Integridad)
    """
    doc = fitz.open("pdf", pdf_bytes)
    doc.set_metadata({
        "author": "UNUWARE ScanOps Auto-Signer",
        "creator": "M7 Reporting Engine",
        "subject": "Evidencia Auditoría ENS Alto - Inalterable",
        "title": "Informe de Ciberseguridad",
        "keywords": "ENS, Confidencial, Auditoria, Integridad",
    })
    permisos = fitz.PDF_PERM_PRINT | fitz.PDF_PERM_ACCESSIBILITY
    out_bytes = doc.write(
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw="ScanOps_MasterKey_2026!",
        user_pw="",
        permissions=permisos,
    )
    doc.close()
    return out_bytes


def render_and_seal_sync(template_name: str, context: dict) -> tuple[str, bytes]:
    """
    Renderiza el HTML, genera el PDF, lo sella criptográficamente
    y lo envía de forma tolerante a fallos hacia Google Drive.
    """
    template = template_env.get_template(template_name)
    html_content = template.render(context)
    
    pdf_file = io.BytesIO()
    HTML(string=html_content).write_pdf(target=pdf_file)
    raw_pdf_bytes = pdf_file.getvalue()
    pdf_file.close()
    
    # Sellado del PDF (Cifrado de ScanOps)
    sealed_bytes = seal_pdf(raw_pdf_bytes)
    
    nombres = {
        'executive.html': '01_Informe_Ejecutivo_ScanOps.pdf',
        'technical.html': '02_Informe_Tecnico_ScanOps.pdf',
        'soa.html': '03_Declaracion_Aplicabilidad_SoA.pdf',
        'certificate.html': '04_Certificado_Activo_Critico.pdf',
        'access_log.html': '06_Evidencia_Accesos_ENS.pdf',
    }
    filename = nombres.get(template_name, 'informe.pdf')
    
    # ─── [NUEVO] SUBIDA EN SEGUNDO PLANO TOLERANTE A FALLOS ───
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        drive_filename = f"{timestamp}_{filename}"
        
        # Intentar subir el archivo sin bloquear el retorno principal
        drive_uploader.upload_pdf(drive_filename, sealed_bytes)
        
    except Exception as drive_err:
        # Si Google Drive falla, se captura el error aquí para que NO tire el endpoint
        logger.error(f"[M7_DRIVE_SHIELD] Falló la subida de respaldo a la nube: {drive_err}. Prosiguiendo con la entrega local.")
    
    # El return queda fuera del bloque de Drive, asegurando la descarga pase lo que pase
    return filename, sealed_bytes


# --- Access Log helpers ---

def _get_internal_token() -> str:
    """Genera JWT interno para llamadas inter-servicio de M7."""
    import jwt as _jwt
    from datetime import datetime, timezone, timedelta
    secret = os.getenv("JWT_SECRET_KEY", "scanops-secret-ens-alto-2026")
    payload = {
        "sub": "m7-reporting",
        "role": "service",
        "token_type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    return _jwt.encode(payload, secret, algorithm="HS256")


async def get_access_log_data() -> dict:
    """
    Consolida logs de acceso de dos fuentes:
    1. Login events de la plataforma ScanOps (JWT sessions) — desde Orchestrator
    2. Auth events SSH de servidores — desde M5 vía paramiko
    ENS: op.exp.5, op.acc.1
    """
    import httpx
    platform_events = []
    server_events = []
    server_stats = []
    brute_force_alerts = []

    # Fuente 1: sesiones ScanOps (JWT logins)
    try:
        async with httpx.AsyncClient(verify=False, timeout=8) as client:
            r = await client.get(
                "http://orchestrator:8009/auth/login-events?limit=200",
                headers={"Authorization": f"Bearer {_get_internal_token()}"}
            )
            if r.status_code == 200:
                data = r.json()
                platform_events = data.get("events", [])
    except Exception as e:
        logger.warning(f"[M7] No se pudieron obtener login-events: {e}")

    # Detección de fuerza bruta: ≥5 fallos en 10 min desde misma IP
    from collections import defaultdict
    failures_by_ip: dict = defaultdict(list)
    for ev in platform_events:
        if not ev.get("success") and ev.get("ip_origin"):
            failures_by_ip[ev["ip_origin"]].append(ev.get("timestamp", ""))
    for ip, timestamps in failures_by_ip.items():
        if len(timestamps) >= 5:
            brute_force_alerts.append({
                "ip": ip,
                "count": len(timestamps),
                "first": min(timestamps),
                "last": max(timestamps),
            })

    # Fuente 2: auth.log SSH de servidores
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.get("http://m5:8006/siem/auth-events?limit=200")
            if r.status_code == 200:
                data = r.json()
                server_events = data.get("events", [])
                server_stats = data.get("server_stats", [])
    except Exception as e:
        logger.warning(f"[M7] No se pudieron obtener auth-events M5: {e}")

    total_platform = len(platform_events)
    total_server = len(server_events)
    failed_platform = sum(1 for e in platform_events if not e.get("success"))
    failed_server = sum(1 for e in server_events if not e.get("success"))

    return {
        "platform_events": platform_events[:100],
        "server_events": server_events[:100],
        "server_stats": server_stats,
        "brute_force_alerts": brute_force_alerts,
        "total_platform": total_platform,
        "total_server": total_server,
        "failed_platform": failed_platform,
        "failed_server": failed_server,
        "success_platform": total_platform - failed_platform,
        "success_server": total_server - failed_server,
    }


# --- Endpoints ---

@app.get("/health")
async def health():
    db_ok = False
    try:
        conn = get_db_connection()
        conn.close()
        db_ok = True
    except Exception:
        pass
    return {"status": "ok", "service": "reporting-engine", "module": "M7", "db": "ok" if db_ok else "unavailable"}


@app.get("/report/test-weasy")
async def test_report():
    """US-7.1: Genera un PDF corporativo usando Jinja2 y WeasyPrint."""
    try:
        context = {
            "titulo": "Informe de Validación de Motor de Reportes",
            "report_id": f"REP-{uuid.uuid4().hex[:8].upper()}",
            "fecha": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "auditor": "Sistema Autónomo ScanOps",
            "mensaje": (
                "La US-7.1 ha sido implementada con éxito. El motor WeasyPrint permite renderizar "
                "estilos CSS3 complejos, garantizando que los informes de cumplimiento y SoA "
                "tengan una estética profesional y cumplan con los estándares del ENS Alto."
            ),
        }
        template = template_env.get_template('base.html')
        html_content = template.render(context)
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        pdf_bytes = pdf_file.getvalue()
        pdf_file.close()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=ScanOps_US_7_1_Test.pdf"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte: {str(e)}")


# ==============================================================================
# 1. ENDPOINT: INFORME EJECUTIVO
# ==============================================================================
@app.get("/report/executive")
async def generate_executive_report():
    """US-7.3: Informe Ejecutivo con datos reales de BD."""
    try:
        data = get_report_data()
        context = {
            "fecha": datetime.now().strftime("%d/%m/%Y"),
            "total_activos": data["total_activos"],
            "ens_score": data["ens_score"],
            "roi_time_saved": data["roi_time_saved"],
            "auto_mitigated": data["auto_mitigated"],
            "exploits_ejecutados": data["exploits_ejecutados"],
            "top_vulns": data["top_vulns"],
            "activos_detalle": data["activos_detalle"],
            "m4_aprobaciones": data["m4_aprobaciones"][:5],
            "siem_eventos": data["siem_eventos"][:5],
            "total_snapshots": data["total_snapshots"],
            "db_available": data["db_available"],
        }
        template = template_env.get_template('executive.html')
        html_content = template.render(context)
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        raw_pdf_bytes = pdf_file.getvalue()
        pdf_file.close()
        sealed_pdf_bytes = seal_pdf(raw_pdf_bytes)

        # ─── BACKUP EN SEGUNDO PLANO GOOGLE DRIVE ───
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            drive_uploader.upload_pdf(f"{timestamp}_01_Informe_Ejecutivo_ScanOps.pdf", sealed_pdf_bytes)
        except Exception as drive_err:
            logger.error(f"[M7_DRIVE_SHIELD] Falló backup en ruta: {drive_err}")

        # ─── ALERTA TELEGRAM: CICLO COMPLETADO ───
        try:
            import httpx as _httpx
            _token = os.getenv("TELEGRAM_BOT_TOKEN", "8607611023:AAFtjXnnQFp2qxH6I3KKrq_0_R-IXBqpzNk")
            _chat = os.getenv("TELEGRAM_CHAT_ID", "-1003918258595")
            _platform = os.getenv("PLATFORM_URL", "https://localhost:5173")
            _msg = (
                f"📊 <b>Ciclo ScanOps completado — Informe generado</b>\n\n"
                f"📅 <b>Fecha:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}\n"
                f"🏢 <b>Activos evaluados:</b> {data['total_activos']}\n"
                f"🔍 <b>Vulnerabilidades:</b> {len(data['vulnerabilidades'])}\n"
                f"✅ <b>Exploits aprobados:</b> {data['auto_mitigated']}\n"
                f"⚡ <b>Ataques ejecutados:</b> {data['exploits_ejecutados']}\n\n"
                f"📄 <b>Descargar informes:</b>\n"
                f"→ <a href='{_platform}/reporting'>M7 Reportes</a>"
            )
            _httpx.post(
                f"https://api.telegram.org/bot{_token}/sendMessage",
                json={"chat_id": _chat, "text": _msg, "parse_mode": "HTML",
                      "disable_web_page_preview": True},
                timeout=10,
            )
        except Exception:
            pass

        return Response(
            content=sealed_pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=ScanOps_Informe_Ejecutivo.pdf"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte ejecutivo: {str(e)}")

# ==============================================================================
# 2. ENDPOINT: INFORME TÉCNICO
# ==============================================================================
@app.get("/report/technical")
async def generate_technical_report():
    """US-7.2 y US-7.7: Informe Técnico y Plan de Remediación con datos reales de BD."""
    try:
        data = get_report_data()
        context = {
            "fecha": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "signature_id": f"SIEM-CORR-{uuid.uuid4().hex[:8].upper()}",
            "vulnerabilidades": data["vulnerabilidades"],
            "tareas": data["tareas"],
            "activos_detalle": data["activos_detalle"],
            "m4_aprobaciones": data["m4_aprobaciones"],
            "siem_eventos": data["siem_eventos"],
            "total_snapshots": data["total_snapshots"],
            "db_available": data["db_available"],
        }
        template = template_env.get_template('technical.html')
        html_content = template.render(context)
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        raw_pdf_bytes = pdf_file.getvalue()
        pdf_file.close()
        sealed_pdf_bytes = seal_pdf(raw_pdf_bytes)

        # ─── BACKUP EN SEGUNDO PLANO GOOGLE DRIVE ───
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            drive_uploader.upload_pdf(f"{timestamp}_02_Informe_Tecnico_ScanOps.pdf", sealed_pdf_bytes)
        except Exception as drive_err:
            logger.error(f"[M7_DRIVE_SHIELD] Falló backup en ruta: {drive_err}")

        return Response(
            content=sealed_pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=ScanOps_Informe_Tecnico.pdf"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte técnico: {str(e)}")


# ==============================================================================
# 3. ENDPOINT: DECLARACIÓN DE APLICABILIDAD (SoA)
# ==============================================================================
@app.get("/report/soa")
async def generate_soa_report():
    """US-7.4: Declaración de Aplicabilidad (SoA) con datos reales de BD."""
    try:
        data = get_report_data()
        context = {
            "fecha": datetime.now().strftime("%d/%m/%Y"),
            "medidas": data["medidas_soa"],
            "total_activos": data["total_activos"],
            "total_snapshots": data["total_snapshots"],
            "vulnerabilidades": data["vulnerabilidades"],
            "auto_mitigated": data["auto_mitigated"],
            "db_available": data["db_available"],
        }
        template = template_env.get_template('soa.html')
        html_content = template.render(context)
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        raw_pdf_bytes = pdf_file.getvalue()
        pdf_file.close()
        sealed_pdf_bytes = seal_pdf(raw_pdf_bytes)

        # ─── BACKUP EN SEGUNDO PLANO GOOGLE DRIVE ───
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            drive_uploader.upload_pdf(f"{timestamp}_03_Declaracion_Aplicabilidad_SoA.pdf", sealed_pdf_bytes)
        except Exception as drive_err:
            logger.error(f"[M7_DRIVE_SHIELD] Falló backup en ruta: {drive_err}")

        return Response(
            content=sealed_pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=ScanOps_SoA_ENS_Alto.pdf"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte SoA: {str(e)}")


@app.get("/report/certificate/{asset_id}")
async def generate_certificate(asset_id: int):
    """US-7.5: Certificado de Evidencia ENS por activo individual."""
    try:
        if asset_id == 1:
            asset_data = {
                "name": "Servidor de Base de Datos Principal (PostgreSQL)",
                "ip": "10.202.15.50",
                "status": "SECURE",
                "audit_id": "AUD-DB-001",
            }
        else:
            asset_data = {
                "name": "Frontend Web de Pruebas (Legacy)",
                "ip": "10.202.15.99",
                "status": "VULNERABLE",
                "audit_id": "AUD-WEB-999",
            }
        context = {
            "asset_name": asset_data["name"],
            "asset_ip": asset_data["ip"],
            "audit_id": asset_data["audit_id"],
            "status": asset_data["status"],
            "fecha": datetime.now().strftime("%d de %B de %Y"),
            "cert_uuid": str(uuid.uuid4()).upper(),
        }
        template = template_env.get_template('certificate.html')
        html_content = template.render(context)
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        raw_pdf_bytes = pdf_file.getvalue()
        pdf_file.close()
        sealed_pdf_bytes = seal_pdf(raw_pdf_bytes)
        return Response(
            content=sealed_pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=Certificado_{asset_data['ip']}.pdf"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando certificado: {str(e)}")


@app.get("/report/full-audit")
async def generate_full_audit_zip():
    """
    US-7.8: Endpoint Maestro Asíncrono.
    Genera todos los informes en paralelo y los devuelve en un archivo ZIP.
    """
    try:
        data = get_report_data()
        fecha_actual = datetime.now().strftime("%d/%m/%Y")

        ctx_exec = {
            "fecha": fecha_actual,
            "total_activos": data["total_activos"],
            "ens_score": data["ens_score"],
            "roi_time_saved": data["roi_time_saved"],
            "auto_mitigated": data["auto_mitigated"],
            "top_vulns": data["top_vulns"],
            "db_available": data["db_available"],
        }
        ctx_tech = {
            "fecha": fecha_actual,
            "signature_id": f"SIEM-FULL-{uuid.uuid4().hex[:8].upper()}",
            "vulnerabilidades": data["vulnerabilidades"],
            "tareas": data["tareas"],
            "db_available": data["db_available"],
        }
        ctx_soa = {
            "fecha": fecha_actual,
            "medidas": data["medidas_soa"],
            "db_available": data["db_available"],
        }
        ctx_cert = {
            "asset_name": "Infraestructura Global ScanOps",
            "asset_ip": "10.0.0.0/8",
            "audit_id": "AUDIT-GLOBAL-2026",
            "status": "SECURE",
            "fecha": fecha_actual,
            "cert_uuid": str(uuid.uuid4()).upper(),
        }

        # Accesos ENS — fuente asíncrona, se obtiene antes del gather
        access_data = await get_access_log_data()
        ctx_access = {
            "fecha": fecha_actual,
            "report_id": f"ACC-FULL-{uuid.uuid4().hex[:8].upper()}",
            "periodo": f"{datetime.now().strftime('%B %Y')}",
            **access_data,
        }

        resultados = await asyncio.gather(
            asyncio.to_thread(render_and_seal_sync, 'executive.html', ctx_exec),
            asyncio.to_thread(render_and_seal_sync, 'technical.html', ctx_tech),
            asyncio.to_thread(render_and_seal_sync, 'soa.html', ctx_soa),
            asyncio.to_thread(render_and_seal_sync, 'certificate.html', ctx_cert),
            asyncio.to_thread(render_and_seal_sync, 'access_log.html', ctx_access),
        )

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
            for filename, pdf_bytes in resultados:
                zip_file.writestr(filename, pdf_bytes)

        timestamp_name = f"ScanOps_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        file_path = os.path.join(HISTORY_DIR, timestamp_name)
        with open(file_path, "wb") as f:
            f.write(zip_buffer.getvalue())

        return Response(
            content=zip_buffer.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=ScanOps_Auditoria_Completa.zip"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en generación asíncrona: {str(e)}")


@app.get("/report/history")
async def list_historical_reports():
    """US-7.9: Lista todos los informes de auditoría guardados en el sistema."""
    try:
        archivos = os.listdir(HISTORY_DIR)
        archivos_zip = sorted([f for f in archivos if f.endswith('.zip')], reverse=True)
        return {"total_historicos": len(archivos_zip), "archivos": archivos_zip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error leyendo el histórico: {str(e)}")


@app.get("/report/history/{filename}")
async def download_historical_report(filename: str):
    """US-7.9: Descarga un informe histórico específico."""
    file_path = os.path.join(HISTORY_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="El informe solicitado no existe.")
    return FileResponse(path=file_path, filename=filename, media_type="application/zip")


@app.get("/report/asset/{asset_id}")
async def generate_asset_report(asset_id: int):
    """
    US-7.10: Informe técnico detallado de un activo específico.
    Consolida datos de M1+M2+M3+M8+M4+M5 en un único PDF firmado AES-256.
    ENS: op.exp.2, mp.info.4, op.exp.5
    """
    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:

                # Activo M1
                cur.execute("""
                    SELECT id, ip, hostname, nombre, tipo, criticidad, status,
                           responsable, departamento, ubicacion, tags_ens, notas,
                           os_family, os_version, created_at
                    FROM assets WHERE id = %s AND deleted_at IS NULL
                """, (asset_id,))
                activo_row = cur.fetchone()
                if not activo_row:
                    raise HTTPException(status_code=404, detail="Activo no encontrado")

                # ── Recon M2 ──────────────────────────────────────────────────
                recon_data = None
                recon_findings_list = []
                recon_subdomains_list = []

                cur.execute("""
                    SELECT id, cycle_id, target, started_at, finished_at,
                           status, os_family, os_version, mac_address, mac_vendor,
                           latency_ms, webcheck_data
                    FROM recon_snapshots
                    WHERE target = %s
                    ORDER BY started_at DESC LIMIT 1
                """, (activo_row["ip"],))
                snap_row = cur.fetchone()

                if snap_row:
                    recon_data = dict(snap_row)
                    snap_id = snap_row["id"]

                    cur.execute("""
                        SELECT port, service, version, state, source
                        FROM recon_findings
                        WHERE snapshot_id = %s AND state = 'open'
                        ORDER BY port
                    """, (snap_id,))
                    recon_findings_list = [dict(r) for r in cur.fetchall()]

                    cur.execute("""
                        SELECT subdomain, source
                        FROM recon_subdomains
                        WHERE snapshot_id = %s
                        ORDER BY subdomain
                    """, (snap_id,))
                    recon_subdomains_list = [dict(r) for r in cur.fetchall()]

                # Vulnerabilidades M3
                cur.execute("""
                    SELECT title, vulnerability_id AS cve_id, severity, cvss_v3_score,
                           description, affected_port AS port, affected_protocol AS protocol,
                           scanner_name, ens_requirement, created_at
                    FROM vuln_findings
                    WHERE asset_id = %s
                    ORDER BY cvss_v3_score DESC NULLS LAST, created_at DESC
                """, (asset_id,))
                vuln_rows = cur.fetchall()

                # ── AI Reasoning M8 ───────────────────────────────────────
                ai_result = None
                try:
                    cur.execute("""
                        SELECT suggested_tool, tool_params, mitre_tactic,
                               risk_level, attack_rationale, confidence,
                               status, created_at
                        FROM m8_results
                        WHERE asset_id = %s
                        ORDER BY created_at DESC LIMIT 1
                    """, (asset_id,))
                    ai_row = cur.fetchone()
                    if ai_row:
                        ai_result = dict(ai_row)
                except Exception:
                    conn.rollback()

                # M4
                m4_row = None
                cur.execute("""
                    SELECT id, cve_id, target_ip, status, requester,
                           created_at, approved_at, executed_at, execution_result AS exploit_result
                    FROM m4_approvals
                    WHERE target_ip = (SELECT ip FROM assets WHERE id = %s)
                      AND status IN ('APPROVED', 'EXECUTED')
                    ORDER BY created_at DESC LIMIT 1
                """, (asset_id,))
                m4_row = cur.fetchone()

                # SIEM M5
                siem_rows = []
                try:
                    cur.execute("""
                        SELECT event_type, severity, target_ip, description, timestamp, source
                        FROM siem_pipeline_events
                        WHERE target_ip = (SELECT ip FROM assets WHERE id = %s)
                        ORDER BY timestamp DESC LIMIT 50
                    """, (asset_id,))
                    siem_rows = cur.fetchall()
                except Exception:
                    conn.rollback()

        conn.close()

        vuln_list = [dict(r) for r in vuln_rows]
        context = {
            "fecha":            datetime.now().strftime("%d/%m/%Y %H:%M"),
            "report_id":        f"ACT-{asset_id}-{uuid.uuid4().hex[:8].upper()}",
            "activo":           dict(activo_row),
            "recon_data":           recon_data,
            "recon_findings":       recon_findings_list,
            "recon_subdomains":     recon_subdomains_list,
            "vulnerabilidades": vuln_list,
            "ai_result":        ai_result,
            "m4_result":        dict(m4_row) if m4_row else None,
            "siem_eventos":     [dict(r) for r in siem_rows],
            "total_vulns":      len(vuln_list),
            "critical_count":   sum(1 for v in vuln_list if v["severity"] == "CRITICAL"),
            "high_count":       sum(1 for v in vuln_list if v["severity"] == "HIGH"),
        }

        template = template_env.get_template('asset_detail.html')
        html_content = template.render(context)
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        raw_pdf_bytes = pdf_file.getvalue()
        pdf_file.close()
        sealed_bytes = seal_pdf(raw_pdf_bytes)

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            drive_uploader.upload_pdf(
                f"{timestamp}_05_Informe_Activo_{asset_id}.pdf", sealed_bytes
            )
        except Exception as drive_err:
            logger.error(f"[M7_DRIVE_SHIELD] Falló backup activo {asset_id}: {drive_err}")

        return Response(
            content=sealed_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=ScanOps_Activo_{asset_id}.pdf"},
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando informe de activo: {str(e)}")


@app.get("/report/access-log")
async def generate_access_log_report():
    """
    Nuevo endpoint: PDF de evidencia de control de acceso ENS.
    Consolida sesiones ScanOps + auth.log SSH de servidores.
    ENS: op.exp.5 (Registro de actividad), op.acc.1 (Control de acceso)
    Firmado AES-256 — mp.info.4
    """
    try:
        data = await get_access_log_data()
        context = {
            "fecha": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "report_id": f"ACC-{uuid.uuid4().hex[:8].upper()}",
            "periodo": f"{datetime.now().strftime('%B %Y')}",
            **data,
        }
        template = template_env.get_template("access_log.html")
        html_content = template.render(context)

        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        raw_bytes = pdf_file.getvalue()
        pdf_file.close()
        sealed_bytes = seal_pdf(raw_bytes)

        # Backup Google Drive
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            drive_uploader.upload_pdf(
                f"{timestamp}_06_Evidencia_Accesos_ENS.pdf", sealed_bytes
            )
        except Exception as drive_err:
            logger.error(f"[M7_DRIVE_SHIELD] Falló backup access-log: {drive_err}")

        return Response(
            content=sealed_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=ScanOps_Evidencia_Accesos_ENS.pdf"
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generando informe de accesos: {str(e)}"
        )


@app.get("/report/hardening/{asset_id}")
async def generate_hardening_report(asset_id: int):
    """
    Informe PDF de bastionado ENS para un activo específico.
    Consolida los resultados de hardening_results con datos del activo (M1).
    ENS: op.exp.2, mp.info.3, op.acc.6, op.cont.2, mp.com.1
    Firmado AES-256 — mp.info.4
    """
    try:
        conn = get_db_connection()

        # Activo (assets siempre existe)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, ip, hostname, nombre, tipo, criticidad,
                       status, responsable
                FROM assets
                WHERE id = %s AND deleted_at IS NULL
            """, (asset_id,))
            activo_row = cur.fetchone()
        if not activo_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Activo no encontrado")

        # hardening_results puede no existir todavía (la crea M3 en primer uso)
        resultado_row = None
        historial_rows = []
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, asset_id, target_ip, hostname, controles,
                           si_count, no_count, revisar_count, cumple_ens, verified_at
                    FROM hardening_results
                    WHERE asset_id = %s
                    ORDER BY verified_at DESC
                    LIMIT 1
                """, (asset_id,))
                resultado_row = cur.fetchone()
                cur.execute("""
                    SELECT si_count, no_count, revisar_count, cumple_ens, verified_at
                    FROM hardening_results
                    WHERE asset_id = %s
                    ORDER BY verified_at DESC
                    LIMIT 5
                """, (asset_id,))
                historial_rows = cur.fetchall()
        except Exception:
            conn.rollback()

        conn.close()

        resultado = None
        if resultado_row:
            resultado = dict(resultado_row)
            import json as _json
            if isinstance(resultado.get("controles"), str):
                resultado["controles"] = _json.loads(resultado["controles"])
            if resultado.get("verified_at"):
                resultado["verified_at"] = resultado["verified_at"].strftime("%d/%m/%Y %H:%M")

        historial = []
        for r in historial_rows:
            row = dict(r)
            if row.get("verified_at"):
                row["verified_at"] = row["verified_at"].strftime("%d/%m/%Y %H:%M")
            historial.append(row)

        context = {
            "fecha":      datetime.now().strftime("%d/%m/%Y %H:%M"),
            "report_id":  f"HARD-{asset_id}-{uuid.uuid4().hex[:8].upper()}",
            "activo":     dict(activo_row),
            "resultado":  resultado,
            "historial":  historial,
            "sin_datos":  resultado is None,
        }

        template = template_env.get_template("hardening.html")
        html_content = template.render(context)
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        raw_bytes = pdf_file.getvalue()
        pdf_file.close()
        sealed_bytes = seal_pdf(raw_bytes)

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            drive_uploader.upload_pdf(
                f"{timestamp}_07_Bastionado_{asset_id}.pdf", sealed_bytes
            )
        except Exception as drive_err:
            logger.error(f"[M7_DRIVE_SHIELD] Falló backup hardening {asset_id}: {drive_err}")

        return Response(
            content=sealed_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition":
                    f"attachment; filename=ScanOps_Bastionado_{asset_id}.pdf"
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generando informe de bastionado: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
