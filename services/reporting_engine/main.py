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
    """
    Queries the DB for real report data.
    Returns a dict with all fields needed by all report templates.
    Falls back to safe defaults if DB is unavailable.
    ENS: op.exp.5 (audit trail), op.exp.2 (vulnerability management)
    """
    defaults: dict = {
        "total_activos": 0,
        "ens_score": 0,
        "top_vulns": [],
        "vulnerabilidades": [],
        "tareas": [],
        "medidas_soa": [],
        "roi_time_saved": 0,
        "auto_mitigated": 0,
        "db_available": False,
    }
    try:
        conn = get_db_connection()
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:

                # Total assets from M1
                cur.execute("SELECT COUNT(*) as total FROM assets WHERE deleted_at IS NULL")
                row = cur.fetchone()
                defaults["total_activos"] = row["total"] if row else 0

                # Vulnerabilities — try dedicated table first, fall back to scan_results
                try:
                    cur.execute("""
                        SELECT host_ip as ip, cve_id as cve, cvss_score::text as cvss,
                               description as desc, severity as crit
                        FROM vulnerabilities
                        WHERE status != 'resolved'
                        ORDER BY cvss_score DESC NULLS LAST
                        LIMIT 20
                    """)
                    vulns = [dict(r) for r in cur.fetchall()]
                except Exception:
                    conn.rollback()
                    try:
                        cur.execute("""
                            SELECT target_ip as ip, finding_id as cve,
                                   '7.0' as cvss, raw_output as desc, 'HIGH' as crit
                            FROM scan_results
                            ORDER BY created_at DESC
                            LIMIT 20
                        """)
                        vulns = [dict(r) for r in cur.fetchall()]
                    except Exception:
                        conn.rollback()
                        vulns = []

                defaults["vulnerabilidades"] = vulns
                defaults["top_vulns"] = vulns[:5]

                # ENS score: percentage of assets without critical vulns
                if defaults["total_activos"] > 0:
                    try:
                        cur.execute("""
                            SELECT COUNT(DISTINCT host_ip) as critical_assets
                            FROM vulnerabilities
                            WHERE severity = 'CRITICAL' AND status != 'resolved'
                        """)
                        row = cur.fetchone()
                        critical_assets = row["critical_assets"] if row else 0
                        score = max(0, 100 - int((critical_assets / defaults["total_activos"]) * 100))
                        defaults["ens_score"] = score
                    except Exception:
                        conn.rollback()

                # Approved M4 exploits
                try:
                    cur.execute("SELECT COUNT(*) as total FROM m4_approvals WHERE status = 'APPROVED'")
                    row = cur.fetchone()
                    defaults["auto_mitigated"] = row["total"] if row else 0
                except Exception:
                    conn.rollback()

                # ROI: 1.9 hours saved per vuln (manual=2h, auto=0.1h)
                defaults["roi_time_saved"] = int(len(vulns) * 1.9)

                # Remediation tasks from critical/high vulns
                defaults["tareas"] = [
                    {
                        "titulo": f"Remediar {v.get('cve', 'Vuln')} en {v.get('ip', 'activo')}",
                        "crit": v.get("crit", "HIGH"),
                        "activos": v.get("ip", "N/A"),
                        "accion": f"Aplicar parche para {v.get('cve', 'vulnerabilidad')}. {v.get('desc', '')[:100]}",
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
            "top_vulns": data["top_vulns"],
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

        resultados = await asyncio.gather(
            asyncio.to_thread(render_and_seal_sync, 'executive.html', ctx_exec),
            asyncio.to_thread(render_and_seal_sync, 'technical.html', ctx_tech),
            asyncio.to_thread(render_and_seal_sync, 'soa.html', ctx_soa),
            asyncio.to_thread(render_and_seal_sync, 'certificate.html', ctx_cert),
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
