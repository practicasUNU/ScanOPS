from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import io
from datetime import datetime
import uuid
from fastapi import APIRouter
import fitz  # PyMuPDF
import zipfile
import asyncio
import os
from fastapi import FastAPI, Response, HTTPException
from fastapi.responses import FileResponse


app = FastAPI(title="ScanOps M7 - Reporting Engine")
HISTORY_DIR = "history"
os.makedirs(HISTORY_DIR, exist_ok=True)

# Configuración de Jinja2
# Buscamos las plantillas en la carpeta local del servicio
template_env = Environment(loader=FileSystemLoader('templates'))

def seal_pdf(pdf_bytes: bytes) -> bytes:
    """
    US-7.6: Aplica cifrado AES-256, metadatos y bloquea la edición del PDF.
    Cumplimiento ENS: mp.info.4 (Integridad)
    """
    # 1. Cargar el PDF en memoria con PyMuPDF
    doc = fitz.open("pdf", pdf_bytes)
    
    # 2. Inyectar Metadatos de Autenticidad
    doc.set_metadata({
        "author": "UNUWARE ScanOps Auto-Signer",
        "creator": "M7 Reporting Engine",
        "subject": "Evidencia Auditoría ENS Alto - Inalterable",
        "title": "Informe de Ciberseguridad",
        "keywords": "ENS, Confidencial, Auditoria, Integridad"
    })
    
    # 3. Configurar Permisos (Permitir lectura e impresión, DENEGAR edición)
    # Solo dejamos el bit de imprimir y accesibilidad (para lectores de pantalla)
    permisos = fitz.PDF_PERM_PRINT | fitz.PDF_PERM_ACCESSIBILITY
    
    # 4. Guardar con cifrado AES-256
    # user_pw="" -> Cualquiera lo puede abrir para leer
    # owner_pw -> Solo el CISO con esta clave podría quitar la protección de edición
    out_bytes = doc.write(
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw="ScanOps_MasterKey_2026!",
        user_pw="", 
        permissions=permisos
    )
    doc.close()
    return out_bytes

@app.get("/report/test-weasy")
async def test_report():
    """
    US-7.1: Genera un PDF corporativo usando Jinja2 y WeasyPrint.
    """
    try:
        # 1. Definir el contexto (datos dinámicos)
        context = {
            "titulo": "Informe de Validación de Motor de Reportes",
            "report_id": f"REP-{uuid.uuid4().hex[:8].upper()}",
            "fecha": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "auditor": "Sistema Autónomo ScanOps",
            "mensaje": "La US-7.1 ha sido implementada con éxito. El motor WeasyPrint permite renderizar "
                       "estilos CSS3 complejos, garantizando que los informes de cumplimiento y SoA "
                       "tengan una estética profesional y cumplan con los estándares del ENS Alto."
        }

        # 2. Cargar y renderizar la plantilla HTML
        template = template_env.get_template('base.html')
        html_content = template.render(context)

        # 3. Convertir HTML a PDF en memoria
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        
        pdf_bytes = pdf_file.getvalue()
        pdf_file.close()

        # 4. Retornar el PDF
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=ScanOps_US_7_1_Test.pdf"
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte: {str(e)}")
    
    
@app.get("/report/executive")
async def generate_executive_report():
    """
    US-7.3: Informe Ejecutivo no técnico con % cumplimiento, top vulns y ROI.
    """
    try:
        # 1. Datos simulados de negocio (Próximamente desde la Base de Datos)
        context = {
            "fecha": datetime.now().strftime("%d/%m/%Y"),
            "total_activos": 14,
            "ens_score": 85,  # 85% de cumplimiento
            "roi_time_saved": 92,
            "auto_mitigated": 3,
            "top_vulns": [
                {"severity": "CRITICAL", "name": "CVE-2024-21626 (runc escape)", "asset": "srv-docker-01", "status": "Pendiente Parche"},
                {"severity": "CRITICAL", "name": "SSH Expuesto a Internet", "asset": "fw-edge-main", "status": "Bloqueado vía M5"},
                {"severity": "HIGH", "name": "Contraseña por defecto en BD", "asset": "db-postgres-02", "status": "Requiere Acción"},
                {"severity": "HIGH", "name": "Falta cifrado en volumen", "asset": "storage-nas-01", "status": "Pendiente"},
                {"severity": "MEDIUM", "name": "Permisos excesivos en /etc", "asset": "srv-web-01", "status": "Bajo Observación"}
            ]
        }

        # 2. Renderizar plantilla ejecutiva
        template = template_env.get_template('executive.html')
        html_content = template.render(context)

        # 3. Convertir a PDF
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        
        pdf_bytes = pdf_file.getvalue()
        raw_pdf_bytes = pdf_file.getvalue()
        pdf_file.close()

        # AQUÍ ESTÁ LA MAGIA: Sellamos el PDF antes de enviarlo
        sealed_pdf_bytes = seal_pdf(raw_pdf_bytes)

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=ScanOps_Informe_Ejecutivo.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte ejecutivo: {str(e)}")

@app.get("/report/soa")
async def generate_soa_report():
    """
    US-7.4: Declaración de Aplicabilidad (SoA) con las medidas ENS.
    Formato horizontal y sellado criptográfico.
    """
    try:
        # 1. Datos del SoA (Muestra de las medidas más críticas que cubre ScanOps)
        # En producción, esto se extrae de la base de datos de auditoría cruzada.
        context = {
            "fecha": datetime.now().strftime("%d/%m/%Y"),
            "medidas": [
                {
                    "id_ens": "op.exp.4", "dominio": "Protección - Explotación", 
                    "descripcion": "Detección de intrusión (IDS/IPS).", 
                    "estado": "CUMPLE", 
                    "justificacion": "Módulo M5 activo. Sensores Suricata y Honeypots (Cowrie/Beelzebub) desplegados y reportando al SIEM central."
                },
                {
                    "id_ens": "op.exp.5", "dominio": "Protección - Explotación", 
                    "descripcion": "Vigilancia y monitorización continua.", 
                    "estado": "CUMPLE", 
                    "justificacion": "Agentes Wazuh y motor OpenSearch ingiriendo telemetría 24/7."
                },
                {
                    "id_ens": "mp.info.4", "dominio": "Marco Operacional", 
                    "descripcion": "Integridad y Autenticidad de la información.", 
                    "estado": "CUMPLE", 
                    "justificacion": "Motor M7 aplica firmas digitales AES-256 a todas las evidencias generadas."
                },
                {
                    "id_ens": "op.exp.7", "dominio": "Protección - Explotación", 
                    "descripcion": "Gestión de incidentes y reporte a CCN-CERT.", 
                    "estado": "CUMPLE", 
                    "justificacion": "Endpoint de orquestación M5 genera y notifica payloads formato LUCÍA automáticamente."
                },
                {
                    "id_ens": "op.acc.4", "dominio": "Control de Acceso", 
                    "descripcion": "Autenticación de doble factor (MFA) obligatoria.", 
                    "estado": "NO CUMPLE", 
                    "justificacion": "Detectados 3 servidores sin MFA aplicado en SSH. Remediación en curso por Blue Team."
                },
                {
                    "id_ens": "op.pl.1", "dominio": "Planificación", 
                    "descripcion": "Arquitectura de seguridad segregada.", 
                    "estado": "CUMPLE", 
                    "justificacion": "Microservicios aislados en redes Docker dedicadas (scanops_net). Tráfico LAPI segmentado."
                }
            ]
        }

        # 2. Renderizar plantilla SoA
        template = template_env.get_template('soa.html')
        html_content = template.render(context)

        # 3. Convertir a PDF (apaisado)
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        
        raw_pdf_bytes = pdf_file.getvalue()
        pdf_file.close()

        # 4. Sellar criptográficamente (Integridad mp.info.4)
        sealed_pdf_bytes = seal_pdf(raw_pdf_bytes)

        return Response(
            content=sealed_pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=ScanOps_SoA_ENS_Alto.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte SoA: {str(e)}")
    
    
@app.get("/report/technical")
async def generate_technical_report():
    """
    US-7.2 y US-7.7: Informe Técnico y Plan de Remediación Priorizado.
    """
    try:
        context = {
            "fecha": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "signature_id": f"SIEM-CORR-{uuid.uuid4().hex[:8].upper()}",
            "vulnerabilidades": [
                {"ip": "10.202.15.100", "cve": "CVE-2024-21626", "cvss": "8.6", "desc": "Fuga de contenedor runc permitiendo acceso al host subyacente.", "crit": "CRITICAL"},
                {"ip": "10.202.15.101", "cve": "MISCONF-SSH", "cvss": "N/A", "desc": "Puerto 22 expuesto a la WAN sin restricción de IP.", "crit": "CRITICAL"},
                {"ip": "10.202.15.105", "cve": "CVE-2023-4863", "cvss": "8.8", "desc": "Desbordamiento de búfer en libwebp (Base de datos).", "crit": "HIGH"},
                {"ip": "10.202.15.100", "cve": "POLICY-01", "cvss": "N/A", "desc": "Contraseñas locales no cumplen política ENS de longitud (14 chars).", "crit": "MEDIUM"}
            ],
            "tareas": [
                {
                    "titulo": "Actualizar motor Docker/runc", "crit": "CRITICAL",
                    "activos": "10.202.15.100",
                    "accion": "Ejecutar 'apt-get update && apt-get install --only-upgrade docker-ce' para parchear CVE-2024-21626. Reinicio requerido."
                },
                {
                    "titulo": "Restringir acceso SSH en Firewall", "crit": "CRITICAL",
                    "activos": "10.202.15.101",
                    "accion": "Modificar reglas de iptables/UFW para dropear tráfico al puerto 22 excepto desde la VPN de administración."
                },
                {
                    "titulo": "Parchear librerías del sistema operativo", "crit": "HIGH",
                    "activos": "10.202.15.105",
                    "accion": "Actualizar paquete libwebp. Verificar dependencias de la base de datos PostgreSQL."
                }
            ]
        }

        # Renderizar la plantilla técnica
        template = template_env.get_template('technical.html')
        html_content = template.render(context)

        # Generar PDF en memoria
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        
        raw_pdf_bytes = pdf_file.getvalue()
        pdf_file.close()

        # Sellar criptográficamente
        sealed_pdf_bytes = seal_pdf(raw_pdf_bytes)

        return Response(
            content=sealed_pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=ScanOps_Informe_Tecnico_Remediacion.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte técnico: {str(e)}")    
    
    
    
@app.get("/report/certificate/{asset_id}")
async def generate_certificate(asset_id: int):
    """
    US-7.5: Certificado de Evidencia ENS por activo individual.
    """
    try:
        # 1. Simulación de lógica de negocio según el ID del activo
        if asset_id == 1:
            asset_data = {
                "name": "Servidor de Base de Datos Principal (PostgreSQL)",
                "ip": "10.202.15.50",
                "status": "SECURE",
                "audit_id": "AUD-DB-001"
            }
        else:
            asset_data = {
                "name": "Frontend Web de Pruebas (Legacy)",
                "ip": "10.202.15.99",
                "status": "VULNERABLE",
                "audit_id": "AUD-WEB-999"
            }

        context = {
            "asset_name": asset_data["name"],
            "asset_ip": asset_data["ip"],
            "audit_id": asset_data["audit_id"],
            "status": asset_data["status"],
            "fecha": datetime.now().strftime("%d de %B de %Y"),
            "cert_uuid": str(uuid.uuid4()).upper(),
        }

        # 2. Renderizado
        template = template_env.get_template('certificate.html')
        html_content = template.render(context)

        # 3. PDF + Sellado Criptográfico
        pdf_file = io.BytesIO()
        HTML(string=html_content).write_pdf(target=pdf_file)
        
        raw_pdf_bytes = pdf_file.getvalue()
        pdf_file.close()

        sealed_pdf_bytes = seal_pdf(raw_pdf_bytes)

        return Response(
            content=sealed_pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=Certificado_{asset_data['ip']}.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando certificado: {str(e)}")
    
    
def render_and_seal_sync(template_name: str, context: dict) -> tuple[str, bytes]:
    """
    Función síncrona que renderiza el HTML, genera el PDF y lo sella.
    Devuelve una tupla con el nombre sugerido del archivo y los bytes del PDF.
    """
    template = template_env.get_template(template_name)
    html_content = template.render(context)
    
    pdf_file = io.BytesIO()
    HTML(string=html_content).write_pdf(target=pdf_file)
    raw_pdf_bytes = pdf_file.getvalue()
    pdf_file.close()
    
    sealed_bytes = seal_pdf(raw_pdf_bytes)
    
    # Asignar un nombre basado en la plantilla
    nombres = {
        'executive.html': '01_Informe_Ejecutivo_ScanOps.pdf',
        'technical.html': '02_Informe_Tecnico_ScanOps.pdf',
        'soa.html': '03_Declaracion_Aplicabilidad_SoA.pdf',
        'certificate.html': '04_Certificado_Activo_Critico.pdf'
    }
    return nombres.get(template_name, 'informe.pdf'), sealed_bytes


@app.get("/report/full-audit")
async def generate_full_audit_zip():
    """
    US-7.8: Endpoint Maestro Asíncrono.
    Genera todos los informes en paralelo (multihilo) y los devuelve en un archivo ZIP.
    """
    try:
        # 1. Preparar los datos (Contextos) para cada informe
        fecha_actual = datetime.now().strftime("%d/%m/%Y")
        
        ctx_exec = {
            "fecha": fecha_actual, "total_activos": 14, "ens_score": 85, 
            "roi_time_saved": 92, "auto_mitigated": 3, "top_vulns": []
        }
        ctx_tech = {
            "fecha": fecha_actual, "signature_id": f"SIEM-FULL-{uuid.uuid4().hex[:8].upper()}",
            "vulnerabilidades": [{"ip": "Red Completa", "cve": "Varios", "cvss": "N/A", "desc": "Ver logs crudos", "crit": "HIGH"}],
            "tareas": [{"titulo": "Revisión General", "crit": "HIGH", "activos": "Todos", "accion": "Aplicar plan integral."}]
        }
        ctx_soa = {
            "fecha": fecha_actual, 
            "medidas": [{"id_ens": "ALL", "dominio": "Global", "descripcion": "Auditoría Completa", "estado": "CUMPLE", "justificacion": "Revisión integral M7"}]
        }
        ctx_cert = {
            "asset_name": "Infraestructura Global ScanOps", "asset_ip": "10.0.0.0/8",
            "audit_id": "AUDIT-GLOBAL-2026", "status": "SECURE", "fecha": fecha_actual, "cert_uuid": str(uuid.uuid4()).upper()
        }

        # 2. Lanzar los 4 renderizados EN PARALELO usando hilos del procesador
        # asyncio.gather espera a que todos los hilos terminen sin bloquear el servidor
        resultados = await asyncio.gather(
            asyncio.to_thread(render_and_seal_sync, 'executive.html', ctx_exec),
            asyncio.to_thread(render_and_seal_sync, 'technical.html', ctx_tech),
            asyncio.to_thread(render_and_seal_sync, 'soa.html', ctx_soa),
            asyncio.to_thread(render_and_seal_sync, 'certificate.html', ctx_cert)
        )

        # 3. Crear el archivo ZIP en memoria
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
            for filename, pdf_bytes in resultados:
                zip_file.writestr(filename, pdf_bytes)
                
        # ---> NUEVO CÓDIGO (US-7.9): Guardar copia en disco <---
        timestamp_name = f"ScanOps_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        file_path = os.path.join(HISTORY_DIR, timestamp_name)
        with open(file_path, "wb") as f:
            f.write(zip_buffer.getvalue())
        # --------------------------------------------------------

        # 4. Retornar el ZIP compilado
        return Response(
            content=zip_buffer.getvalue(),
            media_type="application/zip",
            headers={
                "Content-Disposition": "attachment; filename=ScanOps_Auditoria_Completa.zip"
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en generación asíncrona: {str(e)}")


@app.get("/report/history")
async def list_historical_reports():
    """
    US-7.9: Lista todos los informes de auditoría guardados en el sistema.
    """
    try:
        archivos = os.listdir(HISTORY_DIR)
        # Filtramos para mostrar solo los ZIPs y los ordenamos
        archivos_zip = sorted([f for f in archivos if f.endswith('.zip')], reverse=True)
        return {"total_historicos": len(archivos_zip), "archivos": archivos_zip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error leyendo el histórico: {str(e)}")

@app.get("/report/history/{filename}")
async def download_historical_report(filename: str):
    """
    US-7.9: Descarga un informe histórico específico.
    """
    file_path = os.path.join(HISTORY_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="El informe solicitado no existe.")
    
    return FileResponse(path=file_path, filename=filename, media_type="application/zip")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)