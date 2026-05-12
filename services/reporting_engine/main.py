from fastapi import FastAPI, Response, HTTPException
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import io
from datetime import datetime
import uuid
from fastapi import APIRouter

app = FastAPI(title="ScanOps M7 - Reporting Engine")

# Configuración de Jinja2
# Buscamos las plantillas en la carpeta local del servicio
template_env = Environment(loader=FileSystemLoader('templates'))

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
        pdf_file.close()

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=ScanOps_Informe_Ejecutivo.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte ejecutivo: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)