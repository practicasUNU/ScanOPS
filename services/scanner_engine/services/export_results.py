"""
Export Results Service - Scanner Engine M3
Generación de reportes en formatos JSON, CSV y PDF.
Cumple con ENS Alto [op.exp.2] para la documentación de hallazgos.
"""

import csv
import json
import io
from typing import List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.units import cm

from services.scanner_engine.models.vulnerability import VulnFinding

def get_vuln_findings(db: Session, asset_id: int, scan_id: str = None) -> List[VulnFinding]:
    """Obtiene los hallazgos de vulnerabilidades de la base de datos."""
    query = db.query(VulnFinding).filter(VulnFinding.asset_id == asset_id)
    if scan_id:
        query = query.filter(VulnFinding.scan_id == scan_id)
    return query.all()

def export_to_json(db: Session, asset_id: int, scan_id: str = None) -> str:
    """Exporta los hallazgos a formato JSON."""
    findings = get_vuln_findings(db, asset_id, scan_id)
    data = [
        {
            "id": f.id,
            "vulnerability_id": f.vulnerability_id,
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
            "scanner": f.scanner_name,
            "cvss": f.cvss_v3_score,
            "status": f.remediation_status,
            "created_at": f.created_at.isoformat() if f.created_at else None
        }
        for f in findings
    ]
    return json.dumps(data, indent=4)

def export_to_csv(db: Session, asset_id: int, scan_id: str = None):
    """Exporta los hallazgos a formato CSV."""
    findings = get_vuln_findings(db, asset_id, scan_id)
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Headers
    writer.writerow(["Vulnerability", "Severity", "CVE/ID", "Scanner", "Description", "Status"])
    
    for f in findings:
        writer.writerow([
            f.title,
            f.severity,
            f.vulnerability_id,
            f.scanner_name,
            f.description[:100] + "..." if f.description else "",
            f.remediation_status
        ])
    
    output.seek(0)
    return output

def export_to_pdf(db: Session, asset_id: int, scan_id: str = None):
    """Exporta los hallazgos a formato PDF usando ReportLab."""
    findings = get_vuln_findings(db, asset_id, scan_id)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["Normal"]
    
    elements = []
    
    # Logo Placeholder o Texto
    elements.append(Paragraph("<b>ScanOPS - M3 Vulnerability Report</b>", title_style))
    elements.append(Spacer(1, 0.5*cm))
    
    # Metadata
    elements.append(Paragraph(f"Fecha: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", normal_style))
    elements.append(Paragraph(f"Asset ID: {asset_id}", normal_style))
    if scan_id:
        elements.append(Paragraph(f"Scan ID: {scan_id}", normal_style))
    elements.append(Spacer(1, 1*cm))
    
    # Resumen de Severidad
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.severity.upper() if f.severity else "INFO"
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["INFO"] += 1
            
    elements.append(Paragraph("Resumen de Severidad", heading_style))
    summary_data = [["Severidad", "Cantidad"]]
    for sev, count in severity_counts.items():
        summary_data.append([sev, str(count)])
        
    summary_table = Table(summary_data, colWidths=[4*cm, 2*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 1*cm))
    
    # Detalle de Vulnerabilidades
    elements.append(Paragraph("Detalle de Vulnerabilidades", heading_style))
    
    table_data = [["Vulnerabilidad", "Sev", "CVE/ID", "Scanner"]]
    for f in findings:
        table_data.append([
            Paragraph(f.title[:50], normal_style),
            f.severity,
            f.vulnerability_id,
            f.scanner_name
        ])
        
    vuln_table = Table(table_data, colWidths=[7*cm, 2.5*cm, 4*cm, 3*cm])
    vuln_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    elements.append(vuln_table)
    
    # Generar PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer
