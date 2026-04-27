# services/ai_reasoning/report_generator.py

import logging
from datetime import datetime
from typing import List, Dict, Optional
from jinja2 import Template

from services.ai_reasoning.ollama_client import ollama

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Genera informes de seguridad para ScanOps.
    Incluye informes técnicos (HTML/PDF) e informes ejecutivos IA (ENS op.exp.2).
    """
    
    def __init__(self):
        self.template_html = self._load_html_template()

    async def generate_preliminary_report(self, hallazgos: List[Dict], activos: List[Dict], fecha_ciclo: str, fecha_sabado: str) -> str:
        """
        Genera el informe ejecutivo preliminar semanal usando IA (Ollama).
        
        Este informe es evidencia requerida para el auditor según ENS Alto medida op.exp.2.
        No debe modificarse después de ser revisado y firmado por el Responsable de Seguridad.
        
        Args:
            hallazgos: Lista de hallazgos procesados (filtrados, priorizados y mapeados).
            activos: Lista de activos auditados en el ciclo.
            fecha_ciclo: Fecha de inicio del ciclo.
            fecha_sabado: Fecha de la próxima ventana de explotación.
            
        Returns:
            str: Informe ejecutivo en texto plano estructurado.
        """
        # Formatear lista de hallazgos confirmados
        hallazgos_str_list = []
        for h in hallazgos:
            cve_title = h.get("cve") or h.get("title", "Desconocido")
            hostname = h.get("hostname", "N/A")
            prioridad = h.get("priority_score") or h.get("prioridad_real", 0.0)
            accion = h.get("recommended_action") or h.get("accion_recomendada", "monitorizar")
            ens = h.get("medida_principal") or (h.get("ens_articles", ["op.exp.2"])[0] if h.get("ens_articles") else "op.exp.2")
            msf = h.get("msf_module") or "pendiente"
            
            line = f"- [{cve_title}] | Activo: {hostname} | Prioridad: {prioridad} | Acción: {accion} | ENS: {ens} | MSF sugerido: {msf}"
            hallazgos_str_list.append(line)
            
        lista_hallazgos_confirmados = "\n".join(hallazgos_str_list) if hallazgos_str_list else "Ciclo sin hallazgos críticos."
        
        # Formatear lista de activos
        activos_nombres = [a.get("hostname", "Desconocido") for a in activos]
        lista_activos = ", ".join(activos_nombres) if activos_nombres else "Ninguno"
        
        system_prompt = """
Eres un consultor senior de ciberseguridad especializado en ENS Alto. Tu función es redactar el informe ejecutivo preliminar semanal de ScanOps para que el Responsable de Seguridad lo revise antes de autorizar la fase de explotación.

El informe debe ser claro, directo y sin tecnicismos innecesarios. Va dirigido a un responsable técnico, no a dirección general.

ESTRUCTURA OBLIGATORIA DEL INFORME (respeta exactamente este orden):

1. RESUMEN DEL CICLO: una sola frase con el estado general (ej: "Se detectaron N vulnerabilidades críticas en X activos").
2. HALLAZGOS CRÍTICOS: lista de vulnerabilidades con accion_recomendada "explotar_inmediato", ordenados por prioridad_real descendente.
3. HALLAZGOS A EXPLOTAR EN CICLO: lista de vulnerabilidades con accion_recomendada "explotar_ciclo".
4. PLAN DE EXPLOITS SUGERIDO: para cada hallazgo de los puntos 2 y 3, el módulo de Metasploit sugerido y el riesgo estimado.
5. ACTIVOS SIN VULNERABILIDADES CRÍTICAS: lista breve.
6. DECISIÓN REQUERIDA: qué necesita aprobar el Responsable de Seguridad con TOTP antes del sábado.

REGLAS:
- No incluyas hallazgos con accion_recomendada "monitorizar" o "descartar" en las secciones de exploits.
- Cada hallazgo debe incluir su medida ENS principal.
- Sé conciso. Máximo 400 palabras en total.
- Responde en texto plano estructurado, no en JSON.
"""

        user_prompt = f"""
HALLAZGOS CONFIRMADOS DEL CICLO (ya filtrados, priorizados y mapeados):
{lista_hallazgos_confirmados}

ACTIVOS AUDITADOS ESTE CICLO:
{lista_activos}

FECHA DEL CICLO: {fecha_ciclo}
PRÓXIMA VENTANA DE EXPLOTACIÓN: sábado {fecha_sabado} a las 01:00

Genera el informe ejecutivo preliminar.
"""

        try:
            response = await ollama.analyze(
                prompt=user_prompt,
                system_prompt=system_prompt,
                temperature=0.3,
                top_p=0.9
            )
            
            if not response:
                raise ValueError("Respuesta vacía de Ollama")
                
            return response

        except Exception as e:
            logger.error(f"Error generando informe preliminar con IA: {e}")
            # Fallback: Informe mínimo
            return f"""
INFORME EJECUTIVO PRELIMINAR (ERROR EN GENERACIÓN)
FECHA: {fecha_ciclo}

1. RESUMEN DEL CICLO: Error técnico al procesar el informe. Consulte el dashboard para detalles.
2. HALLAZGOS CRÍTICOS:
{lista_hallazgos_confirmados[:200]}...
3. DECISIÓN REQUERIDA: El Responsable de Seguridad debe revisar manualmente los hallazgos en la base de datos debido a un error en el motor de IA.
"""
    
    def generate_html(self, findings: List[Dict], scan_id: str, scan_date: str) -> str:
        """
        Generar informe HTML
        
        Args:
            findings: Lista de hallazgos procesados
            scan_id: ID del escaneo
            scan_date: Fecha del escaneo
        
        Returns:
            str: HTML completo del informe
        """
        # PASO 1: Preparar datos
        total_findings = len(findings)
        critical_count = len([f for f in findings if f.get("risk_level") == "CRITICAL"])
        high_count = len([f for f in findings if f.get("risk_level") == "HIGH"])
        medium_count = len([f for f in findings if f.get("risk_level") == "MEDIUM"])
        low_count = len([f for f in findings if f.get("risk_level") == "LOW"])
        
        # Ordenar por prioridad si está disponible, si no mantener orden
        sorted_findings = sorted(findings, key=lambda x: x.get("priority_score", 0), reverse=True)
        top_findings = sorted_findings[:10]  # Top 10 por prioridad
        
        # PASO 2: Mapeo ENS resumen
        ens_summary = self._summarize_ens_articles(findings)
        
        # PASO 3: Renderizar template
        context = {
            "scan_id": scan_id,
            "scan_date": scan_date,
            "report_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": total_findings,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "top_findings": top_findings,
            "all_findings": findings,
            "ens_summary": ens_summary
        }
        
        html = self.template_html.render(context)
        logger.info(f"Generated HTML report for {scan_id} with {total_findings} findings")
        
        return html
    
    def generate_pdf(self, html: str, filename: str) -> bool:
        """
        Convertir HTML a PDF (requiere wkhtmltopdf o weasyprint)
        
        Args:
            html: Contenido HTML
            filename: Path de salida PDF
        
        Returns:
            bool: True si éxito
        """
        try:
            # Opción 1: Usar weasyprint (recomendado)
            from weasyprint import HTML, CSS
            
            HTML(string=html).write_pdf(filename)
            logger.info(f"Generated PDF report: {filename}")
            return True
        except ImportError:
            logger.warning("weasyprint not available, saving HTML only")
            return False
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            return False
    
    def save_html(self, html: str, filename: str) -> bool:
        """Guardar HTML a archivo"""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info(f"Saved HTML report: {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving HTML: {e}")
            return False
    
    def _load_html_template(self) -> Template:
        """Cargar template HTML"""
        template_str = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ScanOPS Report - {{ scan_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 3px solid #333; padding-bottom: 20px; }
        .summary { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; }
        .low { color: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #333; color: white; }
        .finding-card { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .ens-tags { margin-top: 10px; }
        .tag { background: #e3f2fd; color: #1565c0; padding: 5px 10px; border-radius: 3px; margin: 3px; display: inline-block; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ScanOPS Security Report</h1>
        <p>Scan ID: <strong>{{ scan_id }}</strong></p>
        <p>Scan Date: {{ scan_date }}</p>
        <p>Report Date: {{ report_date }}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Findings:</strong> {{ total_findings }}</p>
        <p><span class="critical">● CRITICAL: {{ critical }}</span> | <span class="high">● HIGH: {{ high }}</span> | <span class="medium">● MEDIUM: {{ medium }}</span> | <span class="low">● LOW: {{ low }}</span></p>
    </div>
    
    <h2>Top 10 Critical Findings</h2>
    {% for finding in top_findings %}
    <div class="finding-card">
        <h3>{{ finding.title }}</h3>
        <p><strong>Risk Level:</strong> <span class="{{ finding.risk_level|lower }}">{{ finding.risk_level }}</span></p>
        <p><strong>Priority Score:</strong> {{ finding.priority_score }}</p>
        <p><strong>Description:</strong> {{ finding.description }}</p>
        <p><strong>CVSS:</strong> {{ finding.cvss }}</p>
        <p><strong>CWE:</strong> {{ finding.cwe }}</p>
        <div class="ens-tags">
            <strong>RD 311/2022 Articles:</strong>
            {% for article in finding.ens_articles %}
            <span class="tag">{{ article }}</span>
            {% endfor %}
        </div>
    </div>
    {% endfor %}
    
    <h2>RD 311/2022 Compliance Summary</h2>
    <table>
        <tr>
            <th>Article</th>
            <th>Count</th>
            <th>Status</th>
        </tr>
        {% for article, count in ens_summary.items() %}
        <tr>
            <td>{{ article }}</td>
            <td>{{ count }}</td>
            <td class="critical">NOT COMPLIANT</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Complete Findings Table</h2>
    <table>
        <tr>
            <th>Title</th>
            <th>Risk Level</th>
            <th>CVSS</th>
            <th>Priority</th>
            <th>RD 311 Articles</th>
        </tr>
        {% for finding in all_findings %}
        <tr>
            <td>{{ finding.title }}</td>
            <td><span class="{{ finding.risk_level|lower }}">{{ finding.risk_level }}</span></td>
            <td>{{ finding.cvss }}</td>
            <td>{{ finding.priority_score }}</td>
            <td>{{ finding.ens_articles|join(', ') }}</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Recommendations</h2>
    <ul>
        <li>Fix all CRITICAL findings immediately</li>
        <li>Create action plan for HIGH findings within 1 week</li>
        <li>Document compliance with RD 311/2022 requirements</li>
        <li>Implement continuous vulnerability scanning</li>
    </ul>
    
    <footer style="border-top: 1px solid #ddd; margin-top: 40px; padding-top: 20px; font-size: 12px; color: #666;">
        <p>Generated by ScanOPS M8 AI Reasoning Module</p>
        <p>ENS Alto Compliance Report - RD 311/2022</p>
    </footer>
</body>
</html>
        """
        return Template(template_str)
    
    def _summarize_ens_articles(self, findings: List[Dict]) -> Dict[str, int]:
        """Contar artículos ENS"""
        summary = {}
        for finding in findings:
            for article in finding.get("ens_articles", []):
                summary[article] = summary.get(article, 0) + 1
        return summary


# Instancia global
report_generator = ReportGenerator()
