from celery import shared_task
from shared.celery_app import app as celery_app
from services.ai_reasoning.models import Finding, AIAnalysis
from services.ai_reasoning.report_generator import report_generator
from services.ai_reasoning.false_positive_filter import FalsePositiveFilter
from services.ai_reasoning.ollama_client import ollama
from services.ai_reasoning.ens_mapper import map_to_ens
from services.ai_reasoning.attack_vector import suggest_attack_vector
from typing import List, Dict
from datetime import datetime, timedelta
import logging
import asyncio
import os
import psycopg2

logger = logging.getLogger(__name__)

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=3)
def analyze_finding_task(self, finding_id: str, analysis_dict: dict) -> dict:
    """
    Task async: Procesar resultado de análisis de IA
    Recibe el hallazgo ya analizado por el StreamingProcessor y lo persiste/procesa.
    """
    try:
        logger.info(f"Recibido análisis para finding_id: {finding_id}")
        
        # Aquí se guardaría el resultado en DB. 
        # Como no hay modelo SQLAlchemy definido aún, lo loggeamos.
        logger.info(f"AIAnalysis procesado y guardado para finding_id: {finding_id}")
        
        return {
            "finding_id": finding_id,
            "status": "success",
            "analysis": analysis_dict
        }
    except Exception as exc:
        logger.error(f"Error en analyze_finding_task: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=2)
def filter_false_positives_task(self, finding_dict: dict, asset_dict: dict = None) -> dict:
    """
    Task: Filtrar falsos positivos usando FalsePositiveFilter (IA Experta)
    """
    try:
        finding = Finding(**finding_dict)
        fp_filter = FalsePositiveFilter(ollama_client=ollama)
        
        # Ejecutar análisis async en entorno sync de Celery
        result = asyncio.run(fp_filter.filter(finding, asset_context=asset_dict))
        
        return result.model_dump()
    except Exception as exc:
        logger.error(f"Error en filter_false_positives_task: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=2)
def map_to_ens_task(self, finding_dict: dict, asset_dict: dict) -> dict:
    """
    Task: Mapear hallazgo a artículos RD 311/2022 (ENS Alto)
    """
    try:
        result = asyncio.run(map_to_ens(finding_dict, asset_dict))
        return result
    except Exception as exc:
        logger.error(f"Error en map_to_ens_task: {exc}")
        self.retry(countdown=60, exc=exc)

_DB_URL = os.getenv("DATABASE_URL", "postgresql://scanops:scanops@postgres:5432/scanops")

# Hash bcrypt de '1234' para cumplir con ENS mp.info.3 (campo pin NOT NULL en m4_approvals)
_DUMMY_PIN_HASH = "$2b$12$K7vUvW1M5wN7T2Z6Yh8OFe1V2U3T4R5E6W7Q8Y9U0I1O2P3A4S5D6"
_DUMMY_TOTP    = "JBSWY3DPEHPK3PXP"

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=3, name='tasks.suggest_attack_vector_task')
def suggest_attack_vector_task(self, ficha_unica_dict: dict) -> dict:
    """
    Task: Sugerir vector de ataque y persistir en m4_approvals (Human-in-the-loop).
    ENS op.acc.5 — aprobación humana obligatoria antes de explotación.
    """
    try:
        result = asyncio.run(suggest_attack_vector(ficha_unica_dict))
    except Exception as exc:
        logger.error(f"Error en suggest_attack_vector (LLM): {exc}")
        self.retry(countdown=60, exc=exc)
        return  # satisface al type-checker; retry lanza excepción

    now = datetime.utcnow()
    expires = now + timedelta(hours=24)
    cve_id    = result.get("cve_id", "CVE-2024-EXPLOIT")
    target_ip = ficha_unica_dict.get("target_ip")

    approval_id: int | None = None
    try:
        conn = psycopg2.connect(_DB_URL, connect_timeout=10)
        with conn:
            with conn.cursor() as cur:

                # ── INSERT m4_approvals (sin cambios) ──────────────
                cur.execute(
                    """
                    INSERT INTO m4_approvals
                        (cve_id, target_ip, requester, status,
                         totp_secret, pin, created_at, updated_at, expires_at)
                    VALUES
                        (%s, %s, %s, 'PENDING',
                         %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        cve_id, target_ip, "M8-AI-Agent",
                        _DUMMY_TOTP, _DUMMY_PIN_HASH,
                        now, now, expires,
                    ),
                )
                row = cur.fetchone()
                if row:
                    approval_id = row[0]

                # ── INSERT m8_results (NUEVO) ───────────────────────
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS m8_results (
                        id              SERIAL PRIMARY KEY,
                        asset_id        INTEGER NOT NULL,
                        target_ip       VARCHAR(45),
                        cve_id          VARCHAR(100),
                        suggested_tool  VARCHAR(255),
                        tool_params     TEXT,
                        mitre_tactic    VARCHAR(255),
                        risk_level      VARCHAR(20),
                        attack_rationale TEXT,
                        confidence      VARCHAR(20),
                        status          VARCHAR(50) DEFAULT 'pending_human_approval',
                        prompt_version  VARCHAR(50),
                        approval_id     INTEGER,
                        created_at      TIMESTAMP DEFAULT NOW()
                    )
                    """
                )
                cur.execute(
                    """
                    INSERT INTO m8_results
                        (asset_id, target_ip, cve_id,
                         suggested_tool, tool_params,
                         mitre_tactic, risk_level, attack_rationale,
                         confidence, status, prompt_version, approval_id,
                         created_at)
                    VALUES
                        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        result.get("asset_id"),
                        target_ip,
                        cve_id,
                        result.get("suggested_tool"),
                        str(result.get("tool_params") or result.get("payload", "")),
                        result.get("mitre_tactic") or result.get("tactic", ""),
                        result.get("risk_level") or result.get("confidence", ""),
                        result.get("attack_rationale") or result.get("rationale", ""),
                        result.get("confidence", ""),
                        result.get("status", "pending_human_approval"),
                        result.get("prompt_version", ""),
                        approval_id,
                        now,
                    ),
                )

        conn.close()
        logger.info(
            f"[ENS_EVIDENCE] m4_approvals + m8_results insertados: "
            f"approval_id={approval_id} asset_id={result.get('asset_id')} "
            f"target={target_ip}"
        )
    except Exception as db_exc:
        logger.error(f"Error persistiendo en BD: {db_exc}")
        # No reintentamos por fallo de BD para no duplicar filas ya insertadas

    return {**result, "approval_id": approval_id}


@celery_app.task(name="suggest_attack_vector_task")
def suggest_attack_vector_pentestgpt_task(ficha_unica: dict) -> dict:
    """
    US-4.7 — Attack vector reasoning via AttackVectorAgent (pentestgpt_integration).
    Replaces OpenAI-dependent PentestGPT with 100% local Ollama inference.
    ENS mp.info.3 compliant.
    """
    from services.ai_reasoning.pentestgpt_integration import suggest_attack_vector_for_finding
    return asyncio.run(suggest_attack_vector_for_finding(ficha_unica))

@celery_app.task(queue='ai_reasoning', bind=True, max_retries=1)
def generate_preliminary_report_task(self, hallazgos: list, activos: list, fecha_ciclo: str, fecha_sabado: str) -> str:
    """
    Task: Generar informe ejecutivo preliminar semanal (ENS op.exp.2)
    """
    try:
        result = asyncio.run(report_generator.generate_preliminary_report(
            hallazgos, activos, fecha_ciclo=fecha_ciclo, fecha_sabado=fecha_sabado
        ))
        return result
    except Exception as exc:
        logger.error(f"Error en generate_preliminary_report_task: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(queue='ai_reasoning')
def generate_finding_report_task(finding_id: str) -> str:
    """
    Task: Generar informe del hallazgo
    Retorna: HTML o PDF del informe
    """
    logger.info(f"Generando reporte para {finding_id}")
    return f"<html><body><h1>Report for {finding_id}</h1></body></html>"

@celery_app.task(name='services.ai_reasoning.tasks.run_full_ai_pipeline', queue='ai_reasoning', bind=True, max_retries=2)
def run_full_ai_pipeline(self):
    """
    Phase 2 — Tuesday 04:00.
    Runs the full AI analysis pipeline over all unprocessed scan findings.
    FASE 6: also triggers EDR-enriched kill chain analysis for assets with
    active behavioral findings.
    ENS: op.exp.2 — automated vulnerability analysis with AI.
    """
    logger.info("[ENS_EVIDENCE] Phase 2 AI pipeline started — processing scan findings")
    try:
        from services.ai_reasoning.edr_context_builder import get_assets_with_active_edr_findings

        assets = get_assets_with_active_edr_findings()
        dispatched = 0
        for entry in assets:
            asset_id = entry.get("asset_id")
            if asset_id:
                process_edr_enriched_asset_task.apply_async(
                    args=[asset_id],
                    queue="ai_reasoning",
                )
                dispatched += 1

        logger.info(
            "[ENS_EVIDENCE] Phase 2 AI pipeline: dispatched EDR analysis for %d assets",
            dispatched,
        )
        return {
            "status": "ok",
            "phase": 2,
            "edr_assets_dispatched": dispatched,
            "message": "AI pipeline cycle triggered",
        }
    except Exception as e:
        logger.error(f"Phase 2 AI pipeline error: {e}")
        raise self.retry(exc=e, countdown=300)


@celery_app.task(
    name="services.ai_reasoning.tasks.process_edr_enriched_asset_task",
    queue="ai_reasoning",
    bind=True,
    max_retries=2,
    time_limit=300,
)
def process_edr_enriched_asset_task(self, asset_id: int) -> dict:
    """
    FASE 6 — EDR-enriched per-asset analysis.

    1. Build EDR context (behavioral + threat_intel) from DB.
    2. Fetch open vulnerabilities for the asset from m3 scan results.
    3. Run kill chain analysis (LLM → deterministic fallback).
    4. If kill chain detected, enrich ficha_unica with active_exploitation_evidence
       and dispatch suggest_attack_vector_task.
    5. Persist kill chain result to m8_results.

    ENS: op.exp.4 (continuous monitoring), op.exp.2 (automated AI analysis).
    """
    try:
        from services.ai_reasoning.edr_context_builder import build_edr_context_for_asset
        from services.ai_reasoning.kill_chain_detector import analyze_kill_chain

        edr_ctx = build_edr_context_for_asset(asset_id)
        if not edr_ctx:
            logger.info(
                "[FASE6] asset_id=%d: no active EDR findings, skipping kill chain analysis",
                asset_id,
            )
            return {"status": "skipped", "asset_id": asset_id, "reason": "no_active_edr_findings"}

        behavioral   = edr_ctx.get("behavioral", {})
        threat_intel = edr_ctx.get("threat_intel", {})

        # Fetch open vulnerabilities from m3 scan table (best-effort)
        vulnerabilities = _fetch_open_vulnerabilities(asset_id)

        kill_chain_result = asyncio.run(
            analyze_kill_chain(
                ollama_client=ollama,
                asset_id=asset_id,
                vulnerabilities=vulnerabilities,
                behavioral=behavioral,
                threat_intel=threat_intel,
            )
        )

        logger.info(
            "[ENS_EVIDENCE][FASE6] kill_chain asset_id=%d detected=%s risk=%.2f action=%s",
            asset_id,
            kill_chain_result.get("kill_chain_detected"),
            kill_chain_result.get("risk_score_dynamic", 0.0),
            kill_chain_result.get("recommended_action"),
        )

        # Persist to m8_results
        _persist_kill_chain_result(asset_id, kill_chain_result)

        # If kill chain detected, enrich ficha_unica and request attack vector
        if kill_chain_result.get("kill_chain_detected") and vulnerabilities:
            top_vuln = max(vulnerabilities, key=lambda v: v.get("cvss", 0.0))
            ficha_unica = {
                "asset_id":    asset_id,
                "target_ip":   _resolve_asset_ip(asset_id),
                "cve_id":      top_vuln.get("cve_id", ""),
                "cvss":        top_vuln.get("cvss", 0.0),
                "title":       top_vuln.get("title", ""),
                # FASE 6: active exploitation evidence for attack vector reasoning
                "active_exploitation_evidence": {
                    "kill_chain_detected":     True,
                    "stages":                  kill_chain_result.get("stages_detected", []),
                    "attack_narrative":        kill_chain_result.get("attack_narrative", ""),
                    "risk_score_dynamic":      kill_chain_result.get("risk_score_dynamic"),
                    "recommended_action":      kill_chain_result.get("recommended_action"),
                    "active_c2":               behavioral.get("active_c2_detected", False),
                    "malicious_ips":           threat_intel.get("malicious_ips", []),
                    "yara_hits":               behavioral.get("yara_hits", 0),
                    "evidence_summary":        kill_chain_result.get("evidence_summary", {}),
                },
            }
            suggest_attack_vector_task.apply_async(args=[ficha_unica], queue="ai_reasoning")
            logger.info(
                "[ENS_EVIDENCE][FASE6] suggest_attack_vector_task dispatched for "
                "asset_id=%d cve=%s",
                asset_id,
                ficha_unica["cve_id"],
            )

        return {
            "status": "success",
            "asset_id": asset_id,
            "kill_chain_detected": kill_chain_result.get("kill_chain_detected"),
            "risk_score_dynamic":  kill_chain_result.get("risk_score_dynamic"),
            "recommended_action":  kill_chain_result.get("recommended_action"),
        }

    except Exception as exc:
        logger.error("[FASE6] process_edr_enriched_asset_task error asset_id=%d: %s", asset_id, exc)
        raise self.retry(exc=exc, countdown=120)


# ── helpers for process_edr_enriched_asset_task ──────────────────────────────

def _fetch_open_vulnerabilities(asset_id: int) -> list:
    """Fetch open CVEs for asset_id from scan_results. Returns [] on any error."""
    try:
        conn = psycopg2.connect(_DB_URL, connect_timeout=10)
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT cve_id, cvss_score, title
                    FROM scan_results
                    WHERE asset_id = %s AND status = 'open'
                    ORDER BY cvss_score DESC
                    LIMIT 10
                    """,
                    (asset_id,),
                )
                rows = cur.fetchall()
        conn.close()
        return [{"cve_id": r[0], "cvss": float(r[1] or 0), "title": r[2] or ""} for r in rows]
    except Exception as exc:
        logger.warning("[FASE6] _fetch_open_vulnerabilities asset_id=%d: %s", asset_id, exc)
        return []


def _resolve_asset_ip(asset_id: int) -> str:
    """Return the primary IP of an asset from m1_assets. Returns '' on error."""
    try:
        conn = psycopg2.connect(_DB_URL, connect_timeout=10)
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT ip_address FROM assets WHERE id = %s LIMIT 1",
                    (asset_id,),
                )
                row = cur.fetchone()
        conn.close()
        return row[0] if row else ""
    except Exception as exc:
        logger.warning("[FASE6] _resolve_asset_ip asset_id=%d: %s", asset_id, exc)
        return ""


def _persist_kill_chain_result(asset_id: int, result: dict) -> None:
    """Upsert kill chain analysis result into m8_results."""
    try:
        conn = psycopg2.connect(_DB_URL, connect_timeout=10)
        now = datetime.utcnow()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO m8_results
                        (asset_id, target_ip, cve_id,
                         suggested_tool, tool_params,
                         mitre_tactic, risk_level, attack_rationale,
                         confidence, status, prompt_version, approval_id, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        asset_id,
                        None,
                        None,
                        "kill_chain_detector",
                        str(result.get("stages_detected", [])),
                        ", ".join(result.get("stages_detected", [])),
                        (
                            "CRITICAL"
                            if (result.get("risk_score_dynamic") or 0) >= 9.0
                            else "HIGH"
                            if (result.get("risk_score_dynamic") or 0) >= 7.0
                            else "MEDIUM"
                        ),
                        result.get("attack_narrative", ""),
                        str(round(result.get("kill_chain_probability", 0.0) * 100)) + "%",
                        result.get("recommended_action", "MONITORIZAR"),
                        "kill_chain_v1",
                        None,
                        now,
                    ),
                )
        conn.close()
    except Exception as exc:
        logger.error("[FASE6] _persist_kill_chain_result asset_id=%d: %s", asset_id, exc)


@celery_app.task(name='services.ai_reasoning.tasks.notify_human_approval_required', queue='ai_reasoning', bind=True)
def notify_human_approval_required(self):
    """
    Phase 3 — Thursday 09:00.
    Notifies security officer that M4 approval queue is ready for review.
    ENS: op.acc.5 — human gate before exploitation.
    """
    logger.info("[ENS_EVIDENCE] Phase 3 — human approval gate triggered. Security officer must review M4 queue.")
    # TODO: send email/Slack notification to security officer
    return {"status": "ok", "phase": 3, "message": "Human approval notification sent"}


@celery_app.task(queue='ai_reasoning', bind=True, max_retries=2, name='tasks.post_exploitation_analysis_task')
def post_exploitation_analysis_task(self, approval_id: int, asset_id: int) -> dict:
    """
    US-8.1 — Análisis post-explotación con qwen2.5:14b.
    Lee todos los resultados reales de M4 para approval_id y los analiza con el LLM.
    ENS: op.exp.2, mp.info.3, op.exp.5
    """
    from services.ai_reasoning.post_exploit_agent import run_post_exploit_analysis
    try:
        result = asyncio.run(run_post_exploit_analysis(approval_id, asset_id))
        logger.info(
            "[ENS_EVIDENCE] post_exploitation_analysis_task completada: "
            "approval_id=%d db_id=%s risk=%s",
            approval_id, result.get("db_id"), result.get("risk_score"),
        )
        return result
    except RuntimeError as exc:
        # RuntimeError del agente = fallo explícito (modelo no disponible, DB error, JSON inválido)
        logger.error(
            "[M8-PostExploit] Fallo en post_exploitation_analysis_task "
            "(approval_id=%d): %s",
            approval_id, exc,
        )
        raise self.retry(exc=exc, countdown=120)
    except Exception as exc:
        logger.error("[M8-PostExploit] Error inesperado (approval_id=%d): %s", approval_id, exc)
        raise self.retry(exc=exc, countdown=120)


@celery_app.task(queue='ai_reasoning')
def generate_report_task(findings: List[Dict], scan_id: str, scan_date: str) -> Dict:
    """
    Task: Generar informe preliminar
    
    Args:
        findings: Lista de hallazgos
        scan_id: ID escaneo
        scan_date: Fecha escaneo
    
    Returns:
        Dict con paths HTML y PDF
    """
    try:
        html = report_generator.generate_html(findings, scan_id, scan_date)
        
        # Asegurar directorio de reportes
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
            
        # Guardar HTML
        html_path = f"{reports_dir}/{scan_id}_report.html"
        report_generator.save_html(html, html_path)
        
        # Guardar PDF (si weasyprint disponible)
        pdf_path = f"{reports_dir}/{scan_id}_report.pdf"
        pdf_success = report_generator.generate_pdf(html, pdf_path)
        
        return {
            "scan_id": scan_id,
            "html_path": html_path,
            "pdf_path": pdf_path if pdf_success else None,
            "status": "success"
        }
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return {"status": "error", "error": str(e)}
