"""
Kill Chain Detector — M8 FASE 6
=================================
LLM-based kill chain analysis using behavioral EDR data + threat intel + CVEs.
Adds a dynamic risk score that multiplies CVSS by EDR evidence factors.

Called from:
  - run_full_ai_pipeline Celery task (batch, per-asset)
  - process_edr_enriched_asset_task (individual asset analysis)
  - StreamingProcessor.process_finding (finding-level annotation)

Output example:
  {
    "kill_chain_detected": True,
    "kill_chain_probability": 0.95,
    "stages_detected": ["Initial Access", "Execution", "C2"],
    "attack_narrative": "CVE-2021-44228 sin parche → Java spawn curl → POST evil.tk (CrowdSec MALICIOUS)",
    "risk_score_dynamic": 9.8,
    "recommended_action": "RECOMENDAR_APROBACION_M4_INMEDIATA",
    ...
  }
"""
from __future__ import annotations

import json
import logging
import os
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_YAML_PATH = Path(__file__).resolve().parent / "prompts" / "system_kill_chain.yaml"
_prompt_config: Optional[Dict] = None


def _load_prompt_config() -> Dict:
    global _prompt_config
    if _prompt_config is None:
        try:
            with open(_YAML_PATH, "r", encoding="utf-8") as f:
                _prompt_config = yaml.safe_load(f)
        except Exception as exc:
            logger.error("KILL_CHAIN_YAML_LOAD_ERROR", exc_info=exc)
            _prompt_config = {}
    return _prompt_config


async def analyze_kill_chain(
    ollama_client,
    asset_id: int,
    vulnerabilities: List[Dict],
    behavioral: Dict,
    threat_intel: Dict,
) -> Dict:
    """
    Run LLM kill chain analysis.  Falls back to deterministic scoring if Ollama is
    unavailable so the pipeline never blocks.

    Args:
        ollama_client: OllamaClient instance
        asset_id:      Asset being analysed
        vulnerabilities: List of vuln dicts with 'cve_id', 'cvss', 'title'
        behavioral:    EDR behavioral context (from edr_context_builder)
        threat_intel:  EDR threat intel context (from edr_context_builder)

    Returns:
        Kill chain analysis dict (matches system_kill_chain.yaml schema)
    """
    if not behavioral and not threat_intel:
        return _no_edr_result(asset_id, vulnerabilities)

    config = _load_prompt_config()

    # Build the user prompt
    user_prompt = _build_user_prompt(config, asset_id, vulnerabilities, behavioral, threat_intel)

    if not ollama_client or not await ollama_client.is_available():
        logger.warning("KILL_CHAIN_OLLAMA_UNAVAILABLE_fallback_deterministic", extra={"asset_id": asset_id})
        return _deterministic_analysis(asset_id, vulnerabilities, behavioral, threat_intel)

    try:
        response_text = await ollama_client.analyze(
            prompt=user_prompt,
            system_prompt=config.get("system", ""),
            temperature=config.get("temperature", 0.1),
            top_p=config.get("top_p", 0.9),
        )

        if not response_text:
            raise ValueError("Empty Ollama response")

        # Clean markdown fences
        clean = response_text.strip()
        for fence in ("```json", "```"):
            if fence in clean:
                clean = clean.split(fence)[1].split("```")[0].strip()
                break
        if "{" in clean and not clean.startswith("{"):
            clean = clean[clean.index("{"):]
        if "}" in clean and not clean.endswith("}"):
            clean = clean[:clean.rindex("}") + 1]

        result = json.loads(clean)
        result["asset_id"]  = asset_id
        result["llm_based"] = True
        logger.info(
            "KILL_CHAIN_ANALYSIS_DONE",
            extra={
                "asset_id": asset_id,
                "detected": result.get("kill_chain_detected"),
                "risk": result.get("risk_score_dynamic"),
                "action": result.get("recommended_action"),
            },
        )
        return result

    except Exception as exc:
        logger.error("KILL_CHAIN_LLM_ERROR", extra={"asset_id": asset_id, "error": str(exc)})
        return _deterministic_analysis(asset_id, vulnerabilities, behavioral, threat_intel)


# ── Deterministic fallback ─────────────────────────────────────────────────────

def _deterministic_analysis(
    asset_id: int,
    vulnerabilities: List[Dict],
    behavioral: Dict,
    threat_intel: Dict,
) -> Dict:
    """Rule-based kill chain detection and risk scoring when LLM is unavailable."""
    base_cvss = max((v.get("cvss", 0.0) for v in vulnerabilities), default=0.0)

    mult_c2 = 1.5  if behavioral.get("active_c2_detected")             else 1.0
    mult_ti = 1.4  if threat_intel.get("malicious_ips")                else 1.0
    mult_ya = 1.3  if behavioral.get("yara_hits", 0) > 0              else 1.0
    mult_pe = 1.2  if any(
        "PRIV" in (a.get("type") or "").upper()
        for a in behavioral.get("anomalies", [])
    ) else 1.0

    total_mult = min(2.0, mult_c2 * mult_ti * mult_ya * mult_pe)
    risk = round(min(10.0, base_cvss * total_mult), 2)

    # Kill chain: need C2 + at least one other phase
    anomaly_types = {(a.get("type") or "").upper() for a in behavioral.get("anomalies", [])}
    non_c2_phases = anomaly_types - {"C2_CALLBACK", "C2"}
    kill_chain = behavioral.get("active_c2_detected") and bool(non_c2_phases)

    stages: List[str] = []
    if kill_chain:
        stages = ["Execution", "C2"]
        if any("PRIV" in t for t in anomaly_types):
            stages.append("Privilege Escalation")
        if any("EXFIL" in t or "LATERAL" in t for t in anomaly_types):
            stages.append("Exfiltration" if "EXFIL" in anomaly_types else "Lateral Movement")

    if risk >= 9.0 and kill_chain:
        action = "RECOMENDAR_APROBACION_M4_INMEDIATA"
    elif risk >= 7.0 and kill_chain:
        action = "PROPONER_RESPUESTA_INCIDENTE_EDR"
    elif risk >= 5.0:
        action = "ESCALAR_A_CICLO_ACTUAL"
    else:
        action = "MONITORIZAR"

    return {
        "asset_id":                 asset_id,
        "kill_chain_detected":      kill_chain,
        "kill_chain_probability":   round(threat_intel.get("c2_confidence", 0.0), 2),
        "stages_detected":          stages,
        "attack_narrative":         (
            "Kill chain detected via behavioral EDR evidence (deterministic fallback)."
            if kill_chain else "No kill chain detected."
        ),
        "risk_score_dynamic":       risk,
        "risk_score_breakdown": {
            "base_cvss":               base_cvss,
            "c2_multiplier":           mult_c2,
            "threat_intel_multiplier": mult_ti,
            "yara_multiplier":         mult_ya,
            "final":                   risk,
        },
        "ens_compliance_risk":          ["op.exp.4", "op.exp.2"] if kill_chain else ["op.exp.2"],
        "recommended_action":           action,
        "recommended_action_rationale": f"Deterministic: base_cvss={base_cvss} × mult={total_mult:.2f} = {risk}",
        "evidence_summary": {
            "active_c2":                behavioral.get("active_c2_detected", False),
            "malicious_ips_count":      len(threat_intel.get("malicious_ips", [])),
            "yara_rules_matched":       [
                a.get("yara_match") for a in behavioral.get("anomalies", []) if a.get("yara_match")
            ],
            "highest_behavioral_severity": behavioral.get("severity", "INFO"),
        },
        "llm_based": False,
    }


def _no_edr_result(asset_id: int, vulnerabilities: List[Dict]) -> Dict:
    base_cvss = max((v.get("cvss", 0.0) for v in vulnerabilities), default=0.0)
    return {
        "asset_id":                asset_id,
        "kill_chain_detected":     False,
        "kill_chain_probability":  0.0,
        "stages_detected":         [],
        "attack_narrative":        "No EDR data available — analysis based on CVEs only.",
        "risk_score_dynamic":      base_cvss,
        "recommended_action":      "MONITORIZAR",
        "evidence_summary":        {"active_c2": False, "malicious_ips_count": 0},
        "llm_based": False,
    }


# ── Prompt builder ─────────────────────────────────────────────────────────────

def _build_user_prompt(
    config: Dict,
    asset_id: int,
    vulnerabilities: List[Dict],
    behavioral: Dict,
    threat_intel: Dict,
) -> str:
    template = config.get("user_template", "")

    vuln_lines = "\n".join(
        f"- {v.get('cve_id','?')} CVSS={v.get('cvss','?')} {v.get('title','')[:80]}"
        for v in (vulnerabilities or [])
    ) or "Sin vulnerabilidades conocidas"

    anomalies = behavioral.get("anomalies", [])
    anomaly_lines = "\n".join(
        f"  · [{a.get('severity','?')}] {a.get('type','?')} — proceso: {a.get('process','?')} "
        f"IP: {a.get('ip','N/A')} YARA: {a.get('yara_match','N/A')} "
        f"CrowdSec: {a.get('crowdsec','UNKNOWN')} Confianza: {a.get('confidence',0)}%"
        for a in anomalies[:10]
    ) or "Sin anomalías detectadas"

    try:
        return template.format(
            asset_id              = asset_id,
            vulnerabilities_summary = vuln_lines,
            behavioral_severity   = behavioral.get("severity", "INFO"),
            behavioral_total      = behavioral.get("total_findings", 0),
            active_c2             = behavioral.get("active_c2_detected", False),
            yara_hits             = behavioral.get("yara_hits", 0),
            anomalies_detail      = anomaly_lines,
            c2_confidence         = threat_intel.get("c2_confidence", 0.0),
            malicious_ips         = ", ".join(threat_intel.get("malicious_ips", [])) or "Ninguna",
            compromised_domains   = ", ".join(threat_intel.get("compromised_domains", [])) or "Ninguno",
            data_exfil            = threat_intel.get("data_exfil_detected", False),
        )
    except KeyError as e:
        logger.warning("KILL_CHAIN_TEMPLATE_KEY_ERROR", extra={"key": str(e)})
        return f"Asset {asset_id}: {anomaly_lines}"
