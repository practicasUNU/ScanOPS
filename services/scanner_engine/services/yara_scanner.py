"""
YARA Scanner — M3.1 FASE 4
============================
Compiles edr_rules.yar and scans process command lines against it.
Compiled rules are a module-level singleton (compile once, scan many).
If yara-python is not installed, all public functions degrade gracefully
and return empty results — behavioral detection still runs.

ENS op.exp.4: pattern-matching complement to behavioral heuristics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import yara as _yara
    _YARA_AVAILABLE = True
except ImportError:
    _yara = None  # type: ignore
    _YARA_AVAILABLE = False

from services.scanner_engine.clients.behavioral_ssh_client import ProcessInfo
from shared.scan_logger import ScanLogger

logger = ScanLogger("yara_scanner")

_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "edr_rules.yar"

# Compiled rules — initialized lazily on first scan call
_compiled: Optional[object] = None
_compile_failed: bool = False

# Severity rank for comparison
_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEV_ESCALATE = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass
class YaraMatch:
    rule_name:   str
    severity:    str   # from rule meta
    mitre:       str   # from rule meta
    family:      str   # from rule meta
    description: str   # from rule meta
    matched_strings: List[str] = field(default_factory=list)


# ── Compile ────────────────────────────────────────────────────────────────────

def _get_compiled():
    global _compiled, _compile_failed
    if not _YARA_AVAILABLE or _compile_failed:
        return None
    if _compiled is not None:
        return _compiled
    try:
        _compiled = _yara.compile(filepath=str(_RULES_PATH))
        logger.info("YARA_RULES_COMPILED", path=str(_RULES_PATH))
        return _compiled
    except Exception as exc:
        _compile_failed = True
        logger.error("YARA_COMPILE_FAILED", path=str(_RULES_PATH), error=str(exc))
        return None


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_cmdline(cmdline: str) -> List[YaraMatch]:
    """Scan a single command line string against all EDR YARA rules."""
    rules = _get_compiled()
    if rules is None or not cmdline.strip():
        return []

    try:
        raw_matches = rules.match(data=cmdline.encode("utf-8", errors="replace"))
    except Exception as exc:
        logger.warning("YARA_MATCH_ERROR", error=str(exc))
        return []

    results: List[YaraMatch] = []
    for m in raw_matches:
        meta = m.meta if hasattr(m, "meta") else {}
        # Collect matched string fragments (YARA 4.x returns a list of tuples)
        frags: List[str] = []
        for hit in (m.strings if hasattr(m, "strings") else []):
            try:
                # hit is (offset, identifier, data) in yara-python 4.x
                frags.append(hit[1] if isinstance(hit, tuple) else str(hit))
            except Exception:
                pass

        results.append(YaraMatch(
            rule_name        = m.rule,
            severity         = meta.get("severity", "MEDIUM"),
            mitre            = meta.get("mitre", ""),
            family           = meta.get("family", ""),
            description      = meta.get("description", ""),
            matched_strings  = frags[:10],  # cap at 10 to avoid bloat
        ))

    return results


def merge_yara_with_anomalies(
    processes: List[ProcessInfo],
    behavioral_anomalies: list,  # List[AnomalyResult] — avoid circular import
) -> list:
    """
    Run YARA over each process cmdline and merge results with behavioral findings.

    Two outcomes:
    1. Process already has behavioral finding → boost confidence + escalate severity
       if YARA severity >= behavioral severity.  detection_method → "behavioral_heuristic+yara"
    2. Process has YARA match but no behavioral finding → create new AnomalyResult
       with anomaly_type YARA_MATCH.  detection_method → "yara"
    """
    if not _YARA_AVAILABLE or _get_compiled() is None:
        return behavioral_anomalies

    # Import here to avoid circular dep at module level
    from services.scanner_engine.services.anomaly_detector import AnomalyResult

    # PID → list index in behavioral_anomalies for fast lookup
    pid_to_indices: dict[int, List[int]] = {}
    for idx, a in enumerate(behavioral_anomalies):
        pid_to_indices.setdefault(a.process.pid, []).append(idx)

    extra: List[AnomalyResult] = []
    # Work on a copy so we can mutate safely
    result = list(behavioral_anomalies)

    for proc in processes:
        cmdline = proc.full_cmdline
        if not cmdline.strip():
            continue

        matches = scan_cmdline(cmdline)
        if not matches:
            continue

        # Pick the most severe YARA match
        top = max(matches, key=lambda m: _SEV_RANK.get(m.severity, 0))
        yara_indicators = [f"YARA:{m.rule_name}" for m in matches]
        yara_mitre = [m.mitre for m in matches if m.mitre]

        if proc.pid in pid_to_indices:
            # Augment every existing behavioral finding for this PID
            for idx in pid_to_indices[proc.pid]:
                existing = result[idx]
                beh_rank  = _SEV_RANK.get(existing.severity, 0)
                yara_rank = _SEV_RANK.get(top.severity, 0)

                # Escalate if YARA is higher, or if both agree at >= HIGH
                if yara_rank > beh_rank:
                    existing.severity = top.severity
                elif beh_rank >= 3 and yara_rank >= 3:   # both HIGH or CRITICAL
                    existing.severity = "CRITICAL"
                elif beh_rank >= 2 and yara_rank >= 2:   # both MEDIUM+
                    existing.severity = _SEV_ESCALATE.get(existing.severity, existing.severity)

                # Confidence boost: +20 capped at 100
                existing.confidence_score = min(100, existing.confidence_score + 20)

                # Merge indicators and MITRE tactics
                existing.indicators = list(set(existing.indicators + yara_indicators))
                existing.mitre_attack_tactics = list(
                    set(existing.mitre_attack_tactics + yara_mitre)
                )
                existing.detection_method = "behavioral_heuristic+yara"

            logger.info(
                "YARA_AUGMENTED_BEHAVIORAL",
                pid=proc.pid,
                rules=[m.rule_name for m in matches],
            )
        else:
            # No behavioral match — new YARA-only finding
            new_finding = AnomalyResult(
                anomaly_type        = "YARA_MATCH",
                severity            = top.severity,
                confidence_score    = 75,   # YARA match alone = good signal
                detection_method    = "yara",
                process             = proc,
                indicators          = yara_indicators,
                mitre_attack_tactics = yara_mitre,
                remediation_suggested = (
                    f"YARA rules triggered: {', '.join(m.rule_name for m in matches)}. "
                    f"Investigate process PID {proc.pid} ({proc.command}). "
                    "Check for dropped files in /tmp, /var/tmp, /dev/shm."
                ),
            )
            extra.append(new_finding)
            logger.info(
                "YARA_NEW_FINDING",
                pid=proc.pid,
                rules=[m.rule_name for m in matches],
                severity=top.severity,
            )

    return result + extra
