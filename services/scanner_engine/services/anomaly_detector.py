"""
Anomaly Detector
================
Rule-based process anomaly detection engine for M3.1 EDR.
Matches running processes against malicious patterns inspired by SentinelONE's
behavioral heuristics, adapted for open-source tooling.

Detection categories and MITRE ATT&CK mappings:
  - C2 Callback          → TA0011 T1071.001
  - Data Exfiltration    → TA0010 T1048
  - Reverse Shell        → TA0002 T1059 T1071
  - Privilege Escalation → TA0004 T1548.003
  - Lateral Movement     → TA0008 T1021.004
  - Obfuscated Execution → TA0005 T1027 T1140
  - Persistence          → TA0003 T1053.003
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Dict, Pattern

from services.scanner_engine.clients.behavioral_ssh_client import ProcessInfo


# ── Result type ────────────────────────────────────────────────────────────────

@dataclass
class AnomalyResult:
    anomaly_type: str
    severity: str                       # CRITICAL / HIGH / MEDIUM / LOW
    confidence_score: int               # 0–100
    detection_method: str
    process: ProcessInfo
    indicators: List[str] = field(default_factory=list)
    mitre_attack_tactics: List[str] = field(default_factory=list)
    remediation_suggested: str = ""


# ── Detection patterns ─────────────────────────────────────────────────────────

_F = re.IGNORECASE

# C2 indicators
_C2_CURL       = re.compile(r'\bcurl\b.+(-X\s+(POST|PUT)|--data[^\s]*|-d\s+)', _F)
_C2_WGET       = re.compile(r'\bwget\b.+(--post-data|--post-file|-O\s+-)', _F)
_SUSP_DOMAIN   = re.compile(
    r'https?://[^\s]*\.(tk|ga|ml|cf|gq|pw|xyz|top|site|online|click|download|duckdns)\b',
    _F,
)
_PASTEBIN      = re.compile(
    r'(pastebin\.com|paste\.ee|hastebin\.com|dpaste\.com|rentry\.co|raw\.githubusercontent)',
    _F,
)

# Data exfiltration / reverse shell indicators
_DEVTCP        = re.compile(r'/dev/tcp/', _F)
_NC_LISTEN     = re.compile(r'\b(nc|ncat|netcat)\b.+(-l[vpn]*\b|-\blp\b|-lp\b)', _F)
_NC_CONNECT    = re.compile(r'\b(nc|ncat|netcat)\b.+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', _F)
_SOCAT         = re.compile(r'\bsocat\b.+(TCP|EXEC|PTY|GOPEN)', _F)
_RSYNC_EXFIL   = re.compile(r'\brsync\b.+@.+:', _F)

# Reverse shells (script-based)
_BASH_REVSHELL = re.compile(r'bash.+/dev/tcp|exec\s+\d+<>/dev/tcp', _F)
_PY_REVSHELL   = re.compile(r'python[23]?\s+-c.+socket\.(connect|bind)', _F)
_PERL_REVSHELL = re.compile(r'perl\s+-e.+socket', _F)
_PHP_REVSHELL  = re.compile(r'php\s+-r.+fsockopen', _F)

# Privilege escalation
_SUDO_S        = re.compile(r'\bsudo\s+-S\b', _F)
_SU_DASH       = re.compile(r'\bsu\s+-\b', _F)
_DOAS          = re.compile(r'\bdoas\b', _F)
_NOPASSWD      = re.compile(r'NOPASSWD', _F)
_SUID_FIND     = re.compile(r'\bfind\b.+-perm\s+-?/?[0-9]*[4][0-9]*', _F)

# Lateral movement
_SSH_WITH_KEY  = re.compile(r'\bssh\b.+-i\s+\S+.+@', _F)
_SCP_EXFIL     = re.compile(r'\bscp\b.+@.+:', _F)

# Obfuscated execution
_BASE64_PIPE   = re.compile(r'\bbase64\s+-d\b.*\|', _F)
_OPENSSL_DEC   = re.compile(r'\bopenssl\s+enc\b.*\s+-d\b', _F)

# Persistence
_CRONTAB_WRITE = re.compile(r'(crontab\s+-e|>\s*/etc/cron|echo.+>>.+bashrc)', _F)


# ── Rule table ─────────────────────────────────────────────────────────────────

_RULES: List[Dict] = [
    {
        "name": "C2_CALLBACK",
        "patterns": [_C2_CURL, _C2_WGET, _PASTEBIN, _SUSP_DOMAIN],
        "severity": "CRITICAL",
        "confidence_base": 75,
        "mitre": ["TA0011", "T1071.001"],
        "method": "c2_pattern",
        "remediation": (
            "Kill the process immediately (kill -9 <PID>). "
            "Block outbound traffic at firewall level. "
            "Audit with: ss -tupn | grep <PID> and check /proc/<PID>/net/tcp."
        ),
    },
    {
        "name": "DATA_EXFILTRATION",
        "patterns": [_NC_CONNECT, _SOCAT, _DEVTCP, _RSYNC_EXFIL],
        "severity": "CRITICAL",
        "confidence_base": 80,
        "mitre": ["TA0010", "T1048"],
        "method": "behavioral_heuristic",
        "remediation": (
            "Kill process and block the destination port at the firewall. "
            "Identify recently modified files: find / -newer /tmp -type f 2>/dev/null. "
            "Check /proc/<PID>/fd for open file descriptors."
        ),
    },
    {
        "name": "REVERSE_SHELL",
        "patterns": [_NC_LISTEN, _BASH_REVSHELL, _PY_REVSHELL, _PERL_REVSHELL, _PHP_REVSHELL],
        "severity": "CRITICAL",
        "confidence_base": 85,
        "mitre": ["TA0002", "T1059", "T1071"],
        "method": "behavioral_heuristic",
        "remediation": (
            "Kill process immediately. "
            "Search for dropped payloads: find /tmp /var/tmp /dev/shm -type f 2>/dev/null. "
            "Isolate host from network and collect memory dump."
        ),
    },
    {
        "name": "PRIVILEGE_ESCALATION",
        "patterns": [_SUDO_S, _SU_DASH, _DOAS, _NOPASSWD, _SUID_FIND],
        "severity": "HIGH",
        "confidence_base": 60,
        "mitre": ["TA0004", "T1548.003"],
        "method": "behavioral_heuristic",
        "remediation": (
            "Review /etc/sudoers and /etc/sudoers.d/* for unauthorized entries. "
            "Audit auth log: grep -i 'sudo\\|su' /var/log/auth.log | tail -50."
        ),
    },
    {
        "name": "LATERAL_MOVEMENT",
        "patterns": [_SSH_WITH_KEY, _SCP_EXFIL],
        "severity": "HIGH",
        "confidence_base": 65,
        "mitre": ["TA0008", "T1021.004"],
        "method": "behavioral_heuristic",
        "remediation": (
            "Revoke the SSH key referenced in the process arguments. "
            "Audit ~/.ssh/authorized_keys on all hosts. "
            "Check /var/log/auth.log for successful logins from this host."
        ),
    },
    {
        "name": "OBFUSCATED_EXECUTION",
        "patterns": [_BASE64_PIPE, _OPENSSL_DEC],
        "severity": "HIGH",
        "confidence_base": 70,
        "mitre": ["TA0005", "T1027", "T1140"],
        "method": "behavioral_heuristic",
        "remediation": (
            "Decode the payload manually for forensic analysis. "
            "Isolate host for full memory dump. "
            "Do not execute the decoded content without sandboxing."
        ),
    },
    {
        "name": "PERSISTENCE",
        "patterns": [_CRONTAB_WRITE],
        "severity": "MEDIUM",
        "confidence_base": 55,
        "mitre": ["TA0003", "T1053.003"],
        "method": "behavioral_heuristic",
        "remediation": (
            "Run: crontab -l -u <user> for all users. "
            "Inspect /etc/cron.d/, /etc/cron.daily/, /var/spool/cron/. "
            "Diff current crontabs against last known good backup."
        ),
    },
]


# ── Public API ─────────────────────────────────────────────────────────────────

def analyze_processes(processes: List[ProcessInfo]) -> List[AnomalyResult]:
    """
    Analyse a list of ProcessInfo objects against all detection rules.
    Returns one AnomalyResult per (process, rule) match — can return multiple
    results for the same process if it matches more than one rule.
    """
    results: List[AnomalyResult] = []

    for proc in processes:
        cmdline = proc.full_cmdline  # preserve case for indicators, use .lower() only for matching

        for rule in _RULES:
            matched_indicators: List[str] = []
            for pattern in rule["patterns"]:
                m = pattern.search(cmdline)
                if m:
                    matched_indicators.append(m.group(0)[:120])

            if not matched_indicators:
                continue

            confidence = _calculate_confidence(
                base=rule["confidence_base"],
                user=proc.user,
                indicator_count=len(matched_indicators),
            )

            results.append(AnomalyResult(
                anomaly_type=rule["name"],
                severity=rule["severity"],
                confidence_score=confidence,
                detection_method=rule["method"],
                process=proc,
                indicators=matched_indicators,
                mitre_attack_tactics=rule["mitre"],
                remediation_suggested=rule["remediation"],
            ))

    return results


def _calculate_confidence(base: int, user: str, indicator_count: int) -> int:
    """
    Adjust base confidence by context:
    - Root/system user → +15 pts (root-level C2 = near-certain malicious)
    - Each extra indicator hit → +10 pts (multiple signals = higher confidence)
    """
    score = base
    if user in ("root", "0", "daemon", "nobody"):
        score += 15
    if indicator_count > 1:
        score += 10 * (indicator_count - 1)
    return min(100, score)
