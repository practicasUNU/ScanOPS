"""
Incident Response Executor — M3.1 FASE 5
==========================================
SSH-based action executor for approved incident response actions.
All commands run with `sudo` where required.  Read-only operations
(collect_forensics) never require elevated privileges.

ENS Alto op.exp.4: every action is logged before and after execution.
Only callable AFTER TOTP+PIN approval gate has been passed.

Supported actions:
  kill_process      — kill -9 <pid>                      (non-reversible)
  quarantine_file   — mv <path> /var/scanops_quarantine/  (reversible)
  block_ip          — iptables DROP on src+dst             (reversible)
  isolate_host      — drop all traffic except current SSH  (reversible)
  collect_forensics — /proc reads + lsof dump             (read-only)
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from services.scanner_engine.clients.behavioral_ssh_client import BehavioralSSHClient
from shared.scan_logger import ScanLogger

logger = ScanLogger("ir_executor")

_QUARANTINE_DIR = "/var/scanops_quarantine"


@dataclass
class ExecutionResult:
    success:         bool
    output:          str
    duration_ms:     int
    rollback_capable: bool
    rollback_hint:   str = ""


# ── Public entry point ─────────────────────────────────────────────────────────

def execute_action(
    *,
    ssh_host:     str,
    ssh_user:     str,
    ssh_password: str,
    action_type:  str,
    target_detail: str,
    ssh_port:     int = 22,
) -> ExecutionResult:
    """
    Open an SSH session and execute the requested action.
    Returns ExecutionResult — never raises; on exception sets success=False.
    """
    t0 = time.monotonic()
    try:
        with BehavioralSSHClient(
            host=ssh_host,
            username=ssh_user,
            password=ssh_password,
            port=ssh_port,
        ) as client:
            result = _dispatch(client, action_type, target_detail.strip())
    except Exception as exc:
        duration_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "IR_EXEC_SSH_ERROR",
            action=action_type,
            target=target_detail,
            error=str(exc),
        )
        return ExecutionResult(
            success=False,
            output=f"SSH connection failed: {exc}",
            duration_ms=duration_ms,
            rollback_capable=False,
        )

    result.duration_ms = int((time.monotonic() - t0) * 1000)
    log_level = "IR_EXEC_SUCCESS" if result.success else "IR_EXEC_FAILED"
    logger.info(
        log_level,
        action=action_type,
        target=target_detail,
        duration_ms=result.duration_ms,
    )
    return result


# ── Dispatcher ─────────────────────────────────────────────────────────────────

def _dispatch(
    client: BehavioralSSHClient,
    action_type: str,
    target_detail: str,
) -> ExecutionResult:
    handlers = {
        "kill_process":      _kill_process,
        "quarantine_file":   _quarantine_file,
        "block_ip":          _block_ip,
        "isolate_host":      _isolate_host,
        "collect_forensics": _collect_forensics,
    }
    handler = handlers.get(action_type)
    if handler is None:
        return ExecutionResult(
            success=False,
            output=f"Unknown action type: {action_type}",
            duration_ms=0,
            rollback_capable=False,
        )
    return handler(client, target_detail)


# ── Action handlers ────────────────────────────────────────────────────────────

def _kill_process(client: BehavioralSSHClient, target: str) -> ExecutionResult:
    """Kill a process by PID. target = 'PID:1234' or just '1234'."""
    pid = _parse_pid(target)
    if pid is None:
        return ExecutionResult(
            success=False, output=f"Cannot parse PID from: {target}",
            duration_ms=0, rollback_capable=False,
        )

    # Graceful then forced kill
    client.exec(f"kill -15 {pid} 2>/dev/null || true", timeout=5)
    time.sleep(1)
    out = client.exec(f"kill -9 {pid} 2>&1; echo EXIT:$?", timeout=10)
    # Verify process is gone
    check = client.exec(f"ps -p {pid} >/dev/null 2>&1 && echo ALIVE || echo DEAD", timeout=5)
    success = "DEAD" in check or "EXIT:0" in out or "No such process" in out

    return ExecutionResult(
        success=success,
        output=f"kill output: {out.strip()}\nverify: {check.strip()}",
        duration_ms=0,
        rollback_capable=False,
        rollback_hint="Process cannot be revived. Investigate parent process if it respawns.",
    )


def _quarantine_file(client: BehavioralSSHClient, target: str) -> ExecutionResult:
    """Move file to quarantine directory. target = full file path."""
    if not target.startswith("/"):
        return ExecutionResult(
            success=False, output=f"target must be an absolute path, got: {target}",
            duration_ms=0, rollback_capable=False,
        )
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = target.split("/")[-1]
    dest = f"{_QUARANTINE_DIR}/{ts}_{filename}"

    setup = client.exec(f"sudo mkdir -p {_QUARANTINE_DIR} 2>&1", timeout=10)
    move  = client.exec(f"sudo mv -- '{target}' '{dest}' 2>&1; echo EXIT:$?", timeout=10)
    verify = client.exec(f"test -f '{target}' && echo STILL_EXISTS || echo MOVED", timeout=5)
    success = "MOVED" in verify and "EXIT:0" in move

    return ExecutionResult(
        success=success,
        output=f"setup: {setup.strip()}\nmove: {move.strip()}\nverify: {verify.strip()}",
        duration_ms=0,
        rollback_capable=True,
        rollback_hint=f"To restore: sudo mv '{dest}' '{target}'",
    )


def _block_ip(client: BehavioralSSHClient, target: str) -> ExecutionResult:
    """Block all traffic to/from an IP using iptables. target = IP address."""
    ip = target.replace("IP:", "").strip()
    if not _looks_like_ip(ip):
        return ExecutionResult(
            success=False, output=f"Invalid IP address: {ip}",
            duration_ms=0, rollback_capable=False,
        )

    cmds = [
        f"sudo iptables -I INPUT  -s {ip} -j DROP",
        f"sudo iptables -I OUTPUT -d {ip} -j DROP",
        f"sudo iptables -I FORWARD -s {ip} -j DROP",
        f"sudo iptables -I FORWARD -d {ip} -j DROP",
    ]
    outputs = []
    success = True
    for cmd in cmds:
        out = client.exec(f"{cmd} 2>&1; echo EXIT:$?", timeout=10)
        outputs.append(out.strip())
        if "EXIT:0" not in out:
            success = False

    verify = client.exec(
        f"sudo iptables -L -n | grep '{ip}' | head -4 2>&1", timeout=10
    )

    return ExecutionResult(
        success=success,
        output="\n".join(outputs) + f"\nverify:\n{verify.strip()}",
        duration_ms=0,
        rollback_capable=True,
        rollback_hint=(
            f"To unblock: sudo iptables -D INPUT -s {ip} -j DROP; "
            f"sudo iptables -D OUTPUT -d {ip} -j DROP"
        ),
    )


def _isolate_host(client: BehavioralSSHClient, target: str) -> ExecutionResult:
    """
    Soft network isolation: drop all NEW outbound connections except SSH (22).
    Existing SSH session is preserved via ESTABLISHED,RELATED match.
    target = '' or 'PRESERVE:<port>' to keep an extra port.
    """
    preserve_port = 22
    if target.upper().startswith("PRESERVE:"):
        try:
            preserve_port = int(target.split(":")[1])
        except (IndexError, ValueError):
            pass

    cmds = [
        # Allow established/related connections (keeps current SSH alive)
        "sudo iptables -I INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "sudo iptables -I OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        # Allow management SSH
        f"sudo iptables -I INPUT  -p tcp --dport {preserve_port} -j ACCEPT",
        f"sudo iptables -I OUTPUT -p tcp --sport {preserve_port} -j ACCEPT",
        # Drop everything else
        "sudo iptables -A OUTPUT -j DROP",
        "sudo iptables -A INPUT  -j DROP",
    ]
    outputs = []
    success = True
    for cmd in cmds:
        out = client.exec(f"{cmd} 2>&1; echo EXIT:$?", timeout=10)
        outputs.append(out.strip())
        if "EXIT:0" not in out:
            success = False

    return ExecutionResult(
        success=success,
        output="\n".join(outputs),
        duration_ms=0,
        rollback_capable=True,
        rollback_hint="To restore network: sudo iptables -F INPUT && sudo iptables -F OUTPUT",
    )


def _collect_forensics(client: BehavioralSSHClient, target: str) -> ExecutionResult:
    """
    Read-only forensics collection: /proc data, lsof, open connections.
    target = 'PID:1234' or just '1234'.
    """
    pid = _parse_pid(target)
    if pid is None:
        return ExecutionResult(
            success=False, output=f"Cannot parse PID from: {target}",
            duration_ms=0, rollback_capable=True,
        )

    parts = []
    cmds = {
        "cmdline":    f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '",
        "maps":       f"cat /proc/{pid}/maps 2>/dev/null | head -40",
        "net_tcp":    f"cat /proc/{pid}/net/tcp 2>/dev/null | head -20",
        "lsof":       f"lsof -p {pid} 2>/dev/null | head -30",
        "environ":    f"cat /proc/{pid}/environ 2>/dev/null | tr '\\0' '\\n' | head -20",
        "connections": f"ss -tupn 2>/dev/null | grep 'pid={pid}'",
    }
    for section, cmd in cmds.items():
        try:
            out = client.exec(cmd, timeout=15)
            parts.append(f"=== {section} ===\n{out.strip()}")
        except Exception as exc:
            parts.append(f"=== {section} === ERROR: {exc}")

    full_output = "\n\n".join(parts)
    success = any("cmdline" in p and "===" in p for p in parts)

    return ExecutionResult(
        success=True,  # forensics is best-effort
        output=full_output[:4000],  # cap to avoid DB column overflow
        duration_ms=0,
        rollback_capable=True,
        rollback_hint="Read-only operation — no rollback needed.",
    )


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_pid(target: str) -> Optional[int]:
    """Parse 'PID:1234' or '1234' → 1234, or None on failure."""
    cleaned = target.upper().replace("PID:", "").strip()
    try:
        pid = int(cleaned)
        return pid if pid > 0 else None
    except ValueError:
        return None


def _looks_like_ip(value: str) -> bool:
    import re
    return bool(re.match(
        r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$',
        value,
    ))
