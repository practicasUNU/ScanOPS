"""
Behavioral SSH Client
======================
Read-only SSH connection to target hosts.
Collects live process data using ps(1) — no agents required, no writes to target.
ENS Alto op.exp.4: passive observation only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import paramiko


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    user: str
    cpu_percent: float
    mem_percent: float
    command: str
    args: str

    @property
    def full_cmdline(self) -> str:
        return f"{self.command} {self.args}".strip()


class BehavioralSSHClient:
    """
    Thin read-only SSH client for behavioral process collection.
    Supports password or RSA/ED25519 key authentication.
    Use as a context manager to guarantee disconnection.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
        timeout: int = 15,
    ):
        if not password and not key_path:
            raise ValueError("Either password or key_path must be provided")
        self.host = host
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port = port
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    # ── Connection ─────────────────────────────────────────────────────────

    def connect(self) -> None:
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = dict(
            hostname=self.host,
            port=self.port,
            username=self.username,
            timeout=self.timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        if self.key_path:
            kwargs["key_filename"] = self.key_path
        else:
            kwargs["password"] = self.password
        self._client.connect(**kwargs)

    def disconnect(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def __enter__(self) -> "BehavioralSSHClient":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ── Remote execution ───────────────────────────────────────────────────

    def exec(self, command: str, timeout: int = 30) -> str:
        if not self._client:
            raise RuntimeError("Not connected — call connect() first")
        _, stdout, _ = self._client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")

    # ── Process collection ─────────────────────────────────────────────────

    def get_processes(self) -> List[ProcessInfo]:
        """
        Execute ps and return structured process list.
        Tries POSIX extended format first; falls back to BSD (ps aux).
        Read-only: no data is written to the remote host.
        """
        output = self.exec(
            "ps -eo pid,ppid,user,pcpu,pmem,args --no-headers 2>/dev/null "
            "|| ps aux 2>/dev/null"
        )
        return parse_ps_output(output)

    def get_open_connections(self) -> str:
        """Collect active network connections (read-only)."""
        return self.exec("ss -tupn 2>/dev/null || netstat -tupn 2>/dev/null || echo ''")

    def get_listening_ports(self) -> str:
        """Collect listening ports (read-only)."""
        return self.exec("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo ''")


# ── Parser ─────────────────────────────────────────────────────────────────────

def parse_ps_output(raw: str) -> List[ProcessInfo]:
    """
    Parse both `ps -eo pid,ppid,user,pcpu,pmem,args` and `ps aux` output.
    Malformed lines are skipped silently.
    """
    processes: List[ProcessInfo] = []

    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip header lines
        if line.upper().startswith(("USER", "PID", "UID")):
            continue

        parts = line.split(None, 6)
        if len(parts) < 5:
            continue

        try:
            if _is_float(parts[2]):
                # ps aux layout: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
                fields = line.split(None, 10)
                pid  = int(fields[1])
                ppid = 0
                user = fields[0]
                cpu  = float(fields[2])
                mem  = float(fields[3])
                full = fields[10] if len(fields) > 10 else ""
            else:
                # ps -eo layout: PID PPID USER %CPU %MEM ARGS
                fields = line.split(None, 5)
                pid  = int(fields[0])
                ppid = int(fields[1])
                user = fields[2]
                cpu  = float(fields[3])
                mem  = float(fields[4])
                full = fields[5] if len(fields) > 5 else ""

            cmd_parts = full.split(None, 1)
            cmd  = cmd_parts[0] if cmd_parts else ""
            args = cmd_parts[1] if len(cmd_parts) > 1 else ""

            processes.append(ProcessInfo(
                pid=pid, ppid=ppid, user=user,
                cpu_percent=cpu, mem_percent=mem,
                command=cmd, args=args,
            ))
        except (ValueError, IndexError):
            continue

    return processes


def _is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False
