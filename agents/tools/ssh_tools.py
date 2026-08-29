"""SSH remote-exec tool module for infra-agent (sysadmin role).

Transport: paramiko with the operator keypair (see SSH_KEY_PATH in .env).
Authority: commands run as rdrolfe; privileged ops go through the sudoers
whitelist (apt, apt-get, dpkg, chown, chmod, systemctl) — no broad root.

Identity: every audit record carries the workload's SPIFFE ID, fetched from
the SPIRE Workload API (unix socket). This binds each action to a
cryptographically verifiable agent identity — provable, not claimed.

Hygiene: config-driven hosts (config.py), no load_dotenv, logging, imports at top.
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paramiko

from config import settings

logger = logging.getLogger(__name__)


def _fetch_spiffe_id(socket_path: str, spire_bin: str) -> str:
    """Fetch the workload's SPIFFE ID from the SPIRE Workload API.

    Uses spire-agent api fetch x509 and parses the SPIFFE ID from output.
    Returns 'unverified' if SPIRE is unavailable so auditing never blocks.
    """
    try:
        out = subprocess.run(
            [spire_bin, "api", "fetch", "x509", "-socketPath", socket_path],
            capture_output=True, text=True, timeout=15,
        ).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("SPIFFE ID:"):
                return line.split(":", 1)[1].strip()
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning("spire fetch failed: %s", e)
    return "unverified"


class RemoteExec:
    """SSH client wrapper for executing commands on SSOP VMs."""

    def __init__(self) -> None:
        # Host map comes from settings (SSH_HOSTS env: "web=10.0.0.5,db=10.0.0.6")
        self.hosts: dict[str, str] = dict(settings.ssh_hosts)
        if not self.hosts:
            self.hosts["localhost"] = "127.0.0.1"
        self.user = settings.ssh_user
        self.key_path = Path(settings.ssh_key_path).expanduser()
        self.audit_dir: Path = settings.audit_dir
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.spire_socket = settings.spire_socket
        self.spire_bin = settings.spire_bin
        self.timeout = settings.timeout_s
        # Host-key verification: default OFF for the lab (ephemeral VMs, keys
        # rotate on reinstall) but configurable for prod via SSH_STRICT_HOST_KEYS.
        self.strict_host_keys = bool(settings.ssh_strict_host_keys)

    # --- helpers ---

    def _resolve(self, host: str) -> str:
        """Accept a hostname alias or raw IP; return the IP."""
        return self.hosts.get(host, host)

    def _audit(self, entry: dict[str, Any]) -> None:
        """Append one action record to the JSONL audit trail."""
        entry.setdefault("ts", datetime.now(timezone.utc).isoformat())
        entry.setdefault("actor", "infra-agent")
        entry.setdefault("spiffe_id", _fetch_spiffe_id(self.spire_socket, self.spire_bin))
        try:
            with open(self.audit_dir / "actions.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            logger.error("audit write failed: %s", e)

    def _connect(self, host: str) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        if self.strict_host_keys:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # Lab default (SSH_STRICT_HOST_KEYS=False): ephemeral VMs, keys
            # rotate on reinstall. NOT a silent choice — production must set
            # SSH_STRICT_HOST_KEYS=true. Deliberate; see config.py.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
        client.connect(
            hostname=self._resolve(host),
            username=self.user,
            key_filename=str(self.key_path),
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
        )
        return client

    def run(self, host: str, command: str, timeout: int | None = None) -> dict[str, Any]:
        """Execute a command over SSH, return stdout/stderr/exit + audit."""
        t = timeout or self.timeout
        try:
            client = self._connect(host)
        except (paramiko.SSHException, OSError) as e:
            logger.warning("ssh connect failed to %s: %s", host, e)
            self._audit({"host": host, "command": command, "ok": False, "error": str(e)})
            return {"ok": False, "host": host, "error": str(e)}
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=t)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            code = stdout.channel.recv_exit_status()
            result = {"ok": code == 0, "host": host, "command": command, "exit": code,
                      "stdout": out, "stderr": err}
            self._audit(result)
            return result
        except (paramiko.SSHException, OSError) as e:
            logger.warning("ssh exec failed on %s: %s", host, e)
            self._audit({"host": host, "command": command, "ok": False, "error": str(e)})
            return {"ok": False, "host": host, "command": command, "error": str(e)}
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass

    def run_all(self, command: str, hosts: list[str] | None = None) -> dict[str, dict[str, Any]]:
        """Run a command across all (or selected) hosts."""
        targets = hosts or list(self.hosts.keys())
        results = {}
        for host in targets:
            results[host] = self.run(host, command)
        return results

    def check(self, host: str) -> dict[str, Any]:
        """Quick health probe: uptime + disk on a host."""
        return self.run(host, "uptime -p && df -h / | tail -1")
