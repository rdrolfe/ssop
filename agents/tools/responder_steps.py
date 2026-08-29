"""SOAR responder step registry — named, reusable playbook actions.

Steps are invoked BY NAME from playbook YAML (the step library per the
playbook-schema decision). Params come from the playbook; env/paths/creds
resolve from config.py (never hardcoded in playbooks).

P1 registry (whitelisted actions): service_stop, service_restart,
host_quarantine, disk_clean, verify_service_state, verify_firewall_rule.
firewall_block_ip + config_revert are DESIGNED (schema) but require the
sudoers whitelist extension — they are registered as NOT_IMPLEMENTED and
fail-fast with a clear message until the manifest grows.

Hygiene: config-driven, registry singletons, logging, exception discipline.
"""

from __future__ import annotations

from typing import Any

from logging_setup import get_logger
from tools.registry import get_ssh

logger = get_logger(__name__)


class StepError(RuntimeError):
    """Raised when a playbook step fails."""


class StepResult:
    """Outcome of a single step execution."""

    def __init__(self, ok: bool, detail: str, step: str = "") -> None:
        self.ok = ok
        self.detail = detail
        self.step = step

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.step, "ok": self.ok, "detail": self.detail}


# ---------------------------------------------------------------------------
# P1 step implementations
# ---------------------------------------------------------------------------

def _ssh_run(host: str, command: str, timeout_s: int = 60) -> str:
    """Run a command on a host via the SSH singleton (paramiko)."""
    ssh = get_ssh()
    result = ssh.run(host=host, command=command, timeout=timeout_s)
    if not result.get("ok"):
        raise StepError(f"ssh {host}: {result.get('error', 'unknown error')}")
    return result.get("stdout", "")


def step_service_stop(host: str, service: str, timeout_s: int = 60) -> StepResult:
    """Stop a service on a host (systemctl, whitelisted)."""
    try:
        _ssh_run(host, f"sudo -n systemctl stop {service}", timeout_s)
        return StepResult(True, f"service {service} stopped on {host}", "service_stop")
    except StepError as e:
        logger.error("service_stop %s/%s failed: %s", host, service, e)
        return StepResult(False, str(e), "service_stop")


def step_service_restart(host: str, service: str, timeout_s: int = 60) -> StepResult:
    """Restart a service on a host (systemctl, whitelisted)."""
    try:
        _ssh_run(host, f"sudo -n systemctl restart {service}", timeout_s)
        return StepResult(True, f"service {service} restarted on {host}", "service_restart")
    except StepError as e:
        logger.error("service_restart %s/%s failed: %s", host, service, e)
        return StepResult(False, str(e), "service_restart")


def step_host_quarantine(host: str, services: list[str], timeout_s: int = 120) -> StepResult:
    """Isolate a host by stopping its critical services (systemctl, whitelisted)."""
    stopped = []
    for svc in services:
        r = step_service_stop(host, svc, timeout_s)
        if not r.ok:
            return StepResult(False, f"quarantine failed stopping {svc}: {r.detail}", "host_quarantine")
        stopped.append(svc)
    return StepResult(True, f"host {host} quarantined (stopped: {', '.join(stopped)})", "host_quarantine")


def step_disk_clean(host: str, timeout_s: int = 120) -> StepResult:
    """Free disk via the existing heal path (journald vacuum, apt clean, docker prune)."""
    try:
        _ssh_run(host, "sudo -n journalctl --vacuum-size=200M 2>/dev/null; sudo -n apt-get clean 2>/dev/null; docker image prune -f 2>/dev/null || true", timeout_s)
        return StepResult(True, f"disk clean run on {host}", "disk_clean")
    except StepError as e:
        logger.error("disk_clean %s failed: %s", host, e)
        return StepResult(False, str(e), "disk_clean")


def step_verify_service_state(host: str, service: str, expected: str = "active", timeout_s: int = 30) -> StepResult:
    """Verify a service state (read-only, tier0)."""
    try:
        out = _ssh_run(host, f"systemctl is-active {service}", timeout_s)
        ok = out.strip() == expected
        return StepResult(ok, f"service {service} on {host} is {out.strip()}", "verify_service_state")
    except StepError as e:
        return StepResult(False, str(e), "verify_service_state")


def step_verify_firewall_rule(host: str, src_ip: str, timeout_s: int = 30) -> StepResult:
    """Verify a firewall rule is present (read-only, tier0)."""
    try:
        out = _ssh_run(host, f"sudo -n /usr/sbin/iptables -L INPUT -n 2>/dev/null | grep {src_ip} || echo NOT_PRESENT", timeout_s)
        ok = "NOT_PRESENT" not in out
        return StepResult(ok, f"firewall rule for {src_ip} on {host}: {'present' if ok else 'absent'}", "verify_firewall_rule")
    except StepError as e:
        return StepResult(False, str(e), "verify_firewall_rule")


# ---------------------------------------------------------------------------
# Containment actions (sudoers extended for these)
# ---------------------------------------------------------------------------

def step_firewall_block_ip(host: str, src_ip: str, ttl_s: int = 3600) -> StepResult:
    """Block a source IP at the host firewall (iptables, whitelisted).

    sudoers allows ONLY: iptables -I INPUT -s <ip> -j DROP (and -D to
    unblock). The block is the containment action; ttl_s is advisory
    (the playbook's verify step confirms the rule is present).
    """
    try:
        _ssh_run(host, f"sudo -n /usr/sbin/iptables -I INPUT -s {src_ip} -j DROP", 30)
        return StepResult(True, f"blocked {src_ip} at {host} firewall", "firewall_block_ip")
    except StepError as e:
        logger.error("firewall_block_ip %s/%s failed: %s", host, src_ip, e)
        return StepResult(False, str(e), "firewall_block_ip")


def step_config_revert(host: str, path: str, backup: str = "") -> StepResult:
    """Restore a syscheck-monitored file to baseline from the backup store.

    Uses the sudoers-whitelisted wrapper /usr/local/sbin/ssop-revert.sh
    (sudoers allows ONLY the wrapper — it enforces the /opt/ssop-backups
    source constraint and rejects traversal).
    """
    try:
        if backup:
            src = f"/opt/ssop-backups/{backup}"
        else:
            # derive: basename of the target, looked up in the backup store
            base = path.rstrip("/").split("/")[-1]
            src = f"/opt/ssop-backups/{base}"
        _ssh_run(host, f"sudo -n /usr/local/sbin/ssop-revert.sh {src} {path}", 30)
        return StepResult(True, f"reverted {path} from {src} on {host}", "config_revert")
    except StepError as e:
        logger.error("config_revert %s/%s failed: %s", host, path, e)
        return StepResult(False, str(e), "config_revert")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

STEP_REGISTRY: dict[str, Any] = {
    "service_stop": step_service_stop,
    "service_restart": step_service_restart,
    "host_quarantine": step_host_quarantine,
    "disk_clean": step_disk_clean,
    "verify_service_state": step_verify_service_state,
    "verify_firewall_rule": step_verify_firewall_rule,
    # containment actions (sudoers extended):
    "firewall_block_ip": step_firewall_block_ip,
    "config_revert": step_config_revert,
}


def run_step(step_name: str, params: dict[str, Any]) -> StepResult:
    """Execute a step by name with its params (from a playbook)."""
    fn = STEP_REGISTRY.get(step_name)
    if fn is None:
        return StepResult(False, f"unknown step: {step_name}", step_name)
    try:
        return fn(**params)
    except TypeError as e:
        return StepResult(False, f"bad params for {step_name}: {e}", step_name)
