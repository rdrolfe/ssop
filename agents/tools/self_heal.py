"""Self-heal tool module for infra-agent (sysadmin role).

Runs the sense -> decide -> act -> verify -> remember loop against the fleet:
host health (disk, ssh), fleet agent connectivity (Wazuh), and whitelisted
remediation (journald vacuum, apt clean, docker prune). Anything outside the
whitelist escalates as a Tier-1 ticket.

Hygiene: config-driven (config.py), registry-injected clients (no fresh
instances per run), logging, no mid-function imports.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from config import settings
from logging_setup import get_logger
from tools.registry import get_escalation, get_ssh, get_wazuh

logger = get_logger(__name__)


def load_checks(checks_file: Path) -> list[dict[str, Any]]:
    """Load host health checks from a YAML file.

    Data-driven per review: add a check by editing checks.yaml, no code
    change. Name must match decide() logic (disk_root triggers the clean
    path; everything else defaults to investigate/escalate).
    """
    if not checks_file.exists():
        logger.warning("checks file %s not found — empty check set", checks_file)
        return []
    try:
        with open(checks_file, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        checks = data.get("checks", []) if isinstance(data, dict) else []
        if not isinstance(checks, list):
            logger.warning("checks file %s: 'checks' must be a list", checks_file)
            return []
        for c in checks:
            c.setdefault("ok_if", None)
            c.setdefault("warn_pct", settings.disk_warn_pct)
        logger.info("loaded %d health checks from %s", len(checks), checks_file.name)
        return checks
    except (yaml.YAMLError, OSError) as e:
        logger.warning("failed to load checks %s: %s", checks_file, e)
        return []


# Health checks per host (data-driven — see checks.yaml)
CHECKS: list[dict[str, Any]] = load_checks(settings.checks_file)


class SelfHeal:
    """Run the sense->decide->act->verify->remember loop."""

    def __init__(self, remote=None, escalate=None, wazuh=None) -> None:
        # Dependency injection: registry passes shared clients; tests inject fakes.
        self.remote = remote or get_ssh()
        self.escalate = escalate or get_escalation()
        self.wazuh = wazuh or get_wazuh()
        self.hosts: list[str] = list(self.remote.hosts.keys()) or ["localhost"]
        self.disk_ok_pct = settings.disk_warn_pct

    # --- SENSE: fleet agent connectivity (Wazuh) ---
    def sense_agents(self) -> dict[str, Any]:
        """Query Wazuh manager for agent status. Flags any agent not active.

        This is the fleet-level sense: an endpoint dropping off the SIEM is
        a Tier-1 signal the infra-manager should surface BEFORE the human
        notices it on the agents-preview page.
        """
        try:
            r = self.wazuh.list_agents()
            agents = r.get("data", {}).get("affected_items", [])
            statuses = {}
            for a in agents:
                name = a.get("name", "?")
                if name == "wazuh.manager":
                    continue
                statuses[name] = {
                    "id": a.get("id"),
                    "status": a.get("status", "?"),
                    "ip": a.get("ip", "?"),
                    "group": a.get("group", []),
                    "last_keepalive": a.get("lastKeepAlive", "?"),
                    "ok": a.get("status") == "active",
                }
            down = {n: s for n, s in statuses.items() if not s["ok"]}
            logger.info("agent fleet sense: %d agents, %d down", len(statuses), len(down))
            return {
                "ok": len(down) == 0,
                "agents": statuses,
                "down": down,
                "count": len(statuses),
            }
        except Exception as e:  # noqa: BLE001 — sense failure is not fatal
            logger.warning("agent fleet sense failed: %s", e)
            return {"ok": False, "error": str(e), "agents": {}, "down": {}, "count": 0}

    # --- DECIDE: agent connectivity ---
    def decide_agents(self, sense_agents: dict[str, Any]) -> list[dict[str, Any]]:
        """Convert agent sense results into issues (escalation-class)."""
        issues = []
        if sense_agents.get("error"):
            issues.append({
                "issue": "wazuh_api_unreachable",
                "action": "investigate",
                "fixable": False,
                "detail": sense_agents,
            })
            return issues
        for name, info in sense_agents.get("down", {}).items():
            issues.append({
                "issue": f"wazuh_agent_down:{name}",
                "action": "escalate",
                "fixable": False,  # restarting an agent is outside sudoers whitelist
                "detail": info,
            })
        return issues

    # --- SENSE ---
    def sense(self, host: str) -> dict[str, Any]:
        """Run health checks against one host. Returns per-check results."""
        results = {}
        for check in CHECKS:
            r = self.remote.run(host, check["cmd"], timeout=20)
            results[check["name"]] = {
                "ok": r.get("ok", False),
                "output": r.get("stdout", ""),
                "stderr": r.get("stderr", ""),
            }
            # numeric disk parse
            if check["name"] == "disk_root" and results["disk_root"]["ok"]:
                parts = results["disk_root"]["output"].split()
                if len(parts) >= 5:
                    use = parts[4].rstrip("%")
                    try:
                        pct = int(use)
                        results["disk_root"]["pct"] = pct
                        results["disk_root"]["ok"] = pct < check["warn_pct"]
                    except ValueError:
                        pass
            # hostname/echo match
            if check["name"] == "ssh" and check.get("ok_if"):
                results["ssh"]["ok"] = results["ssh"]["ok"] and check["ok_if"] in results["ssh"]["output"]
        return results

    # --- DECIDE ---
    def decide(self, host: str, sense_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Classify issues into fixable (whitelisted) vs escalate."""
        issues = []
        for name, res in sense_results.items():
            if res.get("ok"):
                continue
            if name == "disk_root":
                pct = res.get("pct", "?")
                issues.append({
                    "issue": f"disk_root {pct}%",
                    "action": "clean",
                    "fixable": True,
                    "detail": res,
                })
            else:
                issues.append({
                    "issue": name,
                    "action": "investigate",
                    "fixable": False,
                    "detail": res,
                })
        return issues

    # --- ACT + VERIFY (for fixable issues) ---
    def heal_one(self, host: str, issue: dict[str, Any]) -> dict[str, Any]:
        """Attempt a whitelisted fix, then verify. Returns outcome."""
        outcome = {"host": host, "issue": issue["issue"], "fixed": False}
        if not issue.get("fixable"):
            outcome["reason"] = "not auto-fixable (needs escalation)"
            return outcome
        if issue["action"] == "clean":
            # disk cleanup: vacuum journal + clean apt cache + prune docker layers
            r1 = self.remote.run(host, "sudo -n journalctl --vacuum-time=7d", timeout=30)
            r2 = self.remote.run(host, "sudo -n apt-get clean", timeout=30)
            # Old docker image layers are a known disk hog after upgrades.
            # Safe: only removes dangling images (no tag, no container ref).
            r3 = self.remote.run(host, "sudo -n docker image prune -f", timeout=60)
            outcome["actions"] = [r1, r2, r3]
        # VERIFY: re-run disk check
        verify = self.remote.run(host, "df -h / | tail -1", timeout=20)
        parts = verify.get("stdout", "").split()
        if len(parts) >= 5:
            pct = parts[4].rstrip("%")
            try:
                outcome["pct_after"] = int(pct)
                outcome["fixed"] = int(pct) < self.disk_ok_pct
            except ValueError:
                outcome["pct_after"] = pct
        outcome["verify"] = verify
        logger.info("heal %s %s fixed=%s", host, issue["issue"], outcome.get("fixed"))
        return outcome

    # --- REMEMBER ---
    def remember(self, host: str, outcome: dict[str, Any]) -> None:
        """Store the outcome in Qdrant ltp for future runs."""
        try:
            from tools.qdrant_tools import QdrantMemory
            mem = QdrantMemory()
            mem.store_memory(
                "ltp",
                f"self_heal {host}: {outcome['issue']} fixed={outcome.get('fixed')}",
                metadata={"type": "self_heal", "host": host, "issue": outcome.get("issue", "")},
            )
        except Exception as e:  # noqa: BLE001 — memory failure shouldn't crash the heal loop
            logger.warning("remember failed for %s: %s", host, e)

    # --- MAIN LOOP ---
    def run(self, host: str = "") -> dict[str, Any]:
        """Run the full self-heal cycle across hosts (or one host)."""
        targets = [host] if host else self.hosts
        report = {"ts": datetime.now(timezone.utc).isoformat(), "hosts": {}, "agents": {}}
        for h in targets:
            sense_results = self.sense(h)
            issues = self.decide(h, sense_results)
            heal_results = []
            escalations = []
            for issue in issues:
                if issue.get("fixable"):
                    healed = self.heal_one(h, issue)
                    heal_results.append(healed)
                    self.remember(h, healed)
                else:
                    # escalate non-fixable issues to supervisory layer
                    esc = self.escalate.escalate(
                        tier=1,
                        title=f"Self-heal blocked on {h}: {issue['issue']}",
                        detail={"host": h, "issue": issue["issue"], "sense": issue["detail"]},
                    )
                    escalations.append(esc)
            report["hosts"][h] = {
                "sense": sense_results,
                "issues": issues,
                "healed": heal_results,
                "escalations": escalations,
                "healthy": len(issues) == 0,
            }

        # Fleet-level: Wazuh agent connectivity
        agent_sense = self.sense_agents()
        agent_issues = self.decide_agents(agent_sense)
        agent_escalations = []
        for issue in agent_issues:
            esc = self.escalate.escalate(
                tier=1,
                title=f"Agent fleet: {issue['issue']}",
                detail={"issue": issue["issue"], "sense": issue["detail"]},
            )
            agent_escalations.append(esc)
            self.remember("wazuh-fleet", {
                "issue": issue["issue"], "fixed": False,
                "reason": "escalated to supervisory (agent restart outside whitelist)",
            })
        report["agents"] = {
            "sense": agent_sense,
            "issues": agent_issues,
            "escalations": agent_escalations,
            "healthy": len(agent_issues) == 0,
        }
        return report
