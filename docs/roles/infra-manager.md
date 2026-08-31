# Infra-manager — heal within the whitelist, escalate the rest

`agents/tools/self_heal.py` · senses host health, heals within its sudoers
whitelist, verifies the fix, remembers the outcome. Everything outside the
whitelist becomes a staged escalation with the exact command pre-staged for
human approval.

Loop: **SENSE → DECIDE → ACT → VERIFY → REMEMBER**.

## Inputs
- Health checks: `agents/checks.yaml` (data-driven — add a check = YAML)
- Hosts from `settings.ssh_hosts` (parsed from `SSH_HOSTS`)
- Wazuh manager API (fleet agent status)
- Sudoers whitelist (the cage)

## Decision flow

### 1. SENSE (`self_heal.py:127-151`)
Runs each YAML check against the host (disk_root, ssh, …). Disk parses the
`df` percentage; ssh honors `ok_if`. Fleet-level: `sense_agents()` queries
the Wazuh manager for agent status (`:70-103`).

### 2. DECIDE — fixable vs escalate (`self_heal.py:154-175`)
```
disk_root (>= warn_pct)  → action=clean, fixable=True
anything else unhealthy   → action=investigate, fixable=False
```
Fleet: Wazuh API unreachable → investigate; agent down → escalate
(restarting an agent is outside the whitelist, `:106-124`).

### 3. ACT + VERIFY (`self_heal.py:178-204`)
For fixable disk issues: `journalctl --vacuum-time=7d` + `apt-get clean` +
`docker image prune -f` (dangling images only). Then re-run `df` — `fixed`
only if below the warn threshold.

### 4. REMEMBER (`self_heal.py:207-218`)
Outcome stored in Qdrant `ltp` for future runs.

### 5. Escalate (`self_heal.py:235-242`)
Non-fixable issues → tier-1 escalation ticket with the issue + sense detail
pre-staged. Agent-fleet issues likewise.

## Outputs
Per-host `{sense, issues, healed, escalations, healthy}` + fleet
`{sense, issues, escalations, healthy}` report.

## Gates
- Sudoers whitelist (the OS cage — even a hallucinating model cannot act
  outside it)
- fixable vs escalate classification (checks.yaml name → decide logic)
- Verify-after-fix (a "heal" that didn't move the needle is recorded as not
  fixed)

## Verify coverage
Self-heal fixtures + `agents/verify/` — disk clean path heals and verifies;
agent-down and non-whitelisted issues escalate, never silently fail.
