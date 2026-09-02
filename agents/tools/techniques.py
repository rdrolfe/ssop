"""MITRE ATT&CK technique mapping for alerts.

Adopted SO concept (ATT&CK Navigator / detection->technique -> ontology):
surface the ATT&CK technique(s) behind an alert so analysts (and the
ontology) reason in MITRE terms, not just rule signatures.

PORTABILITY + Wazuh contribution (two-example doctrine, concept 6):
- If the alert already carries Wazuh's built-in MITRE mapping (rule.mitre),
  we CONSUME it (the Wazuh backend contributes the technique).
- Else we fall back to our own technique_id mapped in transport.yaml
  (ontology data, backend-agnostic).
Identical logic runs against SO (whose signals carry mitre.attack.* fields).

Lookup order per alert:
  1. alert["rule"]["mitre"]["id"] / ["technique"]  (Wazuh built-in)
  2. alert["mitre"]["attack"]["technique"]         (SO / ECS-style)
  3. transport.yaml rule map technique_id          (our mapping)
  4. empty (no technique known)
"""

from __future__ import annotations

from typing import Any

import yaml

from logging_setup import get_logger

logger = get_logger(__name__)


def _load_transport() -> dict[str, Any]:
    """Load transport.yaml (backend + rule map with optional technique_id)."""
    try:
        from pathlib import Path
        tpath = Path(__file__).resolve().parent.parent / "transport.yaml"
        if tpath.exists():
            return yaml.safe_load(tpath.read_text()) or {}
    except Exception as e:  # noqa: BLE001 — mapping must never break classify
        logger.warning("transport load failed for technique map: %s", e)
    return {}


def extract_techniques(alert: dict[str, Any]) -> list[str]:
    """Return the MITRE technique IDs for an alert (lookup order above)."""
    rule = alert.get("rule", {}) or {}

    # 1. Wazuh built-in: rule.mitre.id or rule.mitre.technique
    mitre = rule.get("mitre") or {}
    for key in ("id", "technique"):
        val = mitre.get(key)
        if isinstance(val, list):
            return [str(v) for v in val]
        if val:
            return [str(val)]

    # 2. SO / ECS-style: mitre.attack.technique (may be list of dicts)
    attack = (alert.get("mitre") or {}).get("attack") or {}
    tech = attack.get("technique") or attack.get("id")
    if isinstance(tech, list):
        out = []
        for t in tech:
            if isinstance(t, dict):
                tid = t.get("id") or t.get("name")
                if tid:
                    out.append(str(tid))
            else:
                out.append(str(t))
        if out:
            return out
    if tech:
        return [str(tech)]

    # 3. Our mapping in transport.yaml (rule_map technique_id)
    rid = rule.get("id", "")
    if rid is not None:
        data = _load_transport()
        backend = data.get("backend", "wazuh")
        key = f"{backend}_rules" if backend != "wazuh" else "rules"
        rules = data.get(key) or {}
        # Rule-map keys parse as ints in YAML; try both forms.
        entry = rules.get(rid) or rules.get(str(rid))
        if isinstance(entry, dict) and entry.get("technique_id"):
            tids = entry["technique_id"]
            if isinstance(tids, list):
                return [str(t) for t in tids]
            return [str(tids)]

    return []


def technique_summary(techniques: list[str]) -> str:
    """Compact display (e.g. 'T1547.001, T1059')."""
    return ", ".join(techniques) if techniques else "unknown"


# --- technique metadata (ID -> name + tactic) ------------------------------
# Grounded in the IDs observed in live data (probe 2026-09-02: T1078, T1021,
# T1565.001) plus the common technique families the transport map references
# (T1068 apparmor, T1547.001 rootcheck) and the DNS-tunnel/webshell classes
# the drills exercise. Unknown IDs render honestly as (id, name=TID, tactic=Other)
# rather than being invented.
TECHNIQUE_META: dict[str, tuple[str, str]] = {
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1048.003": ("Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1565.001": ("Stored Data Manipulation", "Impact"),
    "T1204": ("User Execution", "Execution"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1572": ("Protocol Tunneling", "Command and Control"),
    "T1568": ("Dynamic Resolution", "Command and Control"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
}


def technique_meta(tid: str) -> dict[str, str]:
    """Resolve a technique ID to {id, name, tactic}. Unknown IDs are honest:
    name falls back to the ID itself, tactic to 'Other' — never invented."""
    name, tactic = TECHNIQUE_META.get(tid, (tid, "Other"))
    return {"id": tid, "name": name, "tactic": tactic}
