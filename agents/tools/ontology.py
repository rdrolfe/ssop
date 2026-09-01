"""Ontology category — the SINGLE source of truth for alert categorization.

Both the analyst verdict path and the router dispatch path previously had
their OWN group→category heuristics (analyst_tools.classify vs
router.classify), and they drifted — the router mapped `syscheck` → security
while the analyst mapped it → integrity, which is exactly how a tuned-FP rule
(2902/2904/550) could be treated differently depending on which path touched
it. That divergence caused the Sep 2026 dpkg/integrity ticket flood.

This module is the one place the ontology category is derived. Consumers:
  - analyst_tools.AnalystClient.classify()  -> category field
  - router.classify()                        -> feeds dispatch role + the
    strong-TP override category gate
  - tuning_tools.strong_tp_evidence()        -> category-aware override

Taxonomy (the ontology): authentication | threat | integrity | compliance |
operational. Backend-agnostic — it reads Wazuh/SO group tokens and threat
description tokens, never a backend-specific field layout.
"""
from __future__ import annotations

from typing import Any

from config import settings

# Suricata/ET signatures carry the threat class in the DESCRIPTION
# (rule.groups is just ['ids','suricata']), so we signal on description too.
THREAT_DESC_TOKENS: tuple[str, ...] = (
    "et malware", "et trojan", "et rat", "et c2", "et botnet",
    "malicious", "malware dns", "cnc", "command and control",
    "mimikatz", "meterpreter", "cobalt strike",
)


def categorize_alert(alert: dict[str, Any]) -> str:
    """Return the ontology category for an alert (single source of truth).

    Deterministic, group-token driven, backend-agnostic. The router's
    dispatch taxonomy (security/pattern/infra) is derived FROM this in
    router.classify — never re-derives category independently.
    """
    rule = alert.get("rule") or {}  # tolerate rule=None (e.g. SO zeek.notice)
    groups = rule.get("groups", [])
    description = rule.get("description", "")
    groups_l = [str(g).lower() for g in groups]
    desc_l = str(description).lower()
    _threat_desc = any(t in desc_l for t in THREAT_DESC_TOKENS)
    # Category heuristics (extensible — the ontology's job)
    # Wazuh emits "authentication_failed" (singular, e.g. rule 5710 sshd auth
    # failure) AND the generic plural "authentication"/"authentication_failures"
    # — the single source must match ALL of them so the analyst and router
    # classify the same alert identically (the Sep 2026 drift came from the
    # analyst matching only the plural while the router matched the singular).
    if ("authentication" in groups_l or "authentication_failed" in groups_l
            or "authentication_failures" in groups_l):
        return "authentication"
    if (_threat_desc or "attack" in groups_l or "malware" in groups_l
            or "virustotal" in groups_l or "threat" in groups_l
            or "exfiltration" in groups_l or "c2" in groups_l
            or "command_and_control" in groups_l):
        return "threat"
    if "rootcheck" in groups_l or "syscheck" in groups_l or "pci_dss" in groups_l:
        return "integrity"
    if "policy" in groups_l or "vulnerability" in groups_l:
        return "compliance"
    return "operational"


# --- tuning fingerprints (thread #2: fingerprint-based tuning) --------------
# When a human tunes a rule, the ledger records the DECISION-RELEVANT
# signature of the alert that was tuned (rule_id + groups + level + category
# + threat-desc presence). Identical signatures are always suppressed; only a
# MATERIAL delta (new attack groups, category became attack-class, a
# threat-desc token appeared, or level rose) lifts the tuning so the human
# re-adjudicates. This replaces the pure threshold heuristic — consistency is
# now explicit: the same alert shape always gets the same outcome.

def _canonical_fingerprint(rule_id: Any, groups: Any, level: Any,
                           category: str, description: Any) -> dict:
    """Normalize a fingerprint to its canonical, comparable form."""
    groups_n = sorted(str(g).lower() for g in (groups or []) if g is not None)
    desc_l = str(description or "").lower()
    try:
        level_n = int(level or 0)
    except (TypeError, ValueError):
        level_n = 0
    return {
        "rule_id": str(rule_id or ""),
        "groups": groups_n,
        "level": level_n,
        "category": category or "",
        "threat_desc": any(t in desc_l for t in THREAT_DESC_TOKENS),
    }


def fingerprint_from_alert(alert: dict) -> dict:
    """Fingerprint a RAW alert (rule nested under alert['rule'])."""
    rule = alert.get("rule") or {}
    category = categorize_alert(alert)
    return _canonical_fingerprint(
        rule.get("id"), rule.get("groups"), rule.get("level"), category,
        rule.get("description"))


def fingerprint_from_verdict(v: dict) -> dict | None:
    """Fingerprint a classify/verdict dict (rule_id/groups/level/category/
    description at TOP level — the shape the analyst verdict and the
    escalation ticket detail carry). Returns None when no rule_id (can't
    fingerprint a hunt finding or a malformed ticket)."""
    rule_id = v.get("rule_id")
    if not rule_id:
        return None
    return _canonical_fingerprint(
        rule_id, v.get("groups"), v.get("level"), v.get("category") or "",
        v.get("description"))


def fingerprint_materially_differs(stored: dict, current: dict) -> bool:
    """True when the current alert differs from the TUNED signature in a way
    that should lift the tuning (re-adjudication), not silent suppression.

    Only deltas that change the risk assessment count:
      - threat-desc token appeared (False -> True)
      - category became attack-class (threat/authentication/security)
      - an attack-class group was added
      - level ROSE (a higher-severity firing than what was tuned)
    Benign drift (fewer groups, lower level, same category, different
    package names in the description) does NOT lift the tuning — the alert
    is still the class the human decided on.
    """
    if stored.get("rule_id") != current.get("rule_id"):
        return True
    if current.get("threat_desc") and not stored.get("threat_desc"):
        return True
    cur_cat = current.get("category") or ""
    if (stored.get("category") != cur_cat
            and cur_cat in ("threat", "authentication", "security")):
        return True
    stored_groups = set(stored.get("groups") or [])
    cur_groups = set(current.get("groups") or [])
    new_groups = cur_groups - stored_groups
    attack_tokens = {"attack", "malware", "c2", "command_and_control",
                     "exfiltration", "threat", "suricata", "ids",
                     "authentication_failed", "invalid_login"}
    if new_groups & attack_tokens:
        return True
    try:
        if int(current.get("level", 0)) > int(stored.get("level", 0)):
            return True
    except (TypeError, ValueError):
        pass
    return False
