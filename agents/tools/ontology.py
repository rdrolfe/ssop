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
