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
