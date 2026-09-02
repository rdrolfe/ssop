"""Analyst role tools: alert intake from Wazuh indexer + verdict workflow.

The analyst does NOT touch infrastructure. Its tools are read-only against
the SIEM and Qdrant; its output is a verdict + escalation, never an action.
Separation of duties: analysis != remediation.

Hygiene (per review): config-driven thresholds (config.py), no load_dotenv
here, imports at top, logging, structured errors.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from config import settings
from logging_setup import get_logger
from tools.indexer_client import IndexerClient, IndexerError

logger = get_logger(__name__)


class AnalystClient:
    """Read-only alert intake + verdict logic for the analyst role."""

    def __init__(self, indexer: IndexerClient | None = None) -> None:
        # Dependency injection: registry passes the shared indexer; tests
        # can pass a fake. Falls back to a fresh one only as last resort.
        self._indexer = indexer or IndexerClient()
        self.high_level = settings.high_level
        self.medium_level = settings.medium_level
        self.medium_escalate = settings.medium_escalate_categories

    # --- public API (read-only) ---

    def recent_alerts(self, limit: int = 10, min_level: int = 0) -> List[Dict[str, Any]]:
        """Fetch recent alerts from the indexer, newest first.

        For the BOTS backend, targets the THREAT-relevant slices (http + dns
        for exfil/tunneling, plus the full Sysmon process-exec index for the
        ransomware/dropped-malware artifacts) and normalizes each doc through
        bots_parser so the analyst sees the ontology shape.
        """
        backend = getattr(self._indexer, "backend", "")
        if backend == "bots":
            from tools.bots_parser import normalize
            alerts = self._indexer.recent_alerts(
                limit=limit, min_level=min_level,
                index="bots-http-poc,bots-dns-poc,bots-sysmon-op-poc")
            return [normalize(a) for a in alerts]
        alerts = self._indexer.recent_alerts(limit=limit, min_level=min_level)
        return alerts

    def classify(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Produce a preliminary classification for an alert."""
        rule = alert.get("rule") or {}  # tolerate rule=None (e.g. SO zeek.notice)
        level = int(rule.get("level", 0))
        groups = rule.get("groups", [])
        description = rule.get("description", "")
        agent = alert.get("agent", {})
        # Category is the SINGLE shared source of truth (tools.ontology) —
        # the router and the analyst must never re-derive it independently
        # (that drift is what let a tuned-FP rule be treated differently by
        # each path — the Sep 2026 dpkg flood).
        from tools.ontology import categorize_alert
        category = categorize_alert(alert)
        if level >= self.high_level:
            severity = "high"
        elif level >= self.medium_level:
            severity = "medium"
        else:
            severity = "low"
        return {
            "category": category,
            "severity": severity,
            "level": level,
            "rule_id": str(rule.get("id", "")),
            "groups": groups,
            "description": description,
            "agent": agent.get("name"),
            "agent_id": agent.get("id"),
            "alert_id": alert.get("id"),
            "timestamp": alert.get("timestamp"),
        }

    def verdict(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Produce the analyst verdict: escalate vs note.

        Rule-based for now (deterministic, auditable); the ontology can
        graduate this to a model-assisted triage with RAG context later.
        """
        c = self.classify(alert)
        # Recompute the description threat signal from the SHARED token list
        # (tools.ontology — single source; the classifier + tuning override
        # read the same tokens).
        from tools.ontology import THREAT_DESC_TOKENS
        desc_l = str((alert.get("rule") or {}).get("description", "")).lower()
        _threat_desc = any(k in desc_l for k in THREAT_DESC_TOKENS)
        # False-positive classes never auto-escalate (config-driven)
        rule_id = str((alert.get("rule") or {}).get("id", ""))
        if rule_id in settings.fp_rule_ids:
            return {
                "verdict": "note",
                "confidence": "high",
                "rationale": f"rule {rule_id} in known-FP class (rootcheck generic signature) — noted, no escalation",
                **c,
            }
        # NOISE rules (baseline events that the router filters) — the analyst
        # should note them if they slip through, never escalate.
        if rule_id in settings.noise_rules:
            return {
                "verdict": "note",
                "confidence": "high",
                "rationale": f"rule {rule_id} in noise class (baseline event) — noted, no escalation",
                **c,
            }
        # STATEFUL STEP — consult the tuning ledger: has this rule_id been
        # adjudicated? If yes, the prior decision is policy (idempotent; we
        # never re-decide a tuned class). Human-written entries are final.
        try:
            from tools.tuning_tools import TuningLedger
            tuning = TuningLedger().lookup(rule_id)
        except Exception:  # noqa: BLE001 — ledger failure must never break triage
            tuning = None
        if tuning and tuning.get("decision") in ("auto_fp", "operational"):
            # Fingerprint-aware suppression (thread #2): the ledger records
            # the decision-relevant signature of the alert that was tuned —
            # identical alerts suppress, only a MATERIAL delta (new attack
            # groups / category became attack / threat token / level rose)
            # lifts the tuning so the human re-adjudicates. Legacy entries
            # without a fingerprint fall back to the strong-TP heuristic.
            from tools.tuning_tools import tuned_rule_suppresses
            suppress, reason = tuned_rule_suppresses(tuning, alert, category=c["category"])
            if not suppress:
                return {
                    "verdict": "escalate",
                    "confidence": "high",
                    "tuning_override": True,
                    "tuned": True,
                    "rationale": reason,
                    **c,
                }
            return {
                "verdict": "note",
                "confidence": "high",
                "rationale": reason,
                "tuned": True,
                **c,
            }
        escalate = c["severity"] == "high" or (
            c["severity"] == "medium"
            and c["category"] in self.medium_escalate
            # auth failures at medium are routine (brute-force noise);
            # only auth SUCCESS anomalies signal lateral movement
            and not (c["category"] == "authentication" and "failed" in " ".join(c["groups"]).lower())
        ) or (
            # ET MALWARE / threat signatures escalate even at low level:
            # the malware indicator (Raspberry Robin, BIOPASS RAT, etc.) is the
            # signal, not Wazuh's level mapping (Suricata rules arrive at lvl 3).
            c["category"] == "threat" and _threat_desc
        )
        # STATEFUL STEP — entity recidivism: if we already have an OPEN case
        # on this (srcip, dstip) pair, we ATTACH (reuse the chain), not mint.
        existing_chain = None
        entity_srcip = entity_dstip = None
        if escalate:
            try:
                from tools.observables import entity_pair
                from tools.registry import get_cases
                pair = entity_pair(alert)
                if pair:
                    entity_srcip, entity_dstip = pair
                    existing_chain = get_cases().recent_entity_cases(entity_srcip, entity_dstip)
                elif c.get("agent"):
                    # HOST-based recidivism (BOTS Cerber replay finding): alerts
                    # without an entity pair — sysmon host events, no srcip/dstip —
                    # have nothing to chain on, so every event minted its own
                    # case (133 cases for one campaign on a host). Same host +
                    # same rule within the window = ONE campaign chain.
                    existing_chain = get_cases().recent_host_cases(
                        c["agent"], rule_id=c.get("rule_id"))
                if existing_chain:
                    escalate = False  # attach to chain below, don't mint a new escalation
            except Exception:  # noqa: BLE001 — recidivism check must never break triage
                existing_chain = None
        # SOAR enrichment: attach a recommended playbook if one matches this
        # alert's category+level (the responder gates on tier + approval).
        recommended_playbook = None
        if escalate:
            try:
                from tools.playbook_loader import load_playbooks
                for pb in load_playbooks().values():
                    if pb.matches(alert) and pb.approval in ("tier1", "tier2"):
                        recommended_playbook = pb.name
                        break
            except Exception:  # noqa: BLE001 — enrichment must never break verdict
                recommended_playbook = None
        verdict = "escalate" if escalate else "note"
        # MITRE ATT&CK techniques (adopted SO concept 6): surface the
        # technique(s) behind the alert — consumes Wazuh's built-in mapping
        # if present, else our transport.yaml technique_id. Backend-agnostic.
        techniques: List[str] = []
        try:
            from tools.techniques import extract_techniques
            techniques = extract_techniques(alert)
        except Exception:  # noqa: BLE001 — technique mapping must never break verdict
            techniques = []
        return {
            "verdict": verdict,
            "confidence": "high" if escalate else "low",
            "rationale": (
                f"level={c['level']} category={c['category']} "
                f"{'high-severity or medium auth/threat -> human review' if escalate else 'low/medium operational -> noted, no action'}"
                + (f"; attaching to existing chain {existing_chain[0].get('case_id')}" if existing_chain else "")
            ),
            "existing_chain": existing_chain[0].get("case_id") if existing_chain else None,
            "entity_srcip": entity_srcip,
            "entity_dstip": entity_dstip,
            "recommended_playbook": recommended_playbook,
            "techniques": techniques,
            **c,
        }
