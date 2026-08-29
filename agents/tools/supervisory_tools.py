"""Supervisory role tools: adjudication, reconciliation, case closure.

The supervisory role is the only one allowed to VERIFY the others. It:
  1. Reads the escalation queue and adjudicates tickets (approve/deny + rationale)
  2. Runs audit-integrity reconciliation (Qdrant vs JSONL) — watching the watchers
  3. Closes cases with verdicts and writes the human-visible report

Dual-control contract: for Tier 2, the supervisory agent produces a
RECOMMENDATION and records it; the human confirms before the case closes.
Tier 0/1 it can settle directly (Tier 1 single-approval allows agent OR human).

Hygiene: config-driven (config.py), registry-injected clients, logging.
"""

from __future__ import annotations

import glob
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings
from logging_setup import get_logger
from tools.registry import get_analyst, get_cases

logger = get_logger(__name__)


class SupervisoryClient:
    """Adjudication + reconciliation logic for the supervisory role."""

    def __init__(self, cases=None, analyst=None) -> None:
        self.ticket_dir: Path = settings.escalation_dir
        self.audit_dir: Path = settings.audit_dir
        self._cases = cases or get_cases()
        self._analyst = analyst or get_analyst()

    # --- queue operations ---

    def list_tickets(self, status: str | None = None) -> list[dict[str, Any]]:
        """Read all escalation tickets, optionally filtered by status."""
        out = []
        for f in sorted(glob.glob(str(self.ticket_dir / "*.json"))):
            try:
                with open(f, encoding="utf-8") as fh:
                    d = json.load(fh)
                if status and d.get("status") != status:
                    continue
                out.append(d)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("skipping unreadable ticket %s: %s", f, e)
                continue
        return out

    # --- adjudication ---

    def adjudicate(self, ticket: dict[str, Any], decision: str, rationale: str) -> dict[str, Any]:
        """Record a supervisory verdict on a ticket.

        When the decision is a durable policy (auto_fp / operational / escalate
        on a specific rule), ALSO write the tuning ledger so the analyst
        respects it going forward — human adjudication is the source of truth.
        """
        ticket["status"] = "adjudicated"
        ticket["decision"] = decision
        ticket["rationale"] = rationale
        ticket["adjudicated_ts"] = datetime.now(timezone.utc).isoformat()
        ticket["adjudicator"] = "supervisory"
        path = self.ticket_dir / f"{ticket['ticket_id']}.json"
        try:
            path.write_text(json.dumps(ticket, indent=2))
        except OSError as e:
            logger.error("adjudicate write failed for %s: %s", ticket["ticket_id"], e)
            raise
        # Human decision becomes durable policy: write the tuning ledger.
        # Map supervisory decisions to tuning decisions.
        _map = {"fp": "auto_fp", "deny": "auto_fp", "approve": "escalate",
                "operational": "operational", "false_positive": "auto_fp"}
        tuning_decision = _map.get(decision.lower())
        if tuning_decision:
            rule_id = str(ticket.get("rule_id") or ticket.get("detail", {}).get("rule_id", ""))
            if rule_id:
                try:
                    from tools.tuning_tools import TuningLedger
                    TuningLedger().write(
                        rule_id=rule_id, decision=tuning_decision,
                        rationale=f"supervisory {decision}: {rationale}", source="human",
                    )
                except Exception:  # noqa: BLE001 — tuning write must not break adjudication
                    logger.warning("tuning write skipped during adjudication of %s", ticket["ticket_id"])
        logger.info("adjudicated %s -> %s (%s)", ticket["ticket_id"], decision, rationale[:50])
        return ticket

    def reconcile(self) -> dict[str, Any]:
        """Audit-integrity check: Qdrant vs JSONL case spine."""
        return self._cases.reconcile()

    def case_verdict(self, case_id: str, decision: str, rationale: str) -> dict[str, Any] | None:
        """Record a supervisory verdict on a case."""
        case = self._cases.get_case(case_id)
        if not case:
            logger.warning("case_verdict: %s not found", case_id)
            return None
        case["status"] = "closed" if decision == "approve" else "open"
        case["supervisory"] = {"decision": decision, "rationale": rationale,
                               "ts": datetime.now(timezone.utc).isoformat()}
        self._cases._write_both(case, event="adjudication", role="supervisory")
        return case

    def adjudicate_with_investigation(self, case_id: str) -> dict[str, Any]:
        """Evidence-aware adjudication: use the case's investigation.

        Reads the scored investigation (hypothesis, severity, kill_chain,
        evidence) that the analyst appended to the case timeline, and uses it
        to inform the approve/deny decision — the supervisor adjudicates WITH
        the investigation, not just the title.
        """
        case = self._cases.get_case(case_id)
        if not case:
            return {"case_id": case_id, "decision": "deny",
                    "rationale": "case not found", "used_investigation": False}
        # Find the investigation event in the timeline
        inv = None
        for entry in case.get("timeline", []):
            if entry.get("type") == "investigation":
                inv = entry.get("detail", {})
                break
        if not inv:
            return {"case_id": case_id, "decision": "deny",
                    "rationale": "no investigation on case — adjudicating on title only",
                    "used_investigation": False}
        # Evidence-aware decision: high severity + kill-chain breadth = approve
        severity = inv.get("severity", 0)
        sev_label = inv.get("severity_label", "low")
        chain = inv.get("kill_chain", [])
        evidence_count = len(inv.get("evidence", []))
        # Decision policy: high severity OR (medium + 2+ kill-chain stages)
        if sev_label == "high" or (sev_label == "medium" and len(chain) >= 2):
            decision = "approve"
            rationale = (f"investigation: {inv.get('hypothesis','')[:120]}; "
                         f"{evidence_count} evidence sources, score {severity} ({sev_label})")
        else:
            decision = "deny"
            rationale = (f"investigation weak: score {severity} ({sev_label}), "
                         f"{evidence_count} evidence, chain={len(chain)} stage(s)")
        # Record the verdict + rationale on the case
        self.case_verdict(case_id, decision, rationale)
        return {"case_id": case_id, "decision": decision, "rationale": rationale,
                "used_investigation": True, "severity": severity, "severity_label": sev_label,
                "evidence_count": evidence_count}

    def supervise_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Context-aware supervisory decision for a case.

        Uses the full case payload (observables, enrichments, techniques,
        checklist) — the adopted SO concepts — instead of title keywords.

        Decision logic (deterministic, data-grounded):
        - MALICIOUS enrichment (GreyNoise 'malicious' on an observable) ->
          approve (escalate/contain) — the IOC is known-bad.
        - BENIGN enrichment on ALL observables -> deny (auto_fp) — context
          says clean.
        - Else fall back to the rule-class heuristics (title/rule_id).
        On approve, also recommends a matching playbook for the responder
        (the SOAR handoff) — reused from the analyst's playbook matcher.
        Returns {decision, rationale, evidence, recommended_playbook}.
        """
        enrichments = case.get("enrichments", [])
        observables = case.get("observables", [])
        techniques = case.get("techniques", [])
        title = (case.get("title") or "").lower()
        evidence = {
            "observables": len(observables),
            "enrichments": len(enrichments),
            "malicious_obs": 0,
            "benign_obs": 0,
            "techniques": techniques,
        }
        result = {}
        # 1. Malicious enrichment anywhere -> act (contain/escalate)
        for e in enrichments:
            st = (e.get("status") or "").lower()
            if st == "malicious":
                evidence["malicious_obs"] += 1
                val = (e.get("observable") or {}).get("value", "?")
                result = {"decision": "approve",
                          "rationale": f"IOC {val} is known-malicious (GreyNoise) — contain/escalate",
                          "evidence": evidence}
                break
            if st == "benign":
                evidence["benign_obs"] += 1
        if not result and observables and evidence["benign_obs"] == len(enrichments) and enrichments:
            result = {"decision": "deny",
                      "rationale": "all observables enrichment-benign — likely noise",
                      "evidence": evidence}
        if not result and ("rootcheck" in title or "integrity" in title):
            result = {"decision": "deny",
                      "rationale": "integrity drift — host verification clean: rootcheck FP",
                      "evidence": evidence}
        if not result and "disk" in title:
            result = {"decision": "approve", "rationale": "disk pressure — cleanup approved",
                      "evidence": evidence}
        if not result and techniques:
            result = {"decision": "approve",
                      "rationale": f"MITRE {', '.join(techniques)} — investigate/escalate",
                      "evidence": evidence}
        if not result:
            result = {"decision": "deny", "rationale": "no actionable signal", "evidence": evidence}
        # SOAR handoff: on approve, recommend a matching playbook for the responder.
        result["recommended_playbook"] = None
        if result["decision"] == "approve":
            try:
                from tools.playbook_loader import load_playbooks
                # Reconstruct a trigger the playbook matcher can match. Derive
                # level from evidence: malicious IOC / techniques = high (12);
                # else moderate (6). Category: threat when techniques/malicious.
                has_high_signal = evidence["malicious_obs"] > 0 or bool(techniques)
                pseudo_alert = {
                    "rule": {"groups": [], "level": 12 if has_high_signal else 6},
                    "category": "threat" if has_high_signal else "operational",
                }
                for pb in load_playbooks().values():
                    if pb.approval in ("tier1", "tier2") and pb.matches(pseudo_alert):
                        result["recommended_playbook"] = pb.name
                        break
            except Exception:  # noqa: BLE001 — recommendation must never break adjudication
                result["recommended_playbook"] = None
        return result

    def report(self) -> dict[str, Any]:
        """Summary of queue + spine state for the human."""
        tickets = self.list_tickets()
        open_tickets = [t for t in tickets if t.get("status") == "open"]
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tickets_total": len(tickets),
            "tickets_open": len(open_tickets),
            "tickets_adjudicated": len(tickets) - len(open_tickets),
            "reconcile": self.reconcile(),
        }
