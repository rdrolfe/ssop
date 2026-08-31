"""SSOP SOAR responder — dedicated state machine for containment actions.

The responder executes playbooks (agents/playbooks/*.yaml) under the approval
model. Flow per the wayfinder decisions:

    candidate match -> recommendation gate -> guard resolution -> tier check
      tier0: execute now (verify/known-safe)
      tier1: execute now (recorded)
      tier2: ticket (run_id + payload) -> await approval
             approved+run_id+not-expired: execute
             denied: record, close; expired: mark expired, no execute
    any failure -> stop, record failed on spine + ticket

Separation of duties: roles RECOMMEND playbooks (enrichment); the responder
EXECUTES under approval. Never targets protected entities (fail-closed).

Hygiene: config-driven, registry singletons, logging, exception discipline,
dotenv only in __main__.
"""

from __future__ import annotations

import ipaddress
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph

from config import settings
from logging_setup import get_logger
from tools.escalate_tools import EscalationClient
from tools.playbook_loader import Playbook, load_playbooks
from tools.registry import get_escalation
from tools.responder_steps import StepResult, run_step

logger = get_logger(__name__)


class ResponderState(TypedDict, total=False):
    """State threaded through the responder state machine."""
    alert: dict[str, Any]
    case_id: str
    dry_run: bool
    playbook_name: str
    tier: str
    run_id: str
    results: list[dict[str, Any]]
    blocked: bool
    blocked_reason: str
    recommended_playbook: str | None
    _pb: Any
    error: str | None


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------

def _is_protected(target: str) -> bool:
    """Is a target in the protected set? Literal -> CIDR -> hostname alias."""
    if not target:
        return False
    t = target.strip().lower()
    # literal
    if t in {p.lower() for p in settings.protected_entities}:
        return True
    # hostname aliases from config SSH_HOSTS resolve to fleet IPs
    for alias, ip in settings.ssh_hosts.items():
        if t == alias.lower():
            return _is_protected(ip)
    # CIDR membership
    try:
        addr = ipaddress.ip_address(t)
        for ent in settings.protected_entities:
            if "/" in ent:
                if addr in ipaddress.ip_network(ent, strict=False):
                    return True
            elif ent.count(".") == 3:
                if addr == ipaddress.ip_address(ent):
                    return True
    except ValueError:
        pass
    return False


def guard_check(playbook: Playbook, alert: dict[str, Any]) -> str | None:
    """Return a protected-entity reason if the playbook must be blocked.

    Resolves every step's target params (host, src_ip, target) against the
    protected set. Fail-closed: any protected target blocks the WHOLE
    playbook (per the trigger-matching-guard decision).
    """
    for step in playbook.steps:
        params = step.get("params", {})
        for field in ("host", "src_ip", "target", "ip"):
            val = params.get(field)
            if val and _is_protected(str(val)):
                return f"{field}={val}"
    # alert srcip can be a target too (top-level, or data.src_ip on live alerts)
    srcip = alert.get("srcip") or (alert.get("data", {}) or {}).get("src_ip")
    if srcip and _is_protected(str(srcip)):
        return f"alert.srcip={srcip}"
    return None


# ---------------------------------------------------------------------------
# Template resolution
# ---------------------------------------------------------------------------

def _resolve_template(val: Any, ctx: dict[str, Any]) -> str:
    """Resolve {{alert.x}} / {{case_id}} template vars in a param."""
    s = str(val)
    for key, repl in ctx.items():
        s = s.replace("{{" + key + "}}", str(repl))
    return s


def _resolve_params(params: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in params.items():
        if isinstance(v, str) and "{{" in v:
            out[k] = _resolve_template(v, ctx)
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Candidate selection + recommendation gate
# ---------------------------------------------------------------------------

def select_candidates(alert: dict[str, Any], playbooks: dict[str, Playbook],
                      recommended: str | None = None) -> list[Playbook]:
    """Find playbooks whose trigger matches the alert.

    Gate: a tier1+/recommended playbook fires only if `recommended` names it
    (a role attached recommended_playbook to the case). tier0 playbooks with
    recommended:false fire on trigger alone.
    """
    out = []
    for pb in playbooks.values():
        if not pb.matches(alert):
            continue
        if pb.requires_recommendation and recommended != pb.name:
            logger.info("gate: %s requires recommendation (got %r)", pb.name, recommended)
            continue
        out.append(pb)
    return out


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def execute_playbook(pb: Playbook, ctx: dict[str, Any], dry_run: bool = False) -> list[dict[str, Any]]:
    """Execute a playbook's steps strictly sequentially; stop on first failure."""
    results: list[dict[str, Any]] = []
    for step in pb.steps:
        name = step.get("step", "")
        params = _resolve_params(step.get("params", {}), ctx)
        if dry_run:
            results.append({"step": name, "ok": True, "detail": "DRY-RUN (not executed)"})
            continue
        res: StepResult = run_step(name, params)
        results.append(res.to_dict())
        if not res.ok:
            logger.error("playbook %s step %s failed: %s", pb.name, name, res.detail)
            break  # stop on first failure (decision)
    return results


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

def node_select(state: ResponderState) -> ResponderState:
    """Candidate match + recommendation gate."""
    alert = state.get("alert", {})
    pb_name = state.get("playbook_name")
    recommended = state.get("recommended_playbook") if "recommended_playbook" in state else pb_name
    playbooks = load_playbooks()
    candidates = select_candidates(alert, playbooks, recommended=recommended)
    if not candidates:
        return {**state, "error": "no candidate playbook", "results": []}
    return {**state, "playbook_name": candidates[0].name, "tier": candidates[0].approval}


def _get_pb(state: ResponderState) -> Playbook:
    """Re-lookup the playbook by name (objects don't survive state channels)."""
    pbs = load_playbooks()
    pb = pbs.get(state.get("playbook_name", ""))
    if pb is None:
        raise KeyError(f"playbook {state.get('playbook_name')} not found")
    return pb


def node_guard(state: ResponderState) -> ResponderState:
    """Self-infliction guard — fail-closed before approval."""
    pb = _get_pb(state)
    reason = guard_check(pb, state.get("alert", {}))
    if reason:
        logger.warning("playbook %s BLOCKED: protected entity %s", pb.name, reason)
        return {**state, "blocked": True, "blocked_reason": f"protected-entity ({reason})"}
    return state


def node_tier1_execute(state: ResponderState) -> ResponderState:
    """Tier-1 executes immediately at dispatch."""
    pb = _get_pb(state)
    ctx = {"case_id": state.get("case_id", ""), "alert.srcip": state.get("alert", {}).get("srcip", "")}
    results = execute_playbook(pb, ctx, dry_run=state.get("dry_run", False))
    return {**state, "results": results}


def node_tier2_ticket(state: ResponderState) -> ResponderState:
    """Tier-2 creates an escalation ticket with run_id + payload, no execution."""
    pb = _get_pb(state)
    run_id = str(uuid.uuid4())[:12]
    ctx = {"case_id": state.get("case_id", ""), "alert.srcip": state.get("alert", {}).get("srcip", "")}
    detail = {
        "run_id": run_id,
        "playbook": pb.name,
        "steps": pb.steps,
        "resolved_params": [_resolve_params(s.get("params", {}), ctx) for s in pb.steps],
        "case_id": state.get("case_id", ""),
        "expires": (datetime.now(timezone.utc) + timedelta(minutes=settings.approval_expiry_min)).isoformat(),
    }
    if not state.get("dry_run", False):
        esc: EscalationClient = get_escalation()
        esc.escalate(tier=2, title=f"SOAR approval: {pb.name}", detail=detail, actor="responder")
        logger.info("tier2 ticket created for %s (run_id %s)", pb.name, run_id)
    else:
        logger.info("DRY-RUN: would create tier2 ticket for %s (run_id %s)", pb.name, run_id)
    return {**state, "run_id": run_id, "results": [{"step": "ticket", "ok": True,
             "detail": f"tier2 approval ticket created (run_id {run_id})"}]}


def build_graph() -> StateGraph:
    """Build the responder state machine."""
    g = StateGraph(ResponderState)
    g.add_node("select", node_select)
    g.add_node("guard", node_guard)
    g.add_node("tier1_execute", node_tier1_execute)
    g.add_node("tier2_ticket", node_tier2_ticket)
    g.set_entry_point("select")

    # select branch: no candidate -> END with error; else guard
    def route_select(state: ResponderState) -> str:
        if state.get("error"):
            return "select_end"
        return "guard"

    g.add_conditional_edges("select", route_select, {
        "guard": "guard",
        "select_end": END,
    })

    # guard branch: blocked -> END (fail-closed); clear -> tier check
    def route_guard(state: ResponderState) -> str:
        if state.get("blocked"):
            return "blocked_end"
        tier = state.get("tier", "tier2")
        return "tier1_execute" if tier == "tier1" else "tier2_ticket"

    g.add_conditional_edges("guard", route_guard, {
        "tier1_execute": "tier1_execute",
        "tier2_ticket": "tier2_ticket",
        "blocked_end": END,
    })
    g.add_edge("tier1_execute", END)
    g.add_edge("tier2_ticket", END)
    return g


def run(alert: dict[str, Any], case_id: str = "", dry_run: bool = False,
        recommended_playbook: str | None = None) -> dict[str, Any]:
    """Run the responder for one alert.

    `recommended_playbook` may be passed explicitly, OR resolved from the
    case spine (the supervisory role writes its recommendation there). The
    case-lookup closes the handoff: supervisor recommends -> responder picks
    it up -> gates on it.

    Approval gate: the responder also reads the supervisor's decision from
    the case. If the supervisor DENIED the case, the responder refuses to
    execute (even if a playbook was recommended) — the human/supervisor
    decision is the authority.
    """
    supervisor_decision = None
    alert_category = None
    if case_id:
        try:
            from tools.case_tools import CaseStore
            case = CaseStore().get_case(case_id)
            if case:
                # 1. Check the case's supervisory field (case_verdict writes here)
                sup_field = case.get("supervisory") or {}
                if sup_field.get("decision"):
                    supervisor_decision = sup_field.get("decision")
                    if recommended_playbook is None:
                        recommended_playbook = sup_field.get("recommended_playbook")
                # 2. Check the most recent supervisory adjudication timeline event
                for ev in reversed(case.get("timeline", [])):
                    if ev.get("role") == "supervisory" and ev.get("type") == "adjudication":
                        supervisor_decision = (ev.get("detail") or {}).get("decision") or supervisor_decision
                        if recommended_playbook is None:
                            recommended_playbook = (ev.get("detail") or {}).get("recommended_playbook")
                        break
                # 3. Analyst verdict category (live alerts carry no `category`;
                #    the analyst's classification is what drove the escalation
                #    and the playbook recommendation — selection must see it).
                for ev in case.get("timeline", []):
                    if ev.get("role") == "analyst" and ev.get("type") == "verdict":
                        alert_category = (ev.get("detail") or {}).get("category")
                        if alert_category:
                            break
        except Exception as e:  # noqa: BLE001 — resolution must not block
            logger.warning("supervisory decision resolution failed: %s", e)
    # APPROVAL GATE: a denied case must not execute a playbook.
    if supervisor_decision == "deny":
        return {
            "playbook": None, "tier": None, "blocked": True,
            "blocked_reason": f"supervisor denied case {case_id} — responder will not execute",
            "run_id": None, "recommended_from_case": recommended_playbook,
            "results": [], "error": None,
            "supervisor_decision": supervisor_decision,
        }
    # Normalize the alert so the SOAR recommendation/ticket read the live
    # Wazuh alert shape correctly: IP nested under data.src_ip, and the
    # analyst's category when the alert carries none (both from the case).
    alert = dict(alert)
    _d = alert.get("data") or {}
    if not alert.get("srcip") and _d.get("src_ip"):
        alert["srcip"] = _d["src_ip"]
    if not alert.get("category") and alert_category:
        alert["category"] = alert_category
    graph = build_graph().compile()
    state: ResponderState = {"alert": alert, "case_id": case_id, "dry_run": dry_run,
                             "recommended_playbook": recommended_playbook}
    result = graph.invoke(state)
    return {
        "playbook": result.get("playbook_name"),
        "tier": result.get("tier"),
        "blocked": result.get("blocked", False),
        "blocked_reason": result.get("blocked_reason"),
        "run_id": result.get("run_id"),
        "recommended_from_case": recommended_playbook,
        "results": result.get("results", []),
        "error": result.get("error"),
        "supervisor_decision": supervisor_decision,
    }


def cli() -> None:
    load_dotenv()  # entry point
    dry_run = "--dry-run" in sys.argv
    # CLI takes an alert JSON (e.g. from a file) or a synthetic test alert
    if len(sys.argv) > 1 and sys.argv[1].endswith(".json"):
        alert = json.loads(open(sys.argv[1]).read())
    else:
        alert = {"rule": {"id": 86601, "level": 8, "groups": ["ids", "suricata", "attack"]},
                 "srcip": "203.0.113.10", "agent": {"name": "network"}}
    out = run(alert, case_id="cli-test", dry_run=dry_run,
              recommended_playbook="block-src-ip")
    print(json.dumps(out, indent=2))
    if out.get("error"):
        sys.exit(1)


if __name__ == "__main__":
    cli()
