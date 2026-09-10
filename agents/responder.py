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

import inspect
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
from tools.responder_steps import STEP_REGISTRY, StepResult, run_step

logger = get_logger(__name__)

VALID_TIERS = ("tier0", "tier1", "tier2")


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


def guard_check(playbook: Playbook, alert: dict[str, Any],
                ctx: dict[str, Any] | None = None) -> str | None:
    """Return a protected-entity reason if the playbook must be blocked.

    Resolves every step's target params (host, src_ip, target, ip) against the
    protected set — AFTER template resolution when a context is supplied, so a
    placeholder like {{alert.srcip}} is guarded by its RESOLVED value, not the
    literal string. Fail-closed: any protected target blocks the WHOLE
    playbook (per the trigger-matching-guard decision).
    """
    for step in playbook.steps:
        params = step.get("params", {})
        if ctx is not None:
            params = _resolve_params(params, ctx)
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


def build_alert_context(alert: dict[str, Any], case_id: str = "") -> dict[str, Any]:
    """Build the canonical playbook template context from a case/alert.

    Covers every placeholder the shipped playbooks use: alert.agent, alert.service,
    alert.srcip, alert.path, alert.file, alert.backup. Live Wazuh alerts nest
    values (agent.name, data.syscheck.file) — flatten them consistently.
    """
    data = alert.get("data") or {}
    syscheck = data.get("syscheck") or {}
    agent = alert.get("agent")
    if isinstance(agent, dict):
        agent = agent.get("name", "")
    path = (alert.get("path") or alert.get("file") or syscheck.get("path")
            or syscheck.get("file") or data.get("path") or data.get("file") or "")
    return {
        "case_id": case_id,
        "alert.srcip": alert.get("srcip") or data.get("src_ip") or "",
        "alert.agent": agent or "",
        "alert.service": alert.get("service") or data.get("service") or "",
        "alert.path": path,
        "alert.file": path,
        "alert.backup": alert.get("backup") or syscheck.get("backup") or data.get("backup") or "",
    }


def find_unresolved(params: dict[str, Any]) -> list[str]:
    """Return param keys that still hold an unresolved or empty placeholder."""
    bad = []
    for k, v in params.items():
        if isinstance(v, str) and "{{" in v:
            bad.append(k)
        elif "{{" in str(v):
            bad.append(k)
    return bad


def validate_playbook_steps(pb: Playbook) -> str | None:
    """Validate every step against the registered step signatures.

    Returns None if all steps bind, else a human-readable reason. Invalid
    playbooks cannot load as executable candidates (fail-closed).
    """
    for step in pb.steps:
        name = step.get("step", "")
        fn = STEP_REGISTRY.get(name)
        if fn is None:
            return f"unknown step: {name}"
        try:
            inspect.signature(fn).bind(**step.get("params", {}))
        except TypeError as e:
            return f"step {name}: bad params: {e}"
    return None


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

def _resolve_step_params(step: dict[str, Any], ctx: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Resolve one step's params; reject unresolved/missing placeholders.

    A placeholder that still contains {{...}} after resolution, or that
    resolved to an empty value for a REQUIRED param, is an error — the
    approved parameters must be exactly the executed parameters.
    """
    name = step.get("step", "")
    params = _resolve_params(step.get("params", {}), ctx)
    fn = STEP_REGISTRY.get(name)
    optional: set[str] = set()
    if fn is not None:
        for pname, p in inspect.signature(fn).parameters.items():
            if p.default is not inspect.Parameter.empty:
                optional.add(pname)
    missing = []
    for k, v in params.items():
        if isinstance(v, str) and "{{" in v:
            missing.append(k)
        elif v == "" and k not in optional and _is_placeholder(step.get("params", {}).get(k)):
            missing.append(f"{k} (no context value)")
    if missing:
        return params, f"unresolved params for step {name}: {', '.join(missing)}"
    return params, None


def _is_placeholder(val: Any) -> bool:
    return isinstance(val, str) and "{{" in val


def execute_playbook(pb: Playbook, ctx: dict[str, Any], dry_run: bool = False) -> list[dict[str, Any]]:
    """Execute a playbook's steps strictly sequentially; stop on first failure.

    Params are resolved from ctx first; any unresolved placeholder aborts the
    playbook with ZERO executed steps (fail-closed).
    """
    results: list[dict[str, Any]] = []
    for step in pb.steps:
        name = step.get("step", "")
        params, err = _resolve_step_params(step, ctx)
        if err:
            logger.error("playbook %s step %s: %s", pb.name, name, err)
            results.append({"step": name, "ok": False, "detail": err})
            break
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
    """Candidate match + recommendation gate. Invalid playbooks are skipped."""
    alert = state.get("alert", {})
    pb_name = state.get("playbook_name")
    recommended = state.get("recommended_playbook") if "recommended_playbook" in state else pb_name
    playbooks = load_playbooks()
    candidates = select_candidates(alert, playbooks, recommended=recommended)
    if not candidates:
        return {**state, "error": "no candidate playbook", "results": []}
    pb = candidates[0]
    invalid = validate_playbook_steps(pb)
    if invalid:
        logger.error("playbook %s rejected: %s", pb.name, invalid)
        return {**state, "error": f"invalid playbook {pb.name}: {invalid}", "results": []}
    if pb.approval not in VALID_TIERS:
        return {**state, "error": f"invalid approval tier {pb.approval!r} on {pb.name}", "results": []}
    return {**state, "playbook_name": pb.name, "tier": pb.approval}


def _get_pb(state: ResponderState) -> Playbook:
    """Re-lookup the playbook by name (objects don't survive state channels)."""
    pbs = load_playbooks()
    pb = pbs.get(state.get("playbook_name", ""))
    if pb is None:
        raise KeyError(f"playbook {state.get('playbook_name')} not found")
    return pb


def node_guard(state: ResponderState) -> ResponderState:
    """Self-infliction guard — fail-closed before approval.

    The guard runs on RESOLVED targets so a protected host/IP hidden behind a
    template placeholder is still caught. Missing values fail closed too.
    """
    pb = _get_pb(state)
    alert = state.get("alert", {})
    ctx = build_alert_context(alert, state.get("case_id", ""))
    # Unresolved params must block before any approval path is taken.
    for step in pb.steps:
        _, err = _resolve_step_params(step, ctx)
        if err:
            logger.error("playbook %s BLOCKED: %s", pb.name, err)
            return {**state, "blocked": True, "blocked_reason": err}
    reason = guard_check(pb, alert, ctx=ctx)
    if reason:
        logger.warning("playbook %s BLOCKED: protected entity %s", pb.name, reason)
        return {**state, "blocked": True, "blocked_reason": f"protected-entity ({reason})"}
    return state


def node_tier1_execute(state: ResponderState) -> ResponderState:
    """Tier-0/tier-1 execute immediately at dispatch (no approval ticket)."""
    pb = _get_pb(state)
    ctx = build_alert_context(state.get("alert", {}), state.get("case_id", ""))
    results = execute_playbook(pb, ctx, dry_run=state.get("dry_run", False))
    return {**state, "results": results}


def node_tier2_ticket(state: ResponderState) -> ResponderState:
    """Tier-2 creates an escalation ticket with run_id + payload, no execution."""
    pb = _get_pb(state)
    run_id = str(uuid.uuid4())[:12]
    ctx = build_alert_context(state.get("alert", {}), state.get("case_id", ""))
    steps = pb.steps
    resolved: list[dict[str, Any]] = []
    for step in steps:
        params, err = _resolve_step_params(step, ctx)
        if err:
            logger.error("tier2 ticket aborted for %s: %s", pb.name, err)
            return {**state, "blocked": True, "blocked_reason": err,
                    "results": [{"step": step.get("step", ""), "ok": False, "detail": err}]}
        resolved.append(params)
    detail = {
        "run_id": run_id,
        "playbook": pb.name,
        "steps": pb.steps,
        "resolved_params": resolved,
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

    # guard branch: blocked -> END (fail-closed); explicit tier branches only.
    # tier0 and tier1 execute directly; tier2 goes to the approval queue;
    # unknown tiers never reach a node (validated in node_select too).
    def route_guard(state: ResponderState) -> str:
        if state.get("blocked"):
            return "blocked_end"
        tier = state.get("tier", "")
        if tier == "tier0" or tier == "tier1":
            return "tier1_execute"
        if tier == "tier2":
            return "tier2_ticket"
        logger.error("unknown approval tier %r — refusing to route", tier)
        return "blocked_end"

    g.add_conditional_edges("guard", route_guard, {
        "tier1_execute": "tier1_execute",
        "tier2_ticket": "tier2_ticket",
        "blocked_end": END,
    })
    g.add_edge("tier1_execute", END)
    g.add_edge("tier2_ticket", END)
    return g


def _consume_approved_run(case_id: str, dry_run: bool = False) -> dict[str, Any] | None:
    """Find an approved tier-2 ticket for this case and execute it ONCE.

    Consumes the stored run_id's resolved_params (the exact reviewed payload —
    never re-resolved), enforces expiry and protected targets, records the
    step results as a case event (which also marks the run as executed so a
    duplicate delivery or restart cannot re-run it). Returns the run-style
    result dict, or None when no consumable approved run exists.
    """
    from tools.case_tools import CaseStore
    try:
        tickets = get_escalation().list_tickets(status="adjudicated")
    except Exception:  # noqa: BLE001 — ticket read failure must not fall through to re-ticketing silently
        logger.exception("approved-run lookup failed for case %s", case_id)
        return None
    try:
        store = CaseStore()
        case = store.get_case(case_id) or {}
        executed_runs = {
            (ev.get("detail") or {}).get("run_id")
            for ev in case.get("timeline", [])
            if ev.get("type") == "responder_execution"
        }
    except Exception:  # noqa: BLE001 — fail closed: cannot verify idempotency
        logger.exception("case read failed while consuming approved run for %s", case_id)
        return {"playbook": None, "tier": "tier2", "blocked": True,
                "blocked_reason": f"case {case_id} unreadable — cannot verify approved run",
                "run_id": None, "recommended_from_case": None, "results": [],
                "error": None, "supervisor_decision": "approved"}
    for t in tickets:
        if (t.get("decision") or "").lower() not in ("approve", "approved"):
            continue
        d = t.get("detail") or {}
        run_id = d.get("run_id")
        if not run_id or d.get("case_id") != case_id:
            continue
        resolved = d.get("resolved_params")
        steps = d.get("steps") or []
        if not isinstance(resolved, list) or len(resolved) != len(steps):
            logger.error("approved ticket %s has malformed payload — skipping", t.get("ticket_id"))
            continue
        if run_id in executed_runs:
            logger.info("run %s already executed on case %s — not re-running", run_id, case_id)
            continue
        # expiry
        try:
            expires = datetime.fromisoformat(d["expires"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires:
                logger.info("approved run %s expired — not executing", run_id)
                try:
                    store.append_event(case_id, "responder", "run_expired",
                                       {"run_id": run_id, "ticket_id": t.get("ticket_id")})
                except Exception:  # noqa: BLE001
                    logger.exception("failed to record expiry event on case %s", case_id)
                continue
        except (KeyError, ValueError):
            logger.error("approved ticket %s has no valid expiry — skipping", t.get("ticket_id"))
            continue
        # protected targets on the STORED payload (fail-closed)
        blocked_field = None
        for params in resolved:
            for field in ("host", "src_ip", "target", "ip"):
                val = (params or {}).get(field)
                if val and _is_protected(str(val)):
                    blocked_field = f"{field}={val}"
                    break
            if blocked_field:
                break
        if blocked_field:
            reason = f"protected-entity ({blocked_field}) in approved run {run_id}"
            logger.warning("approved run BLOCKED: %s", reason)
            try:
                store.append_event(case_id, "responder", "run_blocked",
                                   {"run_id": run_id, "reason": reason})
            except Exception:  # noqa: BLE001
                logger.exception("failed to record blocked event on case %s", case_id)
            return {"playbook": d.get("playbook"), "tier": "tier2", "blocked": True,
                    "blocked_reason": reason, "run_id": run_id,
                    "recommended_from_case": None, "results": [], "error": None,
                    "supervisor_decision": "approved"}
        # execute the reviewed payload exactly, sequentially
        results: list[dict[str, Any]] = []
        for step, params in zip(steps, resolved):
            name = step.get("step", "")
            if dry_run:
                results.append({"step": name, "ok": True, "detail": "DRY-RUN (not executed)"})
                continue
            results.append(run_step(name, params or {}).to_dict())
        detail = {"run_id": run_id, "ticket_id": t.get("ticket_id"),
                  "playbook": d.get("playbook"), "results": results,
                  "dry_run": dry_run}
        if not dry_run:
            # The event doubles as the executed-once marker — only real
            # executions consume the run; dry-runs leave it consumable.
            try:
                store.append_event(case_id, "responder", "responder_execution", detail)
            except Exception:  # noqa: BLE001 — execution happened; the audit failure must be loud
                logger.exception("failed to persist execution event for run %s on case %s", run_id, case_id)
        return {"playbook": d.get("playbook"), "tier": "tier2",
                "blocked": any(not r.get("ok") for r in results),
                "blocked_reason": None, "run_id": run_id,
                "recommended_from_case": None, "results": results, "error": None,
                "supervisor_decision": "approved",
                "executed_from_ticket": t.get("ticket_id")}
    return None


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
    case = None
    if case_id:
        try:
            from tools.case_tools import CaseStore
            case = CaseStore().get_case(case_id)
        except Exception:  # noqa: BLE001 — fail closed: authority cannot be established
            logger.exception("case lookup failed for %s — blocking execution", case_id)
            return {
                "playbook": None, "tier": None, "blocked": True,
                "blocked_reason": f"case {case_id} decision store unavailable — responder will not execute",
                "run_id": None, "recommended_from_case": recommended_playbook,
                "results": [], "error": None, "supervisor_decision": None,
            }
        if case is None:
            # Missing case = missing authority. Fail closed for case-bound runs.
            return {
                "playbook": None, "tier": None, "blocked": True,
                "blocked_reason": f"case {case_id} not found — responder will not execute",
                "run_id": None, "recommended_from_case": recommended_playbook,
                "results": [], "error": None, "supervisor_decision": None,
            }
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
        # 2b. INFRA EVENTS: the ROUTER is the approving authority (the case
        # was minted by dispatch_infra with assignee=responder — there is no
        # supervisory pass for fleet-sysadmin events, by operator policy
        # 2026-09-09). A router adjudication event with decision=approve
        # authorizes tier0/tier1 playbooks. Tier2 STILL requires the
        # supervisory run_id approval path — the router never authorizes
        # quarantine/block/revert-class actions.
        if supervisor_decision is None:
            assignee = (case.get("assignee") or "").lower()
            for ev in reversed(case.get("timeline", [])):
                if (ev.get("role") == "router" and ev.get("type") == "adjudication"
                        and (ev.get("detail") or {}).get("decision") == "approve"):
                    supervisor_decision = "approve"
                    if recommended_playbook is None:
                        recommended_playbook = (ev.get("detail") or {}).get(
                            "recommended_playbook")
                    logger.info("infra case %s: router adjudication authorizes "
                                "execution (assignee=%s)", case_id, assignee)
                    break
        # 3. Analyst verdict category (live alerts carry no `category`;
        #    the analyst's classification is what drove the escalation
        #    and the playbook recommendation — selection must see it).
        for ev in case.get("timeline", []):
            if ev.get("role") == "analyst" and ev.get("type") == "verdict":
                alert_category = (ev.get("detail") or {}).get("category")
                if alert_category:
                    break
    # APPROVAL GATE (fail closed): execution requires an EXPLICIT approving
    # decision. deny / fp / false_positive / operational / undecided / absent
    # / malformed all block. Case-free runs remain an explicit tier-0 policy.
    if case_id and supervisor_decision not in ("approve", "approved"):
        reason = f"supervisor decision for case {case_id} is {supervisor_decision!r} — responder will not execute (explicit approval required)"
        logger.warning(reason)
        return {
            "playbook": None, "tier": None, "blocked": True,
            "blocked_reason": reason,
            "run_id": None, "recommended_from_case": recommended_playbook,
            "results": [], "error": None, "supervisor_decision": supervisor_decision,
        }
    # APPROVED-CONSUMPTION: an approved case with a stored tier-2 run executes
    # that exact reviewed payload ONCE (no new ticket is issued).
    if case_id and case and not dry_run:
        consumed = _consume_approved_run(case_id)
        if consumed is not None:
            return consumed
    elif case_id and case and dry_run:
        # Dry-run preview of the approved run, if any (never consumes it).
        consumed = _consume_approved_run(case_id, dry_run=True)
        if consumed is not None:
            return consumed
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
    results = result.get("results", [])
    # Persist responder results on the case spine so execution is auditable.
    if case_id and results and not dry_run:
        try:
            from tools.case_tools import CaseStore
            CaseStore().append_event(case_id, "responder", "execution", {
                "playbook": result.get("playbook_name"),
                "tier": result.get("tier"),
                "run_id": result.get("run_id"),
                "results": results,
            })
        except Exception:  # noqa: BLE001 — audit failure must not mask the run result
            logger.exception("failed to persist responder results on case %s", case_id)
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
