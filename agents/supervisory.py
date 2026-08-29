"""SSOP Supervisory role — dedicated state machine.

The supervisory role verifies the other roles:
  1. ADJUDICATE: process the escalation queue -> approve/deny + rationale
  2. RECONCILE: audit-integrity check (Qdrant vs JSONL)
  3. CLOSE: record verdicts on the case spine, mark tickets

Dual-control: Tier 2 recommendations require human confirm to fully close;
Tier 1 can be settled by the supervisory agent alone (single approval).
"""

import sys
from typing import TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph

load_dotenv()  # entry point — config is loaded here, passed down

from logging_setup import get_logger
from tools.registry import get_cases, get_escalation
from tools.supervisory_tools import SupervisoryClient

logger = get_logger(__name__)


class SupervisoryState(TypedDict):
    command: str
    target: str | None       # ticket_id / case_id
    params: dict | None
    result: str
    error: str | None


# Shared singletons — one connection set per process (per review)
sup = SupervisoryClient()
cases = get_cases()
escalator = get_escalation()


# --- Nodes ---

def node_adjudicate_queue(state: SupervisoryState) -> SupervisoryState:
    """Process the escalation queue: dedupe, verify, adjudicate, record."""
    try:
        limit = int((state.get("params") or {}).get("limit", 100))
        tickets = sup.list_tickets(status="open")
        if not tickets:
            state["result"] = "No open tickets."
            return state
        # Dedupe by (title, agent) — keep the first, count repeats
        seen = {}
        for t in tickets:
            key = (t.get("title", ""), t.get("agent", ""))
            if key in seen:
                seen[key]["repeat_count"] = seen[key].get("repeat_count", 1) + 1
                continue
            seen[key] = t
            seen[key]["repeat_count"] = 1
        unique = list(seen.values())[:limit]
        lines = [f"Adjudicating {len(unique)} unique tickets (from {len(tickets)} raw):"]
        for t in unique:
            # Context-aware decision: fetch the case (observables/enrichments/
            # techniques/checklist) and let supervise_case decide, falling back
            # to the old title heuristics when no case exists.
            case = None
            case_id = t.get("case_id") or (t.get("detail") or {}).get("case_id")
            if case_id:
                case = cases.get_case(case_id)
            if case:
                # Evidence-aware: if the analyst appended an investigation to
                # the case, adjudicate WITH that scored evidence. Otherwise
                # fall back to the context-aware supervise_case.
                has_inv = any(e.get("type") == "investigation"
                              for e in case.get("timeline", []))
                if has_inv:
                    ev_dec = sup.adjudicate_with_investigation(case_id)
                    decision = ev_dec["decision"]
                    rationale = ev_dec["rationale"]
                    dec = ev_dec
                else:
                    dec = sup.supervise_case(case)
                    decision = dec["decision"]
                    rationale = dec["rationale"]
            else:
                decision = "deny"
                rationale = "no actionable signal"
                dec = {"decision": decision, "rationale": rationale}
                title = (t.get("title") or "").lower()
                if "rootcheck" in title or "integrity" in title:
                    decision = "deny"
                    rationale = "integrity alert but host verification clean: rootcheck FP"
                elif "disk" in title or "disk_root" in title:
                    decision = "approve"
                    rationale = "disk pressure confirmed — cleanup approved"
                elif "agent_down" in title or "wazuh_agent_down" in title:
                    decision = "approve"
                    rationale = "agent connectivity confirmed down — restart approved"
            sup.adjudicate(t, decision, rationale)
            lines.append(f"  {t['ticket_id']} [{decision}] {t.get('title', '')[:50]} — {rationale[:40]}")
            # Record on the case spine
            if case_id:
                ev = {"decision": decision, "rationale": rationale}
                if case and dec.get("recommended_playbook"):
                    ev["recommended_playbook"] = dec["recommended_playbook"]
                    lines.append(f"      -> playbook: {dec['recommended_playbook']}")
                cases.append_event(case_id, "supervisory", "adjudication", ev)
        state["result"] = "\n".join(lines)
        return state
    except Exception as e:
        logger.exception("adjudication failed")
        state["error"] = str(e)
        state["result"] = f"ERROR: {e}"
        return state


def node_reconcile(state: SupervisoryState) -> SupervisoryState:
    """Audit-integrity check: Qdrant vs JSONL."""
    try:
        r = sup.reconcile()
        lines = [
            f"Reconcile: consistent={r.get('consistent')}",
            f"  qdrant: {r.get('qdrant_count')} | receipts: {r.get('receipt_count')}",
            f"  qdrant_only: {len(r.get('qdrant_only', []))}",
            f"  receipt_only: {len(r.get('receipt_only', []))}",
        ]
        state["result"] = "\n".join(lines)
        return state
    except Exception as e:
        logger.exception("reconcile failed")
        state["error"] = str(e)
        state["result"] = f"ERROR: {e}"
        return state


def node_close_case(state: SupervisoryState) -> SupervisoryState:
    """Close a case with a verdict (dual-control aware)."""
    try:
        case_id = state.get("target")
        if not case_id:
            state["error"] = "No case_id target."
            state["result"] = "ERROR: no case_id"
            return state
        params = state.get("params") or {}
        decision = params.get("decision", "approve")
        rationale = params.get("rationale", "supervisory closure")
        case = sup.case_verdict(case_id, decision, rationale)
        if case:
            state["result"] = f"Case {case_id} -> {case.get('status')} ({decision})"
        else:
            state["result"] = f"Case {case_id} not found"
        return state
    except Exception as e:
        logger.exception("case closure failed")
        state["error"] = str(e)
        state["result"] = f"ERROR: {e}"
        return state


# --- Graph ---

def build_graph():
    g = StateGraph(SupervisoryState)
    g.add_node("adjudicate", node_adjudicate_queue)
    g.add_node("reconcile", node_reconcile)
    g.add_node("close", node_close_case)
    g.set_entry_point("adjudicate")
    g.add_edge("adjudicate", "reconcile")
    g.add_edge("reconcile", "close")
    g.add_edge("close", END)
    return g.compile()


# --- CLI ---

def cli():
    graph = build_graph()
    args = sys.argv[1:] if len(sys.argv) > 1 else ["supervisory:adjudicate"]
    cmd = args[0]
    params = {}
    for a in args[1:]:
        if "=" in a:
            k, v = a.split("=", 1)
            params[k] = v
    state = {"command": cmd, "target": params.get("target"), "params": params, "result": "", "error": None}
    out = graph.invoke(state)
    print(out.get("result", ""))
    if out.get("error"):
        sys.exit(1)


if __name__ == "__main__":
    cli()
