"""SSOP Analyst role — dedicated state machine.

Separation of duties: the analyst is a read-only investigator. It queries
the Wazuh indexer, classifies alerts, mints case_ids, records verdicts on
the incident spine, and escalates high-severity findings to the supervisory
layer via the escalation client. It has NO infrastructure tools.

Loop: INGEST -> CLASSIFY -> CASE -> VERDICT -> (ESCALATE | NOTE)
"""

import json
import sys
from typing import Any, TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph

load_dotenv()  # entry point — config is loaded here, passed down

from logging_setup import get_logger
from tools.registry import get_analyst, get_cases, get_escalation

logger = get_logger(__name__)


class AnalystState(TypedDict):
    command: str
    target: str | None       # agent name / case_id / limit
    params: dict | None
    result: str
    error: str | None


# Shared singletons — one connection set per process (per review)
analyst = get_analyst()
cases = get_cases()
escalator = get_escalation()


# --- Nodes ---

def process_alert(alert: dict[str, Any], escalate: bool = True) -> dict[str, Any]:
    """Full per-alert analyst write path: classify, mint/attach case, escalate.

    Shared by the live sweep (node_analyze_recent) and the verify driver
    (drive_analyst with case:true) so the matrix asserts the REAL write path,
    not a logic-only proxy. Returns {verdict, case_id, attached, escalated,
    observables, enrichments} — never raises (fail-closed to a note).

    `escalate=False` (verify) mints the case + records verdict/investigation
    but SKIPS the escalation ticket — a synthetic alert must not pollute the
    human-facing queue. The case-mint is what case:true asserts.
    """
    try:
        v = analyst.verdict(alert)
    except Exception as e:  # noqa: BLE001 — a crash must not take down the sweep
        logger.warning("verdict failed (treating as note): %s", e)
        return {"verdict": "note", "case_id": None, "attached": False,
                "escalated": False, "observables": [], "enrichments": []}
    out: dict[str, Any] = {"verdict": v["verdict"], "case_id": None,
                           "attached": False, "escalated": False,
                           "observables": [], "enrichments": []}
    if not (v["verdict"] == "escalate" or v.get("existing_chain")):
        return out
    # Extract IOCs (adopted SO concept — first-class observables on the case).
    from tools.enrichment import EnrichmentClient
    from tools.observables import extract_observables

    obs = extract_observables(v)
    out["observables"] = obs
    enrichments = []
    if obs:
        try:
            enrichments = EnrichmentClient().enrich_many(obs)
        except Exception as e:  # noqa: BLE001 — enrichment must not block
            logger.warning("enrichment failed (continuing): %s", e)
    out["enrichments"] = enrichments
    # Stateful: repeated entity pair attaches to the open chain, never mints.
    if v.get("existing_chain"):
        cid = v["existing_chain"]
        cases.append_event(
            cid, "analyst", "verdict",
            {"verdict": "escalate", "rationale": v["rationale"], "observables": obs,
             "enrichments": enrichments, **{k: v[k] for k in ("level", "category", "agent")}},
        )
        out.update({"case_id": cid, "attached": True})
        return out
    case = cases.open_case(
        source={"alert_id": v["alert_id"], "agent": v["agent"], "rule_desc": v["description"],
                "rule_id": (v.get("rule") or {}).get("id"),
                "srcip": v.get("entity_srcip"), "dstip": v.get("entity_dstip")},
        title=f"{v['category'].upper()} alert lvl={v['level']} on {v['agent']}",
        observables=obs,
        enrichments=enrichments,
    )
    out["case_id"] = case["case_id"]
    # INVESTIGATE: correlate the case entities across sources and append the
    # kill-chain hypothesis + evidence to the timeline.
    try:
        from tools.investigator import Investigator
        inv = Investigator()
        srcip = (obs[0].get("value") if obs else "") or alert.get("srcip", "")
        inv_res = inv.investigate(srcip=srcip)
        if inv_res["evidence"]:
            cases.append_event(
                case["case_id"], "analyst", "investigation",
                {"hypothesis": inv_res["hypothesis"],
                 "evidence": inv_res["evidence"],
                 "kill_chain": inv_res["kill_chain"]},
            )
    except Exception as e:  # noqa: BLE001 — investigation must not block escalation
        logger.warning("investigation failed (continuing): %s", e)
    cases.append_event(
        case["case_id"], "analyst", "verdict",
        {"verdict": "escalate", "rationale": v["rationale"], **{k: v[k] for k in ("level", "category", "agent")}},
    )
    if escalate:
        esc = escalator.escalate(
            tier=2,
            title=f"[ANALYST] {case['case_id']} {v['description'][:60]}",
            detail={"case_id": case["case_id"], **v},
            actor="analyst",  # who decided; v["agent"] is the alert source
        )
        out["escalated"] = bool(esc.get("delivery", {}).get("delivered", False))
    return out


def node_analyze_recent(state: AnalystState) -> AnalystState:
    """Pull recent alerts, classify, open cases for escalatable ones."""
    try:
        limit = int((state.get("params") or {}).get("limit", 10))
        min_level = int((state.get("params") or {}).get("min_level", 0))
        alerts = analyst.recent_alerts(limit=limit, min_level=min_level)
        if not alerts:
            state["result"] = "No alerts found."
            return state
        lines = []
        opened = 0
        for alert in alerts:
            v = analyst.verdict(alert)
            # Tolerate backend field differences: Wazuh uses 'timestamp'/
            # 'agent.name'; SO events use '@timestamp' and varied agent shapes.
            ts = v.get("timestamp") or v.get("@timestamp") or alert.get("@timestamp") or ""
            ag = v.get("agent") or (alert.get("agent") or {}).get("name") or (alert.get("agent") or "unknown")
            if isinstance(ag, dict):
                ag = ag.get("name", "unknown")
            lines.append(
                f"[{str(ts)[:19]}] agent={ag} lvl={v.get('level', 0)} "
                f"{v.get('category', 'operational'):<13} -> {v['verdict']}"
            )
            res = process_alert(alert)
            if res.get("case_id"):
                if res.get("attached"):
                    lines.append(f"    attached to chain={res['case_id']} (repeated entity) [+{len(res.get('observables', []))} observables, {len(res.get('enrichments', []))} enrichments]")
                else:
                    lines.append(f"    case={res['case_id']} escalated -> {res.get('escalated')}")
                opened += 1
        state["result"] = f"Analyzed {len(alerts)} alerts, escalated {opened}:\n" + "\n".join(lines)
    except Exception as e:
        state["error"] = f"Analyze failed: {e}"
        state["result"] = state["error"]
    return state


def node_get_case(state: AnalystState) -> AnalystState:
    """Fetch a case by id from the incident spine."""
    try:
        case_id = state.get("target") or ""
        if not case_id:
            state["result"] = "Usage: target=<case_id>"
            return state
        case = cases.get_case(case_id)
        state["result"] = json.dumps(case, indent=2) if case else f"Case {case_id} not found"
    except Exception as e:
        state["error"] = f"Case lookup failed: {e}"
        state["result"] = state["error"]
    return state


def node_reconcile(state: AnalystState) -> AnalystState:
    """Audit-integrity check: Qdrant vs JSONL case stores (supervisory duty)."""
    try:
        state["result"] = json.dumps(cases.reconcile(), indent=2)
    except Exception as e:
        state["error"] = f"Reconcile failed: {e}"
        state["result"] = state["error"]
    return state


# --- Router ---

def route_condition(state: AnalystState) -> str:
    cmd = state.get("command", "")
    mapping = {
        "analyst:recent": "node_analyze_recent",
        "analyst:case": "node_get_case",
        "analyst:reconcile": "node_reconcile",
    }
    return mapping.get(cmd, "node_unknown")


def node_unknown(state: AnalystState) -> AnalystState:
    state["error"] = f"Unknown command: {state.get('command')}"
    state["result"] = state["error"]
    return state


# --- Build Graph ---
wf = StateGraph(AnalystState)
wf.add_node("node_analyze_recent", node_analyze_recent)
wf.add_node("node_get_case", node_get_case)
wf.add_node("node_reconcile", node_reconcile)
wf.add_node("node_unknown", node_unknown)
wf.set_entry_point("router")
wf.add_node("router", lambda s: s)
wf.add_conditional_edges("router", route_condition)
for n in ["node_analyze_recent", "node_get_case", "node_reconcile", "node_unknown"]:
    wf.add_edge(n, END)
compiled = wf.compile()

COMMANDS = ["analyst:recent", "analyst:case", "analyst:reconcile"]


def cli():
    if len(sys.argv) < 2:
        print("SSOP Analyst Role CLI\nUsage: python analyst.py <command> [target] [key=val ...]\n")
        for c in COMMANDS:
            print(f"  {c}")
        print("\nExamples:")
        print("  python analyst.py analyst:recent limit=5 min_level=3")
        print("  python analyst.py analyst:case case-abc123")
        print("  python analyst.py analyst:reconcile")
        sys.exit(0)
    cmd = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else ""
    params = {}
    for a in sys.argv[3:]:
        if "=" in a:
            k, v = a.split("=", 1)
            params[k] = v
    result = compiled.invoke({
        "command": cmd, "target": target, "params": params,
        "result": "", "error": None,
    })
    if result.get("error"):
        print(f"ERROR: {result['error']}")
    else:
        print(result.get("result", "(no output)"))


if __name__ == "__main__":
    cli()
