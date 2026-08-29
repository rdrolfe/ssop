"""SSOP Hunt role — dedicated state machine.

The hunter is proactive: it tests hypotheses against SIEM telemetry,
looking for patterns (compromise, misconfig, blind spots) rather than
reacting to individual alerts (that's the analyst's job).

Loop: HYPOTHESIS -> QUERY -> ANALYZE -> CASE -> (ESCALATE | FILE)
"""

import os
import sys
import json
from typing import TypedDict, Optional
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END

load_dotenv()  # entry point — config is loaded here, passed down

from logging_setup import get_logger
from tools.registry import get_hunt, get_cases, get_escalation

logger = get_logger(__name__)


class HuntState(TypedDict):
    command: str
    target: Optional[str]       # hunt_id
    params: Optional[dict]
    result: str
    error: Optional[str]


# Shared singletons — one connection set per process (per review)
hunter = get_hunt()
cases = get_cases()
escalator = get_escalation()

ESCALATE_CATEGORIES = {"lateral-movement", "defense-evasion", "privilege-escalation"}


# --- Nodes ---

def node_run_hunt(state: HuntState) -> HuntState:
    """Run a hunt from the library, analyze, file/escalate findings."""
    try:
        hunt_id = state.get("target") or "auth-success-from-unusual-src"
        days = int((state.get("params") or {}).get("days", 7))
        result = hunter.run_hunt(hunt_id, days=days)
        finding = result.get("finding", "clean")

        lines = [
            f"Hunt: {result['name']} ({result['hunt_id']})",
            f"Hypothesis: {result['hypothesis']}",
            f"Finding: {finding} | confidence {result['confidence']}",
            f"Summary: {result.get('summary', '')}",
            f"Events scanned: {result['events_scanned']}",
        ]

        # Always file the hunt result on the case spine (memory of what was tested)
        case = cases.open_case(
            source={"hunt_id": hunt_id, "category": result["category"], "finding": finding},
            title=f"HUNT {result['category'].upper()}: {result['name'][:50]}",
        )
        cases.append_event(case["case_id"], "hunt", "finding", {
            "finding": finding, "confidence": result["confidence"], "summary": result.get("summary", ""),
            "hunt_id": hunt_id,
        })

        # Escalate suspicious findings in attack-relevant categories
        should_escalate = finding == "suspicious" and result["category"] in ESCALATE_CATEGORIES
        if should_escalate:
            esc = escalator.escalate(
                tier=2,
                title=f"[HUNT] {result['category'].upper()} finding in {result['name'][:50]}",
                actor="hunt",
                detail={
                    "case_id": case["case_id"],
                    "hunt_id": hunt_id,
                    "finding": finding,
                    "summary": result.get("summary", ""),
                    "notes": result.get("notes", []),
                    "category": result["category"],
                },
            )
            lines.append(f"Escalated -> case={case['case_id']} queued={esc['delivery'].get('delivered')}")
        else:
            lines.append(f"Filed as {finding} -> case={case['case_id']} (no escalation needed)")

        for note in result.get("notes", [])[:5]:
            lines.append(f"  * {note}")
        state["result"] = "\n".join(lines)
    except Exception as e:
        state["error"] = f"Hunt failed: {e}"
        state["result"] = state["error"]
    return state


def node_list_hunts(state: HuntState) -> HuntState:
    """List available hunts."""
    try:
        lines = ["Available hunts:"]
        for hid, spec in hunter.HUNTS.items():
            lines.append(f"  {hid:<35} [{spec['category']}] {spec['name']}")
        lines.append("\nUsage: python hunt.py hunt:run <hunt_id> days=7")
        state["result"] = "\n".join(lines)
    except Exception as e:
        state["error"] = str(e)
        state["result"] = state["error"]
    return state


def node_get_case(state: HuntState) -> HuntState:
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


# --- Router ---

def route_condition(state: HuntState) -> str:
    mapping = {
        "hunt:run": "node_run_hunt",
        "hunt:list": "node_list_hunts",
        "hunt:case": "node_get_case",
    }
    return mapping.get(state.get("command", ""), "node_unknown")


def node_unknown(state: HuntState) -> HuntState:
    state["error"] = f"Unknown command: {state.get('command')}"
    state["result"] = state["error"]
    return state


# --- Build Graph ---
wf = StateGraph(HuntState)
wf.add_node("router", lambda s: s)
wf.add_node("node_run_hunt", node_run_hunt)
wf.add_node("node_list_hunts", node_list_hunts)
wf.add_node("node_get_case", node_get_case)
wf.add_node("node_unknown", node_unknown)
wf.set_entry_point("router")
wf.add_conditional_edges("router", route_condition)
for n in ["node_run_hunt", "node_list_hunts", "node_get_case", "node_unknown"]:
    wf.add_edge(n, END)
compiled = wf.compile()

COMMANDS = ["hunt:run", "hunt:list", "hunt:case"]


def cli():
    if len(sys.argv) < 2:
        print("SSOP Hunt Role CLI\nUsage: python hunt.py <command> [target] [key=val ...]\n")
        for c in COMMANDS:
            print(f"  {c}")
        print("\nExamples:")
        print("  python hunt.py hunt:list")
        print("  python hunt.py hunt:run auth-success-from-unusual-src days=7")
        print("  python hunt.py hunt:case case-abc123")
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
