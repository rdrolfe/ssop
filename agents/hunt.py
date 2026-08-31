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
from tools.supervisory_tools import SupervisoryClient

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

def node_run_sweep(state: HuntState) -> HuntState:
    """Run the LIVE hunt sweep: every live-safe hunt over a short window.

    Cadence-safe by design:
    - Only hunts that query LIVE fields run (bots-* are replay/ground-truth
      only and always return clean on live data — skipped).
    - A non-clean finding on a hunt with an existing OPEN case ATTACHES a
      recheck event to that case (hunt-level recidivism) — no re-mint, and
      escalation fires once per case (re-arms when a human closes it).
    - TUNING-RESPECT: a human deny/operational on a hunt finding writes
      "hunt:<id>" to the tuning ledger (adjudicate now keys it). A tuned
      hunt is suppressed — recheck attached if a case is open, never a
      new case or ticket.
    - RE-ARM COOLDOWN: a finding whose case was closed recently (denied) is
      not instantly re-minted — prevents a chronic FP from re-ticketing every
      15m until a human tunes it.
    - Clean findings are logged, not filed (a 15m sweep must not spam the
      case spine with 'nothing to see').
    """
    try:
        days = int((state.get("params") or {}).get("days", 1))
        cooldown_s = int((state.get("params") or {}).get("cooldown", 86400))
        live_hunts = [hid for hid in hunter.HUNTS if not hid.startswith("bots-")]
        lines = [f"Live hunt sweep (days={days}, {len(live_hunts)} hunts):"]
        for hid in sorted(live_hunts):
            result = hunter.run_hunt(hid, days=days)
            finding = result.get("finding", "clean")
            esc = (finding == "suspicious"
                   and result["category"] in ESCALATE_CATEGORIES)
            # Tuning-respect: a human adjudication on this hunt (via the
            # synthetic "hunt:<id>" ledger key) suppresses it going forward.
            tuned = False
            try:
                from tools.tuning_tools import TuningLedger
                t = TuningLedger().lookup(f"hunt:{hid}")
                tuned = bool(t and t.get("decision") in ("auto_fp", "operational"))
            except Exception:  # noqa: BLE001 — tuning lookup must never break the sweep
                tuned = False
            if finding == "clean":
                lines.append(f"  {hid:<38} clean  ({result['events_scanned']} evts)")
                continue
            if tuned:
                # Suppressed: attach a recheck to an open case if one exists;
                # never mint a new case or ticket for a human-tuned hunt.
                existing = cases.recent_hunt_cases(hid, window_s=30 * 86400)
                if existing:
                    cid = existing[0]["case_id"]
                    cases.append_event(cid, "hunt", "recheck", {
                        "finding": finding, "confidence": result["confidence"],
                        "summary": result.get("summary", ""), "hunt_id": hid})
                    lines.append(f"  {hid:<38} {finding:<10} tuned-suppressed, recheck -> {cid}")
                else:
                    lines.append(f"  {hid:<38} {finding:<10} tuned-suppressed (no open case)")
                continue
            # Hunt-level recidivism: attach to an existing OPEN case for this hunt.
            existing = cases.recent_hunt_cases(hid, window_s=30 * 86400)
            if existing:
                cid = existing[0]["case_id"]
                cases.append_event(cid, "hunt", "recheck", {
                    "finding": finding, "confidence": result["confidence"],
                    "summary": result.get("summary", ""), "hunt_id": hid})
                # Escalate once per case (re-arms on close). Check timeline.
                already = any(
                    ev.get("role") == "hunt" and ev.get("type") == "escalated"
                    for ev in cases.get_case(cid).get("timeline", []))
                note = f"attached recheck -> {cid}"
                if esc and not already:
                    escalator.escalate(tier=2, actor="hunt",
                        title=f"[HUNT] {result['category'].upper()} finding in {result['name'][:50]}",
                        detail={"case_id": cid, "hunt_id": hid, "finding": finding,
                                "summary": result.get("summary", ""),
                                "notes": result.get("notes", []), "category": result["category"]})
                    # Verdict event so a later human adjudication (or the
                    # supervisory recommendation) has the real level/category
                    # — without it, supervise falls back to 6/operational and
                    # recommends no playbook for the finding.
                    cases.append_event(cid, "analyst", "verdict", {
                        "verdict": "escalate", "level": 12,
                        "category": result["category"], "hunt_id": hid})
                    cases.append_event(cid, "hunt", "escalated",
                                       {"hunt_id": hid, "finding": finding})
                    note += " + escalated"
                lines.append(f"  {hid:<38} {finding:<10} {note}")
                continue
            # Re-arm cooldown: a finding whose case was recently closed (denied)
            # must not instantly re-mint — a chronic FP would re-ticket every
            # sweep until a human tunes it.
            recent_any = cases.recent_hunt_cases(hid, window_s=cooldown_s,
                                                 include_closed=True)
            if recent_any:
                cid = recent_any[0]["case_id"]
                lines.append(f"  {hid:<38} {finding:<10} cooldown (case {cid} recently closed — not re-minting)")
                continue
            # New finding: mint a case, file, escalate if warranted.
            case = cases.open_case(
                source={"hunt_id": hid, "category": result["category"], "finding": finding},
                title=f"HUNT {result['category'].upper()}: {result['name'][:50]}")
            cid = case["case_id"]
            cases.append_event(cid, "hunt", "finding", {
                "finding": finding, "confidence": result["confidence"],
                "summary": result.get("summary", ""), "hunt_id": hid})
            note = f"case {cid}"
            if esc:
                escalator.escalate(tier=2, actor="hunt",
                    title=f"[HUNT] {result['category'].upper()} finding in {result['name'][:50]}",
                    detail={"case_id": cid, "hunt_id": hid, "finding": finding,
                            "summary": result.get("summary", ""),
                            "notes": result.get("notes", []), "category": result["category"]})
                # Verdict event so adjudication/recommendation sees the real
                # level/category (same as the existing-case path above).
                cases.append_event(cid, "analyst", "verdict", {
                    "verdict": "escalate", "level": 12,
                    "category": result["category"], "hunt_id": hid})
                cases.append_event(cid, "hunt", "escalated",
                                   {"hunt_id": hid, "finding": finding})
                note += " + escalated"
            lines.append(f"  {hid:<38} {finding:<10} {note}")
        state["result"] = "\n".join(lines)
    except Exception as e:
        state["error"] = f"Hunt sweep failed: {e}"
        state["result"] = state["error"]
    return state


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
            # Verdict event so adjudication/recommendation sees the real
            # level/category (same as the sweep path above).
            cases.append_event(case["case_id"], "analyst", "verdict", {
                "verdict": "escalate", "level": 12,
                "category": result["category"], "hunt_id": hunt_id})
            # Investigate the finding's entity (backend-aware) so the case
            # carries evidence + kill-chain, then adjudicate to surface a
            # recommended playbook — the human-facing outcome of the hunt.
            try:
                from tools.investigator import Investigator
                srcip = None
                for d in result.get("detail", []):
                    ed = d.get("event_data") or {}
                    srcip = (d.get("srcip") or (d.get("source") or {}).get("ip")
                             or (ed.get("source") or {}).get("ip")) or None
                    if srcip:
                        break
                if srcip:
                    ires = Investigator().investigate(srcip=srcip)
                    cases.append_event(case["case_id"], "analyst", "investigation", {
                        "entity": srcip,
                        "evidence_count": len(ires.get("evidence", [])),
                        "kill_chain": ires.get("kill_chain", []),
                        "severity": ires.get("severity", 0),
                        "severity_label": ires.get("severity_label", "low"),
                        "evidence": ires.get("evidence", []),
                    })
                    dec = SupervisoryClient().adjudicate_with_investigation(case["case_id"])
                    lines.append(f"Investigate: {srcip} -> {ires['severity_label']} "
                                 f"({ires['severity']}), {len(ires.get('evidence', []))} sources")
                    lines.append(f"Supervise: {dec['decision']} "
                                 f"| playbook: {dec.get('recommended_playbook')}")
                else:
                    lines.append("Investigate: no entity in finding (skipped)")
            except Exception:  # noqa: BLE001 — investigation must not break the hunt
                lines.append("Investigate: failed (see logs)")
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
        "hunt:sweep": "node_run_sweep",
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
wf.add_node("node_run_sweep", node_run_sweep)
wf.add_node("node_list_hunts", node_list_hunts)
wf.add_node("node_get_case", node_get_case)
wf.add_node("node_unknown", node_unknown)
wf.set_entry_point("router")
wf.add_conditional_edges("router", route_condition)
for n in ["node_run_hunt", "node_run_sweep", "node_list_hunts", "node_get_case", "node_unknown"]:
    wf.add_edge(n, END)
compiled = wf.compile()

COMMANDS = ["hunt:run", "hunt:sweep", "hunt:list", "hunt:case"]


def cli():
    if len(sys.argv) < 2:
        print("SSOP Hunt Role CLI\nUsage: python hunt.py <command> [target] [key=val ...]\n")
        for c in COMMANDS:
            print(f"  {c}")
        print("\nExamples:")
        print("  python hunt.py hunt:list")
        print("  python hunt.py hunt:run auth-success-from-unusual-src days=7")
        print("  python hunt.py hunt:sweep days=1")
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
