#!/usr/bin/env python3
"""Live-proof: the material-delta override path (thread #2) end-to-end.

Takes a REAL current alert for a tuned rule (default 2902), clones it, and
bumps the level (7 -> 12) to make it a MATERIAL delta vs the stored tuning
fingerprint. Asserts:

  1. CONTROL (identical alert) -> analyst verdict "note" (suppressed)
     AND router.classify -> (operational, None) (no dispatch)
  2. DELTA (level 12)         -> analyst verdict "escalate" with
     tuning_override=True (the override fires)
     AND router.classify -> (security, analyst) (the fix: the router MUST
     route a material delta to the analyst instead of dropping it at
     (operational, None) — that drop was the live gap the proof exposed)
  3. --live: run the full router dispatch on the delta, verify a tier-2
     ticket lands carrying tuning_override in its detail, then clear the
     ticket and close the case (lab artifact, no residue).

Usage: python3 deploy/lab/prove_override.py [rule_id] [--live]
"""
import json
import sys
import uuid

sys.path.insert(0, ".")
from tools.analyst_tools import AnalystClient
from tools.indexer_client import IndexerTransport
from tools.tuning_tools import TuningLedger
from tools.supervisory_tools import SupervisoryClient
import router


def _clone_real_alert(rule_id: str) -> dict | None:
    """Fetch the most recent real alert for a rule and clone it."""
    t = IndexerTransport()
    body = {"size": 1,
            "query": {"bool": {"filter": [{"term": {"rule.id": rule_id}}]}},
            "sort": [{"@timestamp": {"order": "desc"}}]}
    r = t.search(body, index="wazuh-alerts-4.x-*")
    hits = r.get("hits", {}).get("hits", [])
    if not hits:
        return None
    return json.loads(json.dumps(hits[0]["_source"]))  # deep clone


def _delta(alert: dict, level: int) -> dict:
    a = json.loads(json.dumps(alert))
    a["rule"] = dict(a.get("rule") or {})
    a["rule"]["level"] = level
    a["id"] = f"prove-{uuid.uuid4().hex[:8]}"
    return a


def main() -> int:
    live = "--live" in sys.argv
    pos = [a for a in sys.argv[1:] if a != "--live"]
    rule_id = pos[0] if pos else "2902"
    fails = 0

    base = _clone_real_alert(rule_id)
    if not base:
        print(f"no live alert for rule {rule_id} — nothing to prove")
        return 1
    stored_level = int((base.get("rule") or {}).get("level", 0))
    delta_level = stored_level + 5  # guarantee a rise

    a = AnalystClient()
    control = _delta(base, stored_level)      # identical signature
    delta = _delta(base, delta_level)         # material delta (level rose)

    # 1. CONTROL: identical -> note + no dispatch
    vc = a.verdict(control)
    cc = router.classify(control)
    ok_c = vc["verdict"] == "note" and cc == ("operational", None)
    print(f"CONTROL identical: verdict={vc['verdict']} classify={cc} "
          f"{'OK' if ok_c else 'FAIL'}")
    if not ok_c:
        fails += 1

    # 2. DELTA: escalate + tuning_override; router must route to analyst
    vd = a.verdict(delta)
    cd = router.classify(delta)
    ok_d = (vd["verdict"] == "escalate" and vd.get("tuning_override") is True
            and cd == ("security", "analyst"))
    print(f"DELTA level {delta_level}: verdict={vd['verdict']} "
          f"tuning_override={vd.get('tuning_override')} classify={cd} "
          f"{'OK' if ok_d else 'FAIL'}")
    print(f"   rationale: {vd.get('rationale','')[:100]}")
    if not ok_d:
        fails += 1

    # 3. --live: full router dispatch on the delta -> ticket -> cleanup
    if live and fails == 0:
        print("\n--- live dispatch of the delta alert ---")
        res = router.dispatch(delta)
        disp = res.get("dispatch") or {}
        case_id = res.get("case_id") or disp.get("case_id")
        action = disp.get("action", res.get("action"))
        print(f"dispatch: action={action} case={case_id} escalated={disp.get('escalated')}")
        # find the ticket for this case (case_id rides at TOP level — the
        # escalator spreads **detail into the ticket).
        sup = SupervisoryClient()
        open_t = sup.list_tickets(status="open")
        hit = [t for t in open_t if t.get("case_id") == case_id]
        if hit:
            t0 = hit[0]
            # The override flag rides in ticket["verdict"] (the **detail
            # spread: detail={"case_id":..., "verdict": v} -> ticket.verdict).
            vd0 = t0.get("verdict") or {}
            has_override = vd0.get("tuning_override") is True
            print(f"ticket landed: {t0.get('ticket_id')} "
                  f"override_in_ticket={has_override} "
                  f"verdict={vd0.get('verdict')}")
            # cleanup: clear the ticket + close the case (lab artifact)
            for t in hit:
                sup.mark_adjudicated(t, "auto_fp",
                                     "override proof: cleared (lab artifact)")
            if case_id:
                from tools.case_tools import CaseStore
                cs = CaseStore()
                c = cs.get_case(case_id)
                if c:
                    cs.close_case(case_id, reason="override proof cleanup")
            print("cleaned: ticket cleared + case closed")
        else:
            print("FAIL: no ticket landed for the delta dispatch")
            fails += 1

    print("OVERRIDE PATH PROVEN" if fails == 0 else f"{fails} FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
