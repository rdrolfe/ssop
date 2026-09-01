#!/usr/bin/env python3
"""Loop-closer proof: human deny on an override ticket must update the tuning
fingerprint so the override loop settles.

Flow:
  1. clone a real 2902 alert, bump level to 12 (material delta)
  2. dispatch live -> case + tier-2 ticket (verdict rides at TOP level)
  3. human denies the ticket via supervisory.adjudicate()
  4. assert the tuning fingerprint was updated to the DELTA shape (level 12)
  5. assert a new IDENTICAL delta alert now SUPPRESSES (loop settled)
  6. restore the original tuning fingerprint (lab artifact — don't mutate
     the live tuning with test state)

Usage: python3 deploy/lab/prove_override_loop.py
"""
import json
import sys
import uuid

sys.path.insert(0, ".")
from tools.case_tools import CaseStore
from tools.indexer_client import IndexerTransport
from tools.supervisory_tools import SupervisoryClient
from tools.tuning_tools import TuningLedger, tuned_rule_suppresses
import router


def main() -> int:
    rule_id = "2902"
    fails = 0
    led = TuningLedger()
    original = led.lookup(rule_id)
    if not original:
        print(f"rule {rule_id} not tuned — nothing to loop-close")
        return 1

    t = IndexerTransport()
    body = {"size": 1, "query": {"bool": {"filter": [{"term": {"rule.id": rule_id}}]}},
            "sort": [{"@timestamp": {"order": "desc"}}]}
    r = t.search(body, index="wazuh-alerts-4.x-*")
    hits = r.get("hits", {}).get("hits", [])
    if not hits:
        print("no live 2902 alert")
        return 1
    base = json.loads(json.dumps(hits[0]["_source"]))
    base["rule"] = dict(base.get("rule") or {})
    orig_level = int(base["rule"].get("level", 0))
    base["rule"]["level"] = orig_level + 5
    base["id"] = "loop-" + uuid.uuid4().hex[:8]

    # 2. dispatch live
    res = router.dispatch(base)
    disp = res.get("dispatch") or {}
    case_id = res.get("case_id") or disp.get("case_id")
    print(f"dispatched: case={case_id} escalated={disp.get('escalated')}")

    # find the ticket on disk
    sup = SupervisoryClient()
    open_t = sup.list_tickets(status="open")
    hit = [t for t in open_t if t.get("case_id") == case_id]
    if not hit:
        print("FAIL: no ticket landed")
        return 1
    ticket = hit[0]
    vd = ticket.get("verdict") or {}
    print(f"ticket {ticket['ticket_id']}: top-level verdict={vd.get('verdict')} "
          f"tuning_override={vd.get('tuning_override')}")
    if vd.get("tuning_override") is not True:
        print("FAIL: override flag missing")
        fails += 1

    # 3. human denies
    sup.adjudicate(ticket, "deny", "loop-proof: human denies the delta")

    # 4. tuning fingerprint should now be the DELTA shape (level raised)
    updated = led.lookup(rule_id)
    new_fp = (updated or {}).get("fingerprint") or {}
    print(f"updated fingerprint level: {new_fp.get('level')} "
          f"(was {orig_level}, delta {orig_level + 5})")
    if int(new_fp.get("level", 0)) != orig_level + 5:
        print("FAIL: fingerprint not updated to delta shape")
        fails += 1

    # 5. identical delta now suppresses -> loop settled
    s, _reason = tuned_rule_suppresses(updated, base, category="operational")
    print(f"identical delta now suppresses: {s} (want True — loop settled)")
    if not s:
        fails += 1

    # 6. restore the original tuning (lab artifact)
    led.write(rule_id=rule_id, decision=original["decision"],
              rationale=original.get("rationale", ""), source=original.get("source", "human"),
              tuned_by=original.get("tuned_by", ""), fingerprint=original.get("fingerprint"))
    print("restored original tuning fingerprint")

    # cleanup: close case (ticket already adjudicated by step 3)
    cs = CaseStore()
    c = cs.get_case(case_id)
    if c:
        cs.close_case(case_id, reason="loop-proof cleanup")

    print("LOOP CLOSED" if fails == 0 else f"{fails} FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
