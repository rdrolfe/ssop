#!/usr/bin/env python3
"""Round-trip: open a case, run adjudicate_with_investigation, verify the
decision lands in the timeline (the fix) and is visible via /cases."""
from dotenv import load_dotenv; load_dotenv()
import sys
sys.path.insert(0, ".")
from tools.case_tools import CaseStore
from tools.supervisory_tools import SupervisoryClient

cases = CaseStore()
sup = SupervisoryClient(cases=cases)

# open a minimal test case
case = cases.open_case(
    source={"alert_id": "rt-test", "agent": "network", "rule_desc": "round-trip test"},
    title="ROUNDTRIP test case",
)
cid = case["case_id"]
cases.append_event(cid, "analyst", "investigation", {
    "entity": "10.10.1.11",
    "evidence_count": 3,
    "kill_chain": ["RECON", "C2/MALWARE", "NETWORK"],
    "severity": 3.93, "severity_label": "medium",
})
dec = sup.adjudicate_with_investigation(cid)
print("decision:", dec.get("decision"))

# now read the case back and check the timeline
got = cases.get_case(cid)
tl = got.get("timeline", [])
print("timeline events:", [(e.get("role"), e.get("type")) for e in tl])
adjs = [e for e in tl if e.get("role") == "supervisory" and e.get("type") == "adjudication"]
print("adjudication events found:", len(adjs))
if adjs:
    print("decision in timeline:", adjs[-1].get("detail", {}).get("decision"))

# cleanup
cases.close_case(cid, role="roundtrip-test", reason="verify cleanup")
print("cleaned up:", cid)
