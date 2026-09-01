#!/usr/bin/env python3
"""Verify auto-assign end-to-end (mint -> adjudicate -> assignee flips)."""
import sys

sys.path.insert(0, ".")
from tools.case_tools import CaseStore
from tools.supervisory_tools import SupervisoryClient

cs = CaseStore()
sup = SupervisoryClient()

# 1. mint with auto-assign (analyst owns from start)
case = cs.open_case(
    source={"rule_desc": "auto-assign test", "rule_id": "auto-assign-test"},
    title="AUTO-ASSIGN TEST", observables=[{"type": "ip", "value": "192.0.2.1"}],
    assignee="analyst",
)
print("minted:", case["case_id"], "| assignee:", case["assignee"])
assert case["assignee"] == "analyst", "mint assignee wrong"

# 2. attach a rich investigation (high severity -> approve path)
cs.append_event(case["case_id"], "analyst", "verdict",
                {"verdict": "escalate", "level": 8, "category": "threat"})
cs.append_event(case["case_id"], "analyst", "investigation", {
    "entity": "192.0.2.1", "evidence_count": 2,
    "kill_chain": ["C2: DNS queries/tunneling", "EXFILTRATION: HTTP upload/exfil traffic"],
    "severity": 9.0, "severity_label": "high",
    "evidence": [{"source": "dns", "label": "DNS tunnel"}, {"source": "http", "label": "HTTP exfil"}],
    "hypothesis": "Entity 192.0.2.1 tunneling data out via DNS+HTTP.",
})

# 3. adjudicate -> approve -> assignee should flip to responder
dec = sup.adjudicate_with_investigation(case["case_id"])
print("decision:", dec["decision"], "| recommended:", dec.get("recommended_playbook"))
assert dec["decision"] == "approve", f"expected approve, got {dec['decision']}"

# 4. read back the case — assignee must be responder now
after = cs.get_case(case["case_id"])
print("after adjudication assignee:", after["assignee"])
assert after["assignee"] == "responder", "approve should assign responder"

# 5. deny path: low severity -> analyst
case2 = cs.open_case(
    source={"rule_desc": "auto-assign deny test", "rule_id": "auto-assign-test-2"},
    title="AUTO-ASSIGN DENY TEST", assignee="analyst",
)
dec2 = sup.adjudicate_with_investigation(case2["case_id"])
after2 = cs.get_case(case2["case_id"])
print("deny decision:", dec2["decision"], "| assignee:", after2["assignee"])
assert dec2["decision"] == "deny", f"expected deny, got {dec2['decision']}"
assert after2["assignee"] == "analyst", "deny should assign analyst"

# cleanup both test cases (close with reason, so no open residue)
for cid in (case["case_id"], case2["case_id"]):
    cs.close_case(cid, role="verify", reason="auto-assign test cleanup")
print("AUTO-ASSIGN OK")
