#!/usr/bin/env python3
"""Verify recent_hunt_cases actually matches a freshly-minted hunt case
(does the receipt spine carry enough to key on hunt_id?)."""
from tools.case_tools import CaseStore
cs = CaseStore()
c = cs.open_case(source={"hunt_id": "recidivism-probe", "category": "test", "finding": "suspicious"},
                 title="RECIDIVISM PROBE")
cid = c["case_id"]
print("case_id:", cid)
with open(cs.cases_file, encoding="utf-8") as f:
    tail = [l for l in f.readlines() if cid in l]
print("receipt lines for this case:", len(tail))
for l in tail[:2]:
    print("  ", l[:200])
found = cs.recent_hunt_cases("recidivism-probe", window_s=3600)
print("recent_hunt_cases match:", len(found), [r.get("case_id") for r in found])
cs.close_case(cid, reason="recidivism test cleanup")
