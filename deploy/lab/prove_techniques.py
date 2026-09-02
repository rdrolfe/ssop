#!/usr/bin/env python3
"""End-to-end proof of technique-level ATT&CK mapping:
dispatch a real alert with rule.mitre (T1041 exfil-over-C2, T1078 valid
accounts), confirm the case persists the techniques, and the advisory
renders the real-ID table (not the kill-chain heuristic).

Usage: python3 deploy/lab/prove_techniques.py  (cleans up after itself)
"""
import json
import sys
import uuid

sys.path.insert(0, ".")
import router
from tools.case_tools import CaseStore
from tools.advisory_gen import render_advisory


def main() -> int:
    alert = {
        "id": "tech-" + uuid.uuid4().hex[:8],
        "timestamp": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
        "rule": {
            "id": "20203",
            "level": 12,
            "description": "ET MALWARE Possible DNS Tunneling (NIMLOC)",
            "groups": ["suricata", "malware", "dns"],
            "mitre": {"id": ["T1041", "T1078"], "tactic": ["Exfiltration", "Defense Evasion"]},
        },
        "agent": {"id": "003", "name": "vault-secrets"},
        "data": {"srcip": "10.6.6.66", "dstip": "8.8.8.8", "dstport": 53},
    }
    res = router.dispatch(alert)
    cid = res.get("case_id") or (res.get("dispatch") or {}).get("case_id")
    print("dispatched case:", cid, "| verdict:", (res.get("dispatch") or {}).get("verdict"))

    case = CaseStore().get_case(cid)
    print("case techniques:", case.get("techniques"))

    md = render_advisory(cid, backend="spine")
    in_table = "| `T1041` | Exfiltration Over C2 Channel | Exfiltration |" in md
    in_table2 = "| `T1078` | Valid Accounts | Defense Evasion |" in md
    print("advisory renders T1041 row:", in_table)
    print("advisory renders T1078 row:", in_table2)
    for line in md.splitlines():
        if line.startswith("| `T"):
            print("  ", line)

    # cleanup: close the case
    CaseStore().close_case(cid, reason="technique proof cleanup")
    print("cleaned up", cid)
    ok = bool(case.get("techniques")) and in_table and in_table2
    print("TECHNIQUE LOOP PROVEN" if ok else "TECHNIQUE LOOP FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
