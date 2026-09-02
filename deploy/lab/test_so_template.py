#!/usr/bin/env python3
"""End-to-end meat-suit template test: mint a realistic threat case, drive
it through the spine (investigate -> escalate -> adjudicate approve), then
publish the FULL case into SO's native store WITH the attached
report + advisory comments — exactly what the SOC meatsuit sees.

Flow:
  1. open_case (threat source, observables, assignee=analyst)
  2. append investigation (hypothesis, entity, 2-stage kill-chain,
     evidence 2 sources, severity high) -> drives APPROVE
  3. append analyst verdict escalate
  4. publish case to SO (create + timeline comment ops, deterministic ids)
  5. adjudicate_with_investigation -> approve -> auto-assign responder ->
     case_verdict -> AUTO-ATTACH report + advisory to the SO case
  6. verify the SO store (create + comments + report + advisory ops)
  7. print the SOC view URLs

Usage (on infra-ops): python3 deploy/lab/test_so_template.py
"""
import json
import sys
import time

sys.path.insert(0, ".")
from tools.case_tools import CaseStore
from tools.supervisory_tools import SupervisoryClient


def main() -> int:
    cs = CaseStore()
    sup = SupervisoryClient()

    # 1. Mint a realistic threat case (DNS tunneling, the classic).
    case = cs.open_case(
        source={
            "rule_id": "TEST-1001",
            "rule_desc": "DNS tunneling — NIMLOC record to known tunnel domain",
            "category": "threat",
            "level": 12,
        },
        title="[TEST MEATSUIT] DNS tunneling attempt via NIMLOC records",
        observables=[
            {"type": "ip", "value": "10.6.6.66"},
            {"type": "domain", "value": "tunnel-test.example.net"},
        ],
        assignee="analyst",
    )
    cid = case["case_id"]
    print("minted:", cid, "|", case["title"])

    # 2. Analyst investigation — 2-stage kill chain, 2 evidence sources,
    #    high severity (drives APPROVE in the evidence-aware policy).
    cs.append_event(cid, "analyst", "investigation", {
        "entity": "10.6.6.66",
        "hypothesis": "Entity 10.6.6.66 is exfiltrating data via DNS "
                      "tunneling to tunnel-test.example.net (NIMLOC records "
                      "carry 1200+ byte payloads on a 1.2/s cadence).",
        "severity": 9.2,
        "severity_label": "high",
        "kill_chain": [
            "C2: DNS queries/tunneling",
            "EXFILTRATION: DNS exfil to tunnel domain",
        ],
        "evidence": [
            {"source": "dns", "index": "wazuh-alerts-4.x-*", "label": "NIMLOC tunnel queries",
             "count": 1421},
            {"source": "suricata", "index": "suricata-alerts-*", "label": "DNS tunnel signature hits",
             "count": 87},
        ],
        "evidence_count": 2,
    })

    # 3. Analyst verdict: escalate.
    cs.append_event(cid, "analyst", "verdict", {
        "verdict": "escalate", "level": 12, "category": "threat",
        "rationale": "high-severity threat — DNS tunneling indicators",
    })

    # 4. Adjudicate -> approve -> auto-assign responder -> auto-attach.
    dec = sup.adjudicate_with_investigation(cid)
    print("adjudication:", dec["decision"], "| playbook:", dec.get("recommended_playbook"))
    time.sleep(1)

    # 5. Publish the case to SO's native store (create + ALL timeline
    #    comments including the supervisory adjudication event, so the SO
    #    timeline is complete).
    import importlib.util

    def _load(mod_path: str):
        spec = importlib.util.spec_from_file_location("mod", mod_path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    from pathlib import Path
    _base = Path(__file__).resolve().parent
    import sys as _sys
    _pub = _load(str(_base / "publish_case_so.py"))
    _sys.argv = ["publish_case_so.py", cid]
    _pub.main()
    print("published case to SO")
    time.sleep(2)

    # 6. Verify the SO store.
    _ver = _load(str(_base / "verify_attach_so.py"))
    import sys as _sys
    _sys.argv = ["verify_attach_so.py", cid]
    _ver.main()

    # 7. SOC view URLs.
    print("\n=== MEATSUIT VIEWS ===")
    print(f"SO SOC case: search title  '[TEST MEATSUIT] DNS tunneling attempt'")
    print(f"Console case: https://192.168.1.75:5602/cases?case_id={cid}")
    print(f"Report:  https://192.168.1.75:5602/report?case_id={cid}&format=html")
    print(f"Advisory: https://192.168.1.75:5602/advisory?case_id={cid}&format=html")
    print(f"(case {cid} — find it in the SOC Cases list)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
