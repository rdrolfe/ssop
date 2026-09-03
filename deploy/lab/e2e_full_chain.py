#!/usr/bin/env python3
"""End-to-end full-chain replay — the un-tuned attack path, live.

Feeds a FRESH un-tuned threat alert through the REAL pipeline, end to end:

  router.dispatch (classify -> mint case + techniques -> escalate ticket)
    -> analyst investigation (live Investigator on the entity)
    -> supervisory adjudicate (approve -> responder auto-assign)
    -> publish case to SO native store
    -> verify SO store + report/advisory render

Proves the whole spine still produces a human-facing artifact after the
recent changes (tuning, host recidivism, technique mapping, get_case
scroll cap). Rule 2045417 (ET MALWARE Raspberry Robin) is un-tuned and
threat-class; srcip/dstip give the investigator real entities.

Usage (on infra-ops): python3 deploy/lab/e2e_full_chain.py [case_id]
  Reuse an existing case_id (publish+verify only) by passing it as argv.
"""
import importlib.util
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, ".")

_BASE = Path(__file__).resolve().parent


def _load(mod_path: str):
    spec = importlib.util.spec_from_file_location("mod", mod_path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _mk_alert() -> dict:
    return {
        "id": "e2e-" + uuid.uuid4().hex[:8],
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "id": "2045417",
            "level": 12,
            "description": "ET MALWARE Raspberry Robin",
            "groups": ["suricata", "malware", "dns"],
            "mitre": {"id": ["T1041", "T1078"], "tactic": ["Exfiltration", "Defense Evasion"]},
        },
        "agent": {"id": "004", "name": "we8105desk.waynecorpinc.local"},
        "data": {"srcip": "192.168.250.100", "dstip": "198.51.100.7", "dstport": 53},
        "input": {"type": "log"},
    }


def main() -> int:
    import router
    from tools.case_tools import CaseStore
    from tools.supervisory_tools import SupervisoryClient

    cs = CaseStore()
    sup = SupervisoryClient()

    if len(sys.argv) > 1:
        cid = sys.argv[1]
        print(f"reusing case {cid} (publish+verify only)")
    else:
        alert = _mk_alert()
        res = router.dispatch(alert)
        cid = res.get("case_id") or (res.get("dispatch") or {}).get("case_id")
        print("dispatch:", json.dumps({k: v for k, v in res.items() if k != "dispatch"},
                                      default=str)[:400])
        assert cid, f"no case minted: {res}"
        # Technique persistence via the real analyst verdict path.
        c = cs.get_case(cid)
        print("case:", cid, "| techniques:", c and c.get("techniques"),
              "| status:", c and c.get("status"))
        assert c and c.get("techniques"), "techniques not persisted at mint"
        assert c.get("status") == "open", "case not open"
        # Live investigation on the entity — tagged kill-chain stages.
        from tools.investigator import Investigator
        ires = Investigator().investigate(srcip="192.168.250.100")
        cs.append_event(cid, "analyst", "investigation", {
            "entity": "192.168.250.100",
            "hypothesis": ires.get("hypothesis"),
            "severity": ires.get("severity", 0),
            "severity_label": ires.get("severity_label", "low"),
            "kill_chain": ires.get("kill_chain", []),
            "evidence": ires.get("evidence", []),
            "evidence_count": len(ires.get("evidence", [])),
        })
        print("investigation:", ires.get("severity_label"),
              f"({ires.get('severity')}) | chain:",
              " -> ".join(ires.get("kill_chain", []))[:120])
        # Supervisory adjudication -> approve -> responder auto-assign.
        dec = sup.adjudicate_with_investigation(cid)
        print("adjudication:", dec.get("decision"), "| playbook:",
              dec.get("recommended_playbook"))
        time.sleep(1)

    # Publish to SO native store (create + timeline comments).
    import sys as _sys
    _pub = _load(str(_BASE / "publish_case_so.py"))
    _sys.argv = ["publish_case_so.py", cid]
    _pub.main()
    print("published to SO")
    time.sleep(2)

    # Verify SO store + attached report/advisory.
    _ver = _load(str(_BASE / "verify_attach_so.py"))
    _sys.argv = ["verify_attach_so.py", cid]
    _ver.main()

    # Report/advisory render check (spine side).
    from tools.advisory_gen import render_advisory
    md = render_advisory(cid)
    has_tech = "| `T" in md
    print("advisory renders technique table:", has_tech)

    print("\n=== MEATSUIT VIEWS ===")
    print(f"Console case: https://192.168.1.75:5602/cases?case_id={cid}")
    print(f"Report:  https://192.168.1.75:5602/report?case_id={cid}&format=html")
    print(f"Advisory: https://192.168.1.75:5602/advisory?case_id={cid}&format=html")
    print(f"(case {cid} — find it in the SOC Cases list)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
