#!/usr/bin/env python3
"""Live demo flow: fresh un-tuned alert -> full spine chain -> IRIS case.

Kicks a real Raspberry Robin alert (rule 2045417, un-tuned) through the
live pipeline: router dispatch -> mint -> investigation (tagged
kill-chain) -> supervisory approve -> publish to DFIR-IRIS as a case
attributed to the supervisor role, with a task assigned to the rdrolfe
user (id 7) so the human dashboard lights up.

Usage (on infra-ops): python3 deploy/lab/iris_demo_flow.py
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
_IRIS_USER_ID = 7  # rdrolfe


def _load(mod_path: str):
    spec = importlib.util.spec_from_file_location("mod", mod_path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main() -> int:
    import router
    from tools.case_tools import CaseStore
    from tools.supervisory_tools import SupervisoryClient

    cs = CaseStore()
    sup = SupervisoryClient()

    # 1. Fresh un-tuned threat alert (real BOTS entity -> real correlation).
    alert = {
        "id": "demo-" + uuid.uuid4().hex[:8],
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "id": "2045417", "level": 12,
            "description": "ET MALWARE Raspberry Robin",
            "groups": ["suricata", "malware", "dns"],
            "mitre": {"id": ["T1041", "T1078"], "tactic": ["Exfiltration", "Defense Evasion"]},
        },
        "agent": {"id": "004", "name": "we8105desk.waynecorpinc.local"},
        "data": {"srcip": "192.168.250.100", "dstip": "198.51.100.7", "dstport": 53},
        "input": {"type": "log"},
    }
    res = router.dispatch(alert)
    cid = res.get("case_id") or (res.get("dispatch") or {}).get("case_id")
    print("dispatch:", json.dumps({k: v for k, v in res.items() if k != "dispatch"},
                                  default=str)[:300])
    assert cid, f"no case minted: {res}"
    c = cs.get_case(cid)
    print("case:", cid, "| techniques:", c and c.get("techniques"))

    # 2. Investigation (live) — tagged kill-chain.
    from tools.investigator import Investigator
    ires = Investigator().investigate(srcip="192.168.250.100")
    cs.append_event(cid, "analyst", "investigation", {
        "entity": "192.168.250.100", "hypothesis": ires.get("hypothesis"),
        "severity": ires.get("severity", 0),
        "severity_label": ires.get("severity_label", "low"),
        "kill_chain": ires.get("kill_chain", []),
        "evidence": ires.get("evidence", []),
        "evidence_count": len(ires.get("evidence", [])),
    })
    print("investigation:", ires.get("severity_label"), f"({ires.get('severity')}) |",
          " -> ".join(ires.get("kill_chain", []))[:110])

    # 3. Supervisory approve.
    dec = sup.adjudicate_with_investigation(cid)
    print("adjudication:", dec.get("decision"), "| playbook:", dec.get("recommended_playbook"))
    time.sleep(1)

    # 4. Publish to IRIS (supervisor role attributes the case). Re-fetch the
    #    case AFTER adjudication so the chain summary carries the
    #    investigation + decision (a stale pre-adjudication snapshot shows
    #    "(no decision chain on timeline)").
    c = cs.get_case(cid)
    pub = _load(str(_BASE / "publish_case_iris.py"))
    pub._ROLE = "supervisor"
    pub._load_env()
    if not pub._IRIS_KEY:
        print("IRIS key missing"); return 1
    payload = {
        "case_soc_id": cid, "case_customer": 1,
        "case_name": (c or {}).get("title", cid)[:60],
        "case_description": (f"{(c or {}).get('title', '')}\n\nsource: rule 2045417 "
                             f"ET MALWARE Raspberry Robin on we8105desk\nstate: "
                             f"{(c or {}).get('state')}\n\n{pub._chain_summary(c)}")[:2000],
    }
    created = pub._req("POST", "/manage/cases/add", payload)
    data = created.get("data", {})
    iris_id = data.get("case_id")
    print("IRIS case:", iris_id)
    # Decision chain tasklog.
    pub._req("POST", f"/case/tasklog/add?cid={iris_id}",
             {"log_content": f"SSOP chain: {pub._chain_summary(c)}"})
    # 5. Task assigned to rdrolfe so the human dashboard shows it.
    t = pub._req("POST", f"/case/tasks/add?cid={iris_id}", {
        "task_title": "Triage SSOP case",
        "task_description": f"Decision chain from {cid} — review in IRIS",
        "task_status_id": 1,
        "task_assignees_id": [_IRIS_USER_ID],
    })
    print("task:", t.get("status"), t.get("message"))
    print(f"IRIS case URL: {pub._IRIS_URL}/case?case_id={iris_id}")
    print(f"Console: https://192.168.1.75:5602/cases?case_id={cid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
