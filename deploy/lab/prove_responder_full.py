#!/usr/bin/env python3
"""Full-loop responder proof: live Wazuh alert -> analyst recommends -> responder executes.

Injects a synthetic operational alert (service crash-loop on .13) into the
live Wazuh index, waits for the router/analyst timers to mint + escalate the
case with recommended_playbook=restart-flapping-service, then invokes the
responder on the minted case and verifies the restart + spine receipts.

Run on .29: PYTHONPATH=. ./agent-env/bin/python3 deploy/lab/prove_responder_full.py
"""
import json
import sys
import time
import uuid
import datetime

sys.path.insert(0, ".")

NETWORK_IP = "192.168.1.13"
NOW = datetime.datetime.now(datetime.timezone.utc)
TS = NOW.strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def inject_alert() -> str:
    """Write a real-shape alert doc into the live wazuh index (fixed id)."""
    from tools.investigator import Investigator
    from config import settings
    import yaml as _yaml
    from pathlib import Path

    tp = _yaml.safe_load(Path("transport.yaml").read_text())
    b = (tp.get("backends") or {}).get("wazuh", {})
    host = (b.get("endpoint") or "").replace("https://", "").replace(
        "http://", "").split(":")[0] or "192.168.1.75"
    user = b.get("user") or settings.indexer_user
    pw = settings.indexer_password
    idx = b.get("alerts_index") or "wazuh-alerts-4.x-*"
    idx = idx.replace("*", NOW.strftime("%Y.%m.%d"))

    doc_id = "resp-flap-proof"
    alert = {
        "timestamp": TS,
        "@timestamp": NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "id": doc_id,
        "rule": {"id": "541", "level": 5,
                 "description": "Service flagged as crash-looping (responder proof)",
                 "groups": ["systemd", "operational"], "firedtimes": 1},
        "agent": {"id": "013", "name": "network"},
        "manager": {"name": "telemetry"},
        "data": {"service": "ssop-demo-svc", "src_ip": ""},
        "location": "responder-proof",
        "input": {"type": "log"},
    }
    from tools.tls import verified_ssl_context
    import urllib.request
    req = urllib.request.Request(
        f"https://{host}:9200/{idx}/_doc/{doc_id}",
        data=json.dumps(alert).encode(),
        headers={"Authorization": "Basic " + __import__("base64").b64encode(
            f"{user}:{pw}".encode()).decode(),
            "Content-Type": "application/json"},
        method="PUT")
    with urllib.request.urlopen(req, timeout=20,
                                context=verified_ssl_context()) as r:
        out = json.loads(r.read().decode())
    print("injected:", out.get("result"), doc_id, flush=True)
    return doc_id


def find_case(doc_id: str, deadline_s: int = 480) -> tuple[str, dict] | None:
    """Poll the spine for a case minted from the injected alert."""
    from tools.case_tools import CaseStore
    store = CaseStore()
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        pts = store._get_memory().search_memory(
            "cases", doc_id, limit=5, scroll_limit=10000)
        for hit in pts:
            cid = hit.get("id")
            if not cid or not str(cid).startswith("case-"):
                continue
            case = store.get_case(cid)
            if not case:
                continue
            src = json.dumps(case)
            if doc_id in src:
                rec = None
                for ev in case.get("timeline", []):
                    if ev.get("role") == "analyst" and ev.get("type") == "verdict":
                        rec = (ev.get("detail") or {}).get("recommended_playbook")
                return cid, {"recommended": rec,
                             "state": case.get("state")}
        time.sleep(15)
    return None


def main() -> int:
    doc_id = inject_alert()
    print("waiting for router+analyst timers to mint the case...", flush=True)
    found = find_case(doc_id)
    if not found:
        print("FAIL: no case minted from the injected alert within 8m", flush=True)
        return 1
    cid, info = found
    print(f"case minted: {cid} recommended={info['recommended']} state={info['state']}",
          flush=True)

    from responder import run
    alert = {
        "id": doc_id,
        "rule": {"id": "541", "level": 5,
                 "description": "Service flagged as crash-looping (responder proof)",
                 "groups": ["systemd", "operational"]},
        "agent": {"name": "network"},
        "service": "ssop-demo-svc",
        "category": "operational",
    }
    r = run(alert, case_id=cid, dry_run=False,
            recommended_playbook=info["recommended"])
    print(json.dumps(r, indent=1)[:1200], flush=True)

    ok = (not r.get("blocked")
          and any(s.get("step") == "service_restart" and s.get("ok")
                  for s in r.get("results", [])))
    # verify spine receipts
    from tools.case_tools import CaseStore
    case = CaseStore().get_case(cid) or {}
    execs = [e for e in case.get("timeline", [])
             if e.get("role") == "responder" and e.get("type") == "execution"]
    print(f"spine responder-execution events: {len(execs)}", flush=True)
    ok = ok and len(execs) >= 1
    print("\nFULL-LOOP RESPONDER PROOF: " + ("PASS" if ok else "FAIL"), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
