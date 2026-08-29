"""Two-backend FULL-LOOP comparison: run the whole spine on both SIEMs.

The doctrine's capstone: the ENTIRE decision chain (recognize -> investigate
-> supervise -> respond) producing identical outcomes on both backends — on
the SAME shared data (bots-http-poc, ingested to both Wazuh and SO).

Non-mutating: resolves each backend's endpoint/creds from transport.yaml and
passes them explicitly; does NOT flip the active backend or rewrite the file.

Usage: python3 -m verify.two_backend_full_loop [wazuh|so]
"""
import os, sys, json, ssl, base64, urllib.request
from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, ".")
from config import settings
from tools.analyst_tools import AnalystClient
from tools.investigator import Investigator
from tools.supervisory_tools import SupervisoryClient
from tools.case_tools import CaseStore
from tools.bots_parser import normalize

GT_IP = "192.168.250.100"  # published infected workstation (exfil source)

def _backend_endpoint(name: str):
    import yaml as _yaml
    with open("transport.yaml") as f:
        cfg = _yaml.safe_load(f)
    b = (cfg.get("backends") or {}).get(name) or {}
    ep = b.get("endpoint") or ""
    host = ep.replace("https://", "").replace("http://", "").split(":")[0] if ep else settings.indexer_host
    user = b.get("user") or settings.indexer_user
    pw = settings.so_indexer_password if name == "securityonion" else settings.indexer_password
    return host, user, pw

def main() -> None:
    backend = sys.argv[1] if len(sys.argv) > 1 else "wazuh"
    # Map the CLI alias to the transport.yaml backend key.
    cfg_key = "securityonion" if backend in ("so", "securityonion") else backend
    host, user, pw = _backend_endpoint(cfg_key)
    print(f"=== FULL-LOOP on backend: {backend} ({host}) ===")
    print(f"ground-truth entity: {GT_IP}\n")

    a = AnalystClient()
    inv = Investigator(indexer_host=host, user=user, password=pw)
    sup = SupervisoryClient()
    cs = CaseStore()

    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    def search(idx, q, size=3):
        req = urllib.request.Request(f"https://{host}:9200/{idx}/_search",
            data=json.dumps({"size": size, "query": q}).encode(),
            headers={"Authorization": auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return json.loads(r.read().decode()).get("hits", {}).get("hits", [])

    # 1. RECOGNIZE: a real exfil event from the shared slice must escalate
    hits = search("bots-http-poc", {"bool": {"must": [
        {"term": {"c_ip": GT_IP}}, {"match_phrase": {"uri": "UploadData.aspx"}}]}})
    escalated = False
    if hits:
        v = a.verdict(normalize(hits[0]["_source"]))
        escalated = v["verdict"] == "escalate"
        print(f"  1. recognize: verdict={v['verdict']} level={v['level']} cat={v['category']} "
              f"({len(hits)} exfil events)")
    else:
        print("  1. recognize: 0 exfil events found (data missing?)")
    print(f"     -> escalated: {escalated}")

    # 2. INVESTIGATE: correlate + score (against THIS backend's data)
    res = inv.investigate(srcip=GT_IP)
    n_ev = len(res.get("evidence", []))
    sev = res.get("severity_label", "?")
    print(f"  2. investigate: {n_ev} evidence sources, severity={sev}")

    # 3. SUPERVISE: adjudicate with the evidence
    case = cs.open_case(
        source={"alert_id": f"fl-{backend}", "agent": "network",
                "rule_desc": "HTTP exfil", "rule_id": "bots-threat-http-exfil"},
        title=f"HTTP exfil from {GT_IP}",
        observables=[{"type": "ip", "value": GT_IP}],
    )
    cs.append_event(case["case_id"], "analyst", "investigation", {
        "hypothesis": res.get("hypothesis", ""),
        "evidence": res.get("evidence", []),
        "kill_chain": res.get("kill_chain", []),
        "severity": res.get("severity", 0),
        "severity_label": res.get("severity_label", "low"),
    })
    dec = sup.adjudicate_with_investigation(case["case_id"])
    print(f"  3. supervise: decision={dec['decision']} used_inv={dec.get('used_investigation')}")

    # 4. RESPOND: must not block on approve
    from responder import run as responder_run
    alert = {"rule": {"id": 1, "level": 8, "groups": ["threat", "http"],
                      "description": "HTTP exfil"}, "agent": {"name": "network"}}
    r = responder_run(alert, case_id=case["case_id"], dry_run=True)
    blocked = r.get("blocked")
    print(f"  4. respond: blocked={blocked}")

    try:
        cs.close_case(case["case_id"])
    except Exception:
        pass

    summary = {"backend": backend, "recognize_escalated": escalated,
               "investigate_evidence": n_ev, "investigate_severity": sev,
               "supervise_decision": dec["decision"],
               "supervise_used_investigation": dec.get("used_investigation"),
               "responder_blocked": blocked}
    print(f"\nSUMMARY: {json.dumps(summary)}")
    with open(f"/tmp/full_loop_{backend}.json", "w") as f:
        json.dump(summary, f, indent=2)

if __name__ == "__main__":
    main()
