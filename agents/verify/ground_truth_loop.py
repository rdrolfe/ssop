"""Ground-truth FULL-LOOP validation: run the real BOTS attack event through
the whole spine (analyst -> investigator -> supervisor -> responder) and check
the outcome against the published BOTSv1 answers.

Published answers (samclass / Andickinson / AbbasMurshid writeups):
- infected workstation 192.168.250.100  (Bob Smith / we8105desk, Cerber source)
- the same IP does HTTP exfil uploads + DNS tunneling  (our validated signals)

The spine must: recognize (escalate) -> investigate (correlate + score HIGH) ->
supervise (approve on the evidence) -> recommend a playbook.
"""
import os, sys, json
from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, ".")
from tools.analyst_tools import AnalystClient
from tools.investigator import Investigator
from tools.supervisory_tools import SupervisoryClient
from tools.case_tools import CaseStore

GT_IP = "192.168.250.100"  # published: Bob Smith's infected workstation
GT_IP2 = "192.168.250.70"  # published: the web server (defacement target)

results = []
def check(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  [{'✅' if ok else '❌'}] {label}" + (f"  ({detail})" if detail else ""))

print("=== BOTSv1 GROUND-TRUTH FULL-LOOP ===")
print(f"published infected workstation: {GT_IP}\n")

# 1. RECOGNITION: the analyst must escalate the infected workstation's HTTP exfil
print("1. RECOGNITION (analyst escalates the real attack)")
try:
    a = AnalystClient()
    # pull a real exfil event from the infected workstation
    from tools.indexer_client import IndexerTransport
    t = IndexerTransport()
    body = {"size": 3, "query": {"bool": {"must": [
                {"term": {"c_ip": GT_IP}},
                {"match_phrase": {"uri": "UploadData.aspx"}}]}},
            "_source": ["c_ip", "uri", "http_method", "http_user_agent", "_raw"]}
    hits = t.search(body, "bots-http-poc").get("hits", {}).get("hits", [])
    check("exfil events exist for GT IP", len(hits) > 0, f"{len(hits)} events")
    if hits:
        src = hits[0]["_source"]
        from tools.bots_parser import normalize
        norm = normalize(src)
        lvl = int(norm.get("rule", {}).get("level", 0))
        cat = norm.get("rule", {}).get("groups", [])
        check("exfil event normalizes to threat", lvl >= 8 and "threat" in cat,
              f"level {lvl}, groups {cat}")
except Exception as e:
    check("recognition probe ran", False, f"ERR: {e}")

# 2. INVESTIGATION: correlate the GT IP across sources, score HIGH
print("\n2. INVESTIGATION (correlate + score the published entity)")
try:
    inv = Investigator()
    res = inv.investigate(srcip=GT_IP)
    sev = res.get("severity_label", "?")
    n_ev = len(res.get("evidence", []))
    check("GT IP investigated", n_ev > 0, f"{n_ev} evidence sources")
    check("GT IP scores HIGH", sev == "high", f"severity={sev}")
except Exception as e:
    check("investigation ran", False, f"ERR: {e}")

# 3. SUPERVISION: adjudicate the case with the evidence -> approve
print("\n3. SUPERVISION (evidence-aware adjudication)")
try:
    cs = CaseStore()
    sup = SupervisoryClient()
    case = cs.open_case(
        source={"alert_id": "gt-loop-1", "agent": "network", "rule_desc": "HTTP exfil",
                "rule_id": "bots-threat-http-exfil"},
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
    check("supervisor approves the GT case", dec["decision"] == "approve",
          f"decision={dec['decision']}")
    check("supervisor used the investigation", bool(dec.get("used_investigation")),
          f"used_investigation={dec.get('used_investigation')}")
    # cleanup
    try: cs.close_case(case["case_id"], reason="ground-truth loop cleanup")
    except Exception: pass
except Exception as e:
    check("supervision ran", False, f"ERR: {e}")

# 4. RESPONDER: must resolve the recommendation + proceed (not block)
print("\n4. RESPONDER (obeys approve, picks up playbook)")
try:
    from responder import run as responder_run
    alert = {"rule": {"id": 1, "level": 8, "groups": ["threat", "http"],
                      "description": "HTTP exfil"}, "agent": {"name": "network"}}
    r = responder_run(alert, case_id=case["case_id"], dry_run=True)
    check("responder not blocked on approve", not r.get("blocked"),
          f"blocked={r.get('blocked')}")
except Exception as e:
    check("responder ran", False, f"ERR: {e}")

print("\n=== SUMMARY ===")
ok_n = sum(1 for _, ok, _ in results if ok)
print(f"{ok_n}/{len(results)} ground-truth checks passed")
