"""Ground-truth RANSOMWARE (Cerber) validation against BOTH backends.

Runs the real Cerber process-create event through the full spine
(analyst -> investigator -> supervisor -> responder) against a chosen
backend's indexer, and checks against the published BOTSv1 answers.

Published anchors (Andickinson / AbbasMurshid writeups):
- 121214.tmp: the Cerber drop/temp process (parent PID 3968)
- AAE3F5A29935E6ABCC2C2754D12A9AF0: the Cerber binary hash
- 3791.exe: the uploaded executable (APT scenario, 69 sysmon hits)
- cerberhhyed5frqa.xmfir0.win: the ransomware C2 FQDN

The spine must recognize the malicious process-exec, investigate/correlate
it, supervise (approve), and the responder must not block.

Backend-parameterized: `python3 -m verify.ground_truth_ransomware [wazuh|so]`
resolves host/user/pw from transport.yaml backends (never the active
backend). With no arg, runs BOTH and diffs the summaries — the parity claim.
"""
import os
import sys
import json
import base64
import ssl
import urllib.request

from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, ".")
from config import settings
from tools.bots_parser import normalize


def _backend(backend: str):
    """Resolve (host, user, password) for a transport.yaml backend."""
    import yaml as _yaml
    with open("transport.yaml") as f:
        cfg = _yaml.safe_load(f)
    b = (cfg.get("backends") or {}).get(backend) or {}
    ep = b.get("endpoint") or ""
    host = ep.replace("https://", "").replace("http://", "").split(":")[0]
    if not host:
        host = settings.indexer_host if settings.indexer_host not in ("", "localhost") else "192.168.1.75"
    user = b.get("user") or settings.indexer_user
    pw = settings.so_indexer_password if backend == "securityonion" else settings.indexer_password
    return host, user, pw


def main() -> int:
    backend = sys.argv[1] if len(sys.argv) > 1 else "wazuh"
    cfg_key = "securityonion" if backend in ("so", "securityonion") else backend
    host, user, pw = _backend(cfg_key)
    print(f"=== BOTSv1 RANSOMWARE (Cerber) FULL-LOOP — backend {backend} ({host}) ===")
    print("published: 121214.tmp drop, hash AAE3F5A2..., C2 cerberhhyed5frqa.xmfir0.win\n")

    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    results = []
    def check(label, ok, detail=""):
        results.append((label, ok, detail))
        print(f"  [{'OK' if ok else 'XX'}] {label}" + (f"  ({detail})" if detail else ""))

    def search(idx, q, size=3, src=None):
        body = {"size": size, "query": q}
        if src: body["_source"] = src
        req = urllib.request.Request(f"https://{host}:9200/{idx}/_search",
            data=json.dumps(body).encode(),
            headers={"Authorization": auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return json.loads(r.read().decode()).get("hits", {}).get("hits", [])

    # 1. RECOGNITION: does the parser escalate the Cerber process-create events?
    print("1. RECOGNITION (parser on real Cerber sysmon events)")
    try:
        for label, q in [("121214.tmp", {"match_phrase": {"_raw": "121214.tmp"}}),
                         ("3791.exe", {"match_phrase": {"_raw": "3791.exe"}})]:
            hits = search("bots-sysmon-op-poc", q, size=1, src=["_raw", "EventCode", "Image"])
            if hits:
                src = hits[0]["_source"]
                norm = normalize(src)
                lvl = int(norm.get("rule", {}).get("level", 0))
                groups = norm.get("rule", {}).get("groups", [])
                desc = norm.get("rule", {}).get("description", "")
                check(f"Cerber process {label.split()[0]} escalates", lvl >= 8,
                      f"level={lvl} groups={groups} desc={desc[:40]}")
            else:
                check(f"Cerber process {label.split()[0]} found", False, "no hits")
    except Exception as e:
        check("recognition probe ran", False, f"ERR: {e}")

    # 2. INVESTIGATION: correlate the infected host (192.168.250.100) — already HIGH
    print("\n2. INVESTIGATION (correlate the infected workstation)")
    res: dict = {}
    try:
        from tools.investigator import Investigator
        inv = Investigator(indexer_host=host, user=user, password=pw)
        res = inv.investigate(srcip="192.168.250.100")
        check("infected workstation investigated", len(res.get("evidence", [])) > 0,
              f"{len(res.get('evidence', []))} evidence sources")
        check("infected workstation scores HIGH", res.get("severity_label") == "high",
              f"severity={res.get('severity_label')}")
    except Exception as e:
        check("investigation ran", False, f"ERR: {e}")

    # 3. SUPERVISION: evidence-aware adjudication -> approve
    print("\n3. SUPERVISION (evidence-aware)")
    case = None
    try:
        from tools.supervisory_tools import SupervisoryClient
        from tools.case_tools import CaseStore
        cs = CaseStore(); sup = SupervisoryClient()
        case = cs.open_case(
            source={"alert_id": f"gt-cerber-{backend}", "agent": "we8105desk", "rule_desc": "Cerber process",
                    "rule_id": "bots-threat-proc"},
            title="Cerber ransomware process-exec on we8105desk",
            observables=[{"type": "ip", "value": "192.168.250.100"}],
        )
        cs.append_event(case["case_id"], "analyst", "investigation", {
            "hypothesis": res.get("hypothesis", ""),
            "evidence": res.get("evidence", []),
            "kill_chain": res.get("kill_chain", []),
            "severity": res.get("severity", 0),
            "severity_label": res.get("severity_label", "low"),
        })
        dec = sup.adjudicate_with_investigation(case["case_id"])
        check("supervisor approves the Cerber case", dec["decision"] == "approve",
              f"decision={dec['decision']}")
        check("supervisor used the investigation", bool(dec.get("used_investigation")))
    except Exception as e:
        check("supervision ran", False, f"ERR: {e}")

    # 4. RESPONDER: not blocked on approve
    print("\n4. RESPONDER (obeys approve)")
    try:
        from responder import run as responder_run
        alert = {"rule": {"id": 1, "level": 8, "groups": ["threat", "process"],
                          "description": "Cerber process-exec"}, "agent": {"name": "we8105desk"}}
        r = responder_run(alert, case_id=(case["case_id"] if case else ""), dry_run=True)
        check("responder not blocked on approve", not r.get("blocked"),
              f"blocked={r.get('blocked')}")
    except Exception as e:
        check("responder ran", False, f"ERR: {e}")

    print("\n=== SUMMARY ===")
    ok_n = sum(1 for _, ok, _ in results if ok)
    print(f"{ok_n}/{len(results)} ransomware ground-truth checks passed")
    summary = {"backend": backend, "passed": ok_n, "total": len(results),
               "checks": [{"label": l, "ok": ok, "detail": d} for l, ok, d in results]}
    with open(f"/tmp/gt_ransom_{backend}.json", "w") as f:
        json.dump(summary, f, indent=2)
    return 0 if ok_n == len(results) else 1


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(main())
    else:
        # Run BOTH backends and diff the summary files.
        import subprocess
        ok = True
        for b in ("wazuh", "so"):
            r = subprocess.run([sys.executable, __file__, b],
                               capture_output=True, text=True, timeout=300)
            print(r.stdout)
            if r.stderr.strip():
                print("STDERR:", r.stderr.strip()[-500:])
            if r.returncode != 0:
                ok = False
        try:
            with open("/tmp/gt_ransom_wazuh.json") as f:
                w = json.load(f)
            with open("/tmp/gt_ransom_so.json") as f:
                s = json.load(f)
            print("\n=== DIFF wazuh vs so (ransomware ground-truth) ===")
            diffs = []
            if w["passed"] != s["passed"] or w["total"] != s["total"]:
                diffs.append(f"summary: wazuh={w['passed']}/{w['total']} so={s['passed']}/{s['total']}")
            for cw, cs in zip(w["checks"], s["checks"]):
                if cw["ok"] != cs["ok"] or cw["detail"] != cs["detail"]:
                    diffs.append(f"{cw['label']}: wazuh={cw['ok']}({cw['detail']}) so={cs['ok']}({cs['detail']})")
            if diffs:
                for d in diffs:
                    print("  DIFF:", d)
                sys.exit(1)
            else:
                print("  IDENTICAL — Cerber ground-truth behaves the same on both backends.")
        except OSError as e:
            print(f"  ! no summary files: {e}")
            sys.exit(1)
