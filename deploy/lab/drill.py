#!/usr/bin/env python3
"""SSOP standing purple-team drill — self-verifying, scheduled.

Fires a known technique into the lab, runs the spine against the ACTIVE
backend (wazuh | securityonion from transport.yaml), asserts the decision
chain, and writes a PASS/FAIL receipt the daily digest reads.

Phase 1 — LIVE FIRE: an SSH brute-force burst against localhost (this host
runs the Wazuh agent). Failed logins land in the active backend's alert
index as sshd auth-failure (Wazuh 5710); we then assert the alert was
ingested AND the analyst classified it (note is CORRECT for a single
failed login — anti-noise working as designed).

Phase 2 — GROUND-TRUTH CHAIN: runs the BOTSv1 Cerber process-create event
(121214.tmp, the ransomware drop) through the full spine — recognize ->
investigate -> supervise -> recommend. Asserts escalate, >=1 evidence
source, approve, and a recommended playbook. This is the decision chain
proven identical on both backends.

Receipt: ~/.ssop/state/drill-last.json — {ts, backend, phase1{...},
phase2{...}, pass, fail}. The digest appends a one-line drill status.

Non-mutating to the queue: phase 1 opens no case/ticket (single failed
login = note); phase 2 opens+adjudicates+closes one throwaway case and
escalates nothing (adjudication only, no escalator call).

Usage: python3 drill.py   (reads active backend; write receipt)
"""
import json
import socket
import subprocess
import sys
import time
import datetime
from pathlib import Path

RECEIPT = Path.home() / ".ssop" / "state" / "drill-last.json"
WINDOW_S = 120  # phase-1 polling window for the fired alert


def sh(cmd: str, timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception as e:  # noqa: BLE001 — a probe must never kill the drill
        return f"ERR {e}"


def active_backend() -> str:
    try:
        import yaml
        tp = yaml.safe_load(Path("transport.yaml").read_text()) if Path("transport.yaml").exists() else {}
        return tp.get("backend", "?")
    except Exception:
        return "?"


def phase1_live_fire() -> dict:
    """Fire 3 failed SSH logins, then assert the alert landed + was classified."""
    backend = active_backend()
    # The Wazuh agent on THIS host reports failed logins to the active
    # backend's alert stream. Fire real auth failures.
    fired = 0
    for _ in range(3):
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
             "nonexistent-user@127.0.0.1", "echo hi"],
            capture_output=True, text=True, timeout=6)
        if r.returncode != 0:
            fired += 1
    # Poll for the fired alert. NOTE: the fired SSH failures are reported by
    # THIS host's Wazuh agent, so they land in the WAZUH indexer regardless
    # of the active transport backend. Phase1 therefore verifies the live
    # ingest path on the Wazuh side (explicit endpoint), while phase2 runs
    # the decision chain against the ACTIVE backend.
    found = []
    try:
        import yaml as _yaml
        from tools.investigator import Investigator
        from tools.analyst_tools import AnalystClient
        # Resolve the Wazuh backend endpoint + creds from transport.yaml.
        tp = _yaml.safe_load(Path("transport.yaml").read_text())
        b = (tp.get("backends") or {}).get("wazuh", {})
        ep = b.get("endpoint") or ""
        host = ep.replace("https://", "").replace("http://", "").split(":")[0] or "192.168.1.75"
        from config import settings
        user = b.get("user") or settings.indexer_user
        pw = settings.indexer_password
        idx = b.get("alerts_index") or "wazuh-alerts-4.x-*"
        inv = Investigator(indexer_host=host, user=user, password=pw)
        body = {
            "size": 5,
            "query": {"bool": {"filter": [
                {"term": {"rule.id": "5710"}},
                {"range": {"@timestamp": {"gte": "now-3m"}}},
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        for _ in range(5):
            r = inv._search(idx, body)
            found = r.get("hits", {}).get("hits", [])
            if found:
                break
            time.sleep(5)
        landed = len(found) > 0
        verdicts = []
        if found:
            a = AnalystClient()
            for h in found[:2]:
                v = a.verdict(h.get("_source", {}))
                verdicts.append(v["verdict"])
        ok = landed and all(v == "note" for v in verdicts)
        return {
            "fired": fired,
            "landed": landed,
            "alert_count": len(found),
            "verdicts": verdicts,
            "ok": ok,
            "detail": (f"{len(found)} sshd auth-failure alerts on wazuh, "
                       f"analyst: {set(verdicts) or 'n/a'} (note = correct anti-noise)"),
        }
    except Exception as e:  # noqa: BLE001
        return {"fired": fired, "landed": False, "alert_count": 0,
                "verdicts": [], "ok": False, "detail": f"ERR {e}"}


def phase2_ground_truth() -> dict:
    """Run the Cerber process-create event through the full spine chain."""
    try:
        from tools.indexer_client import IndexerTransport
        from tools.bots_parser import normalize
        from tools.analyst_tools import AnalystClient
        from tools.investigator import Investigator
        from tools.case_tools import CaseStore
        from tools.supervisory_tools import SupervisoryClient

        t = IndexerTransport()
        r = t.search({"size": 1, "query": {"match_phrase": {"_raw": "121214.tmp"}}},
                     index="bots-sysmon-op-poc")
        hits = r.get("hits", {}).get("hits", [])
        if not hits:
            return {"ok": False, "detail": "Cerber 121214.tmp not in bots-sysmon-op-poc on active backend"}

        # 1. RECOGNIZE
        norm = normalize(hits[0]["_source"])
        a = AnalystClient()
        v = a.verdict(norm)
        recognize_ok = v["verdict"] == "escalate"

        # 2. INVESTIGATE (backend-aware — auto-resolves active backend)
        srcip = norm.get("data", {}).get("srcip") or norm.get("srcip") or "192.168.250.100"
        inv = Investigator()
        ires = inv.investigate(srcip=srcip)
        n_ev = len(ires.get("evidence", []))
        sev = ires.get("severity_label", "low")
        investigate_ok = n_ev > 0

        # 3. SUPERVISE (evidence-aware approve + playbook)
        cs = CaseStore(); sup = SupervisoryClient()
        case = cs.open_case(
            source={"alert_id": "drill-cerber", "agent": "we8105desk",
                    "rule_desc": "Cerber process", "rule_id": "bots-threat-proc"},
            title="Cerber drill (throwaway)", observables=[{"type": "ip", "value": srcip}])
        cs.append_event(case["case_id"], "analyst", "verdict", {
            "verdict": "escalate", "level": v.get("level", 8),
            "category": v["category"], "agent": "we8105desk"})
        cs.append_event(case["case_id"], "analyst", "investigation", {
            "entity": srcip, "evidence_count": n_ev,
            "kill_chain": ires.get("kill_chain", []),
            "severity": ires.get("severity", 0),
            "severity_label": sev, "evidence": ires.get("evidence", []),
            "hypothesis": ires.get("hypothesis", ""),
        })
        dec = sup.adjudicate_with_investigation(case["case_id"])
        supervise_ok = dec["decision"] == "approve"
        recommend = dec.get("recommended_playbook")
        recommend_ok = bool(recommend)
        try:
            cs.close_case(case["case_id"])
        except Exception:
            pass

        ok = recognize_ok and investigate_ok and supervise_ok and recommend_ok
        return {
            "ok": ok,
            "recognize": v["verdict"], "category": v["category"],
            "evidence": n_ev, "severity": sev, "score": ires.get("severity", 0),
            "decision": dec["decision"], "playbook": recommend,
            "detail": (f"escalate({v['category']}) -> {n_ev} sources/{sev} -> "
                       f"{dec['decision']} -> {recommend}"),
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": f"ERR {e}"}


def main() -> int:
    backend = active_backend()
    p1 = phase1_live_fire()
    p2 = phase2_ground_truth()
    ok = p1.get("ok") and p2.get("ok")
    receipt = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "backend": backend,
        "phase1_live_fire": p1,
        "phase2_ground_truth": p2,
        "pass": bool(ok),
        "fail": not ok,
    }
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
