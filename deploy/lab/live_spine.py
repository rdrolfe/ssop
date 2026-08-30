#!/usr/bin/env python3
"""Live spine run: full decision chain against genuinely NEW live signals.

What's new this run (vs the replay fixtures):
  - T1046 port scan from ubuntu-target -> c2-sink  -> Suricata STREAM alert
  - T1053.005 scheduled task on win-target          -> service startup change
  - T1071.001 HTTP exfil -> c2-sink:8080            -> SO zeek conn.log

Sweeps a TIME WINDOW (not "newest N") filtered to the novel rule classes, so
baseline PAM/sshd noise doesn't bury the new signals. Uses the proven direct
clients against the LIVE index. Read-only except opening/adjudicating one real
case for an escalated signal (mirrors the operational flow).
"""
from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

from tools.analyst_tools import AnalystClient
from tools.case_tools import CaseStore
from tools.indexer_client import IndexerTransport
from tools.investigator import Investigator
from tools.supervisory_tools import SupervisoryClient

# Novel-signal rule classes we expect from the techniques we fired.
# Rule descriptions are matched loosely so SIEM-specific wording still hits.
NEW_SIGNAL_TERMS = (
    "suricata",      # network anomalies: scan STREAM alert
    "stream",        # SURICATA STREAM 3way handshake
    "service startup type",   # T1053.005 scheduled-task service change
    "scheduled task",
    "scheduled_tasks",
    "port scan",
    "network scan",
)

def is_new_signal(desc: str) -> bool:
    d = desc.lower()
    return any(t in d for t in NEW_SIGNAL_TERMS)


def main() -> int:
    analyst = AnalystClient()
    cases = CaseStore()
    sup = SupervisoryClient(cases=cases, analyst=analyst)
    inv = Investigator()

    print("=== LIVE SPINE — windowed sweep for novel signals (45m) ===")
    transport = IndexerTransport()
    body = {
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-45m"}}}]}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 200,
    }
    try:
        result = transport.search(body)
    except Exception as e:
        print(f"search ERR: {e}")
        return 1
    hits = result.get("hits", {}).get("hits", [])
    print(f"pulled {len(hits)} alerts in window")

    targets = []
    for h in hits:
        src = h.get("_source", {})
        desc = (src.get("rule") or {}).get("description", "") or ""
        if is_new_signal(desc):
            targets.append(src)
    print(f"new-signal candidates: {len(targets)}")
    if not targets:
        print("none in window — list top descriptions seen (debug):")
        from collections import Counter
        c = Counter()
        for h in hits:
            desc = (h.get("_source", {}).get("rule") or {}).get("description", "?")
            c[desc[:70]] += 1
        for desc, n in c.most_common(8):
            print(f"  {n:4d}  {desc}")
        return 1

    for alert in targets:
        desc = (alert.get("rule") or {}).get("description", "") or ""
        lvl = (alert.get("rule") or {}).get("level", 0)
        agent = alert.get("agent", {})
        agent_name = agent.get("name") if isinstance(agent, dict) else agent
        print(f"\n--- signal: {desc[:70]} (lvl={lvl} agent={agent_name}) ---")
        # 1. RECOGNIZE
        v = analyst.verdict(alert)
        print(f"  1. recognize: verdict={v['verdict']} level={v['level']} cat={v['category']}")
        if v["verdict"] != "escalate":
            print(f"     (not escalated: {v['rationale'][:60]})")
            continue
        # 2. INVESTIGATE (correlate on the relevant entity)
        srcip = alert.get("data", {}).get("srcip") or alert.get("srcip", "")
        if not srcip:
            srcip = "10.10.1.11"  # ubuntu-target attack NIC — the scanner
        res = inv.investigate(srcip=srcip)
        n_ev = len(res.get("evidence", []))  # evidence is a list, not evidence_count
        sev = res.get("severity_label", "?")
        chain = res.get("kill_chain", [])
        print(f"  2. investigate: {n_ev} evidence sources, severity={sev}, chain={len(chain)} (entity {srcip})")
        # 3. OPEN CASE + SUPERVISE
        case = cases.open_case(
            source={"alert_id": v["alert_id"], "agent": v["agent"], "rule_desc": desc},
            title=f"LIVE {v['category'].upper()} alert lvl={v['level']} on {v['agent']}",
        )
        cases.append_event(case["case_id"], "analyst", "verdict",
                           {"verdict": "escalate", "rationale": v["rationale"],
                            **{k: v[k] for k in ("level", "category", "agent")}})
        cases.append_event(case["case_id"], "analyst", "investigation", {
            "entity": srcip, "evidence_count": n_ev,
            "kill_chain": chain,  # supervisor adjudicates on this (medium + 2+ stages)
            "severity": res.get("severity", 0), "severity_label": sev,
        })
        dec = sup.adjudicate_with_investigation(case["case_id"])
        print(f"  3. supervise: decision={dec['decision']} used_inv={dec.get('used_investigation')}")
        # 4. RESPOND (dry-run)
        from responder import run as responder_run
        r = responder_run(alert, case_id=case["case_id"], dry_run=True)
        blocked = r.get("blocked", False)
        print(f"  4. respond: blocked={blocked} (dry-run)")
        cases.close_case(case["case_id"])
        print(f"     case {case['case_id']} closed after live run")

    print("\n=== LIVE SPINE DONE ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
