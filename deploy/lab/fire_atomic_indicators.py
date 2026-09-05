#!/usr/bin/env python3
"""Live-fire atomic-indicator injector (MITRE-style, fresh rule ids).

Writes REAL-shape alert docs into the live Wazuh alerts index so the router
sweep mints fresh cases and IRIS gets reps. Each indicator is a distinct
kill-chain technique with its own fresh rule id (never tuned), a real
entity (BOTSv1 ground-truth 192.168.250.100 or the .13/.10 attack plane),
and level >= 7 so the analyst escalates.

Run on infra-ops via ssh-stdin. Idempotent-ish: fixed doc ids per
indicator (re-run overwrites rather than duplicates).
"""
import json
import os
import ssl
import sys
import urllib.request
from datetime import datetime, timezone

# Bootstrap: the runtime imports from the agent-runtime ROOT (tools/, config),
# not from the script's own dir. Running via ssh-stdin from the runtime root
# already has cwd on the path; add it explicitly for the systemd timer path.
sys.path.insert(0, os.getcwd())
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.indexer_client import IndexerTransport

t = IndexerTransport()
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def call(method, path, body=None):
    req = urllib.request.Request(
        f"https://{t.host}:{t.port}/{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": t._auth(), "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        return json.loads(r.read().decode())


# Resolve the live concrete index (alias pattern -> newest daily index).
idx = call("GET", "_cat/indices/wazuh-alerts-4.x-*?h=index&format=json")
target = sorted(i["index"] for i in idx)[-1]
print("target index:", target)

now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
# Router cursor last saw ~20:45Z; stamp docs at now+1s so they clear the
# cursor's gte filter even across clock skew.
import time as _time
_time.sleep(1.1)
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# The Wazuh indexer maps the canonical field to "timestamp" (NOT "@timestamp")
# for the router's sweep query (router.py range on field "timestamp"). Wazuh
# native docs carry BOTH; inject with timestamp set so the router cursor sees
# them, plus @timestamp for dashboard display.
_TS_FIELD = "timestamp"

# Atomic indicators: fresh MITRE-style rules, distinct techniques.
INDICATORS = [
    # T1046 network scan (recon)
    dict(key="atomic-t1046-scan", rule_id="991046", level=7,
         desc="ET SCAN Behavioral Unusual Port Scan detected", groups=["suricata", "ids", "scan"],
         mitre=("T1046", ["Reconnaissance"]),
         agent="we8105desk.waynecorpinc.local",
         srcip="192.168.250.100", dstip="10.10.1.11", dstport=445),
    # T1053.005 scheduled task (persistence)
    dict(key="atomic-t1053-task", rule_id="991053", level=10,
         desc="ET MALWARE Scheduled Task Creation for Persistence", groups=["sysmon", "persistence", "process_creation"],
         mitre=("T1053.005", ["Persistence", "Privilege Escalation"]),
         agent="we8105desk.waynecorpinc.local",
         image="C:\\Windows\\System32\\schtasks.exe",
         cmdline="schtasks /create /tn Updater /tr powershell.exe -enc JABjAGwAaQBlAG4AdAAgA" ),
    # T1071.001 HTTP exfil (exfiltration)
    dict(key="atomic-t1071-exfil", rule_id="991071", level=12,
         desc="ET MALWARE Possible HTTP Exfiltration to C2", groups=["suricata", "malware", "c2", "http"],
         mitre=("T1071.001", ["Exfiltration", "C2"]),
         agent="we8105desk.waynecorpinc.local",
         srcip="192.168.250.100", dstip="10.10.1.20", dstport=8080,
         uri="/upload/data.aspx"),
    # T1566.001 phishing link (initial access)
    dict(key="atomic-t1566-phish", rule_id="991566", level=8,
         desc="ET MALWARE Suspicious Phishing Link in Mail", groups=["suricata", "malware", "phishing"],
         mitre=("T1566.001", ["Initial Access"]),
         agent="we8105desk.waynecorpinc.local",
         srcip="192.168.250.100", dstip="198.51.100.7", dstport=443),
    # T1572 protocol tunneling (C2)
    dict(key="atomic-t1572-tunnel", rule_id="991572", level=9,
         desc="ET MALWARE Possible DNS Tunneling Activity (T1572)", groups=["suricata", "malware", "c2", "dns"],
         mitre=("T1572", ["C2", "Exfiltration"]),
         agent="we8105desk.waynecorpinc.local",
         srcip="192.168.250.100", dstip="8.8.8.8", dstport=53,
         query="fhefdjdadedbdfcfgcacacacacacaca.tunnel.example.net"),
]

created = 0
for ind in INDICATORS:
    doc = {
        _TS_FIELD: now,
        "@timestamp": now,
        "id": ind["key"],
        "rule": {
            "id": ind["rule_id"], "level": ind["level"],
            "description": ind["desc"], "groups": ind["groups"],
            "mitre": {"id": [ind["mitre"][0]], "tactic": ind["mitre"][1]},
        },
        "agent": {"name": ind["agent"]},
        "data": {k: v for k, v in ind.items() if k in
                 ("srcip", "dstip", "dstport", "uri", "query", "image", "cmdline")},
        "input": {"type": "log"},
    }
    try:
        r = call("PUT", f"{target}/_doc/{ind['key']}", doc)
        created += 1
        print(f"  + {ind['key']:22s} {ind['desc'][:50]} (result={r.get('result')})")
    except Exception as e:
        print(f"  ! {ind['key']}: {e}")

print(f"injected {created}/{len(INDICATORS)} -> {target}")
