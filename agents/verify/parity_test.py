"""Ontology parity test: same logical event, Wazuh-shape vs SO-shape.

Feeds the SAME event (a C2 beacon) through the analyst verdict + router
classify in both backend shapes, then diffs the ontology execution
(category, role, verdict, techniques). Proves the spine executes identically
regardless of which SIEM produced the alert.
"""
import os, sys, json
from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, ".")
from tools.analyst_tools import AnalystClient
from router import classify
from tools.indexer_client import IndexerTransport

# The transport normalizes SO results; construct the two shapes the spine sees
# AFTER transport normalization (so we test the spine, not the transport).
# Wazuh shape: rule.* at top level (what recent_alerts returns).
wazuh_alert = {
    "alert_id": "parity-w-1",
    "srcip": "198.51.100.50",
    "dstip": "10.0.0.5",
    "agent": {"name": "network"},
    "rule": {"id": 86610, "level": 12, "groups": ["ids", "suricata", "attack"],
             "description": "ET MALWARE C2 Beacon from 198.51.100.50", "mitre": {"id": ["T1059.001"]}},
}
# SO shape: signal.rule.* (raw ES Security doc, pre-normalization).
so_signal = {
    "signal": {
        "rule": {"id": 86610, "level": 12, "tags": ["suricata", "attack"],
                 "description": "ET MALWARE C2 Beacon from 198.51.100.50"},
        "id": "so-sig-1",
    },
    "source": {"ip": "198.51.100.50"},
    "destination": {"ip": "10.0.0.5"},
    "agent": {"name": "network"},
}

# 1. Verify the transport NORMALIZES the SO shape into the Wazuh shape.
t = IndexerTransport()
so_norm = t._normalize(so_signal)
print("=== transport normalization ===")
print("SO normalized rule.level:", so_norm.get("rule", {}).get("level"), "| has signal wrapper:", "signal" in so_norm)

# 2. Run both through the spine (analyst verdict + router classify).
a = AnalystClient()
def run(label, alert):
    v = a.verdict(alert)
    cat, role = classify(alert)
    print(f"=== {label} ===")
    print(f"  verdict: {v['verdict']} | category: {v.get('category')} | role: {role}")
    print(f"  techniques: {v.get('techniques')} | rationale: {v.get('rationale','')[:60]}")
    return {"verdict": v["verdict"], "category": v.get("category"), "role": role, "techniques": v.get("techniques")}

r_w = run("WAZUH shape", wazuh_alert)
r_s = run("SO shape (normalized)", so_norm)

# 3. Diff the ontology execution.
print("=== PARITY RESULT ===")
parity = r_w == r_s
print("  execution identical:", parity)
if not parity:
    for k in r_w:
        if r_w[k] != r_s.get(k):
            print(f"  MISMATCH {k}: wazuh={r_w[k]} so={r_s.get(k)}")
