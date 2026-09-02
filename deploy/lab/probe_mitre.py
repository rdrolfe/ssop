#!/usr/bin/env python3
"""Probe live alerts for MITRE fields — what technique IDs actually appear
in the data, so the resolver table is grounded, not guessed."""
import json
import sys
from collections import Counter

sys.path.insert(0, ".")
from tools.indexer_client import IndexerTransport

t = IndexerTransport()
# docs carrying rule.mitre or mitre.attack in the last few days
q = {"query": {"bool": {"should": [
    {"exists": {"field": "rule.mitre"}},
    {"exists": {"field": "mitre.attack"}},
]}}, "size": 100, "sort": [{"@timestamp": "desc"}]}
try:
    r = t.search(q, index="wazuh-alerts-4.x-*")
    hits = r.get("hits", {}).get("hits", [])
    print("alerts with mitre fields:", r.get("hits", {}).get("total", {}).get("value"), "| sampled:", len(hits))
    ids = Counter()
    for h in hits:
        s = h["_source"]
        rule = s.get("rule") or {}
        mitre = rule.get("mitre") or {}
        for key in ("id", "technique"):
            v = mitre.get(key)
            if isinstance(v, list):
                for x in v:
                    ids[str(x)] += 1
            elif v:
                ids[str(v)] += 1
        attack = (s.get("mitre") or {}).get("attack") or {}
        tech = attack.get("technique") or attack.get("id")
        if isinstance(tech, list):
            for x in tech:
                if isinstance(x, dict):
                    ids[str(x.get("id") or x.get("name"))] += 1
                else:
                    ids[str(x)] += 1
        elif tech:
            ids[str(tech)] += 1
    print("technique ids seen in live data:")
    for tid, n in ids.most_common(20):
        print(f"  {tid}: {n}")
except Exception as e:  # noqa: BLE001
    print("probe failed:", str(e)[:200])
