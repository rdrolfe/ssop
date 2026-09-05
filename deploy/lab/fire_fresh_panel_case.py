#!/usr/bin/env python3
"""One-off: fire ONE fresh untuned alert (novel rule id, live-fleet shape).

Deliberately NOT a corpus batch: no atomic-* doc id, no 99xxxx rule family,
no BOTS 192.168.2xx subnet, single doc (no same-second batch). The corpus-FP
classifier keys on those markers; this doc should stay human-decidable so the
IRIS panel can be exercised end-to-end.
"""
import json
import os
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.getcwd())
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


idx = call("GET", "_cat/indices/wazuh-alerts-4.x-*?h=index&format=json")
target = sorted(i["index"] for i in idx)[-1]
time.sleep(1.1)
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

doc = {
    "timestamp": now,
    "@timestamp": now,
    "id": "fresh-cred-access-" + now.replace(":", "")[-6:],
    "rule": {
        "id": "994242", "level": 12,
        "description": "ET MALWARE LSASS Memory Dump via Procdump",
        "groups": ["windows", "sysmon", "credential_access"],
        "mitre": {"id": ["T1003.001"], "tactic": ["Credential Access"]},
    },
    "agent": {"id": "004", "name": "we8105desk.waynecorpinc.local"},
    "data": {"srcip": "192.168.1.50", "dstip": "192.168.1.50",
             "image": "C:\\Windows\\System32\\procdump.exe",
             "cmdline": "procdump.exe -ma lsass.exe"},
    "input": {"type": "log"},
}
r = call("PUT", f"{target}/_doc/{doc['id']}", doc)
print("injected:", r.get("result"), "->", target, "id:", doc["id"], "ts:", now)
