#!/usr/bin/env python3
"""Capture both surfaces for the bake-off seed case (dodge nested-ssh quoting).

Reads:
  - SO side: the native so-case store (activity log) for the seed case
  - Wazuh side: the console API /cases (reads the spine)
and writes /tmp/bakeoff_capture.json with both representations.
"""
import json
import ssl
import sys
import urllib.request
import yaml

sys.path.insert(0, ".")
from config import settings


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def main() -> int:
    case_id = sys.argv[1] if len(sys.argv) > 1 else "case-26b166ce32"
    ctx = _ctx()

    # --- SO side: read back so-case for the seed case ---
    with open("transport.yaml") as f:
        cfg = yaml.safe_load(f)
    b = cfg["backends"]["securityonion"]
    import re
    m = re.match(r"https?://([^:]+)(?::(\d+))?", b["endpoint"])
    host = m.group(1) if m else "192.168.1.76"
    port = int(m.group(2) or 9200) if m else 9200
    import base64
    auth = "Basic " + base64.b64encode(
        f"{b.get('user')}:{settings.so_indexer_password}".encode()).decode()
    q = {"query": {"bool": {"filter": [
        {"term": {"so_case.id.keyword": case_id}}]}},
         "size": 20, "sort": [{"@timestamp": "asc"}]}
    req = urllib.request.Request(
        f"https://{host}:{port}/so-case/_search", data=json.dumps(q).encode(),
        method="POST", headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
        so = json.loads(r.read().decode())

    so_ops = []
    for h in so.get("hits", {}).get("hits", []):
        s = h["_source"]
        so_ops.append({
            "operation": s.get("so_operation"),
            "ts": s.get("@timestamp"),
            "case_title": (s.get("so_case") or {}).get("title"),
            "comment": (s.get("so_comment") or {}).get("message"),
            "related": (s.get("so_related") or {}),
        })

    # --- Wazuh side: console API ---
    wazuh_view = {}
    try:
        req = urllib.request.Request("https://192.168.1.75:5602/cases",
                                     headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            d = json.loads(r.read().decode())
        for c in d.get("cases", []):
            if c.get("case_id") == case_id:
                wazuh_view = c
                break
        if not wazuh_view:
            wazuh_view = {"note": f"case {case_id} not in console /cases response "
                                  f"({len(d.get('cases', []))} total)"}
    except Exception as e:
        wazuh_view = {"error": f"{type(e).__name__}: {e}"}

    out = {
        "case_id": case_id,
        "so_native_case_store": so_ops,
        "so_total_docs": so.get("hits", {}).get("total", {}).get("value"),
        "wazuh_console_api": wazuh_view,
    }
    print(json.dumps(out, indent=2, default=str))
    with open("/tmp/bakeoff_capture.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
