#!/usr/bin/env python3
"""Verify the attached report/advisory ops in SO store: they exist, carry
role=report, and hold the report/advisory markdown. Usage: <case_id>"""
import base64
import json
import sys
import urllib.request
import ssl
import yaml

sys.path.insert(0, ".")
from config import settings


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def main() -> int:
    case_id = sys.argv[1]
    with open("transport.yaml") as f:
        cfg = yaml.safe_load(f)
    b = cfg["backends"]["securityonion"]
    import re
    m = re.match(r"https?://([^:]+)(?::(\d+))?", b["endpoint"])
    host = m.group(1) if m else "192.168.1.76"
    port = int(m.group(2) or 9200) if m else 9200
    auth = "Basic " + base64.b64encode(f"{b['user']}:{settings.so_indexer_password}".encode()).decode()

    # refresh then pull ALL ops for the case
    for idx in ("so-case", "so-casehistory"):
        req = urllib.request.Request(
            f"https://{host}:{port}/{idx}/_refresh", data=b"", method="POST",
            headers={"Authorization": auth})
        urllib.request.urlopen(req, timeout=20, context=_ctx())

    q = {"query": {"term": {"so_related.case_id": case_id}}, "size": 300,
         "sort": [{"@timestamp": "asc"}]}
    req = urllib.request.Request(
        f"https://{host}:{port}/so-case/_search", data=json.dumps(q).encode(),
        method="POST", headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=_ctx()) as r:
        res = json.loads(r.read().decode())
    hits = res.get("hits", {}).get("hits", [])
    print("total so-case docs:", res["hits"]["total"]["value"])
    art = [h["_source"] for h in hits if (h["_source"].get("so_related") or {}).get("role") == "report"]
    print("artifact ops (role=report):", len(art))
    for s in art:
        rel = s.get("so_related") or {}
        msg = (s.get("so_comment") or {}).get("message", "")
        print(f"  [{rel.get('type')}] op={s.get('so_operation')} len={len(msg)} "
              f"head={msg[:60]!r}")
    # idempotency: re-run attach should NOT duplicate
    from tools.attach_case_report import publish_artifacts_to_so
    publish_artifacts_to_so(case_id)
    req = urllib.request.Request(
        f"https://{host}:{port}/so-case/_refresh", data=b"", method="POST",
        headers={"Authorization": auth})
    urllib.request.urlopen(req, timeout=20, context=_ctx())
    req = urllib.request.Request(
        f"https://{host}:{port}/so-case/_search", data=json.dumps(q).encode(),
        method="POST", headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=_ctx()) as r2:
        res2 = json.loads(r2.read().decode())
    print("after re-attach total:", res2["hits"]["total"]["value"],
          "(want same => idempotent upsert)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
