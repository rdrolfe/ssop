#!/usr/bin/env python3
"""Flip a published SO case's create-doc status to 'open' so it shows in the
SOC Cases default (Open) view. Usage: python3 deploy/lab/set_so_case_open.py <case_id>"""
import base64
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
    case_id = sys.argv[1]
    with open("transport.yaml") as f:
        cfg = yaml.safe_load(f)
    b = cfg["backends"]["securityonion"]
    import re
    m = re.match(r"https?://([^:]+)(?::(\d+))?", b["endpoint"])
    host = m.group(1) if m else "192.168.1.76"
    port = int(m.group(2) or 9200) if m else 9200
    auth = "Basic " + base64.b64encode(
        f"{b['user']}:{settings.so_indexer_password}".encode()).decode()
    ctx = _ctx()

    for idx in ("so-case", "so-casehistory"):
        q = {"query": {"bool": {"filter": [
            {"term": {"so_audit_doc_id": case_id}}]}}, "size": 5}
        req = urllib.request.Request(
            f"https://{host}:{port}/{idx}/_search", data=json.dumps(q).encode(),
            method="POST", headers={"Authorization": auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            res = json.loads(r.read().decode())
        hits = res.get("hits", {}).get("hits", [])
        if not hits:
            print(f"  {idx}: no create op for {case_id}")
            continue
        _id = hits[0]["_id"]
        sc = hits[0]["_source"].get("so_case") or {}
        sc["status"] = "open"
        body = {"doc": {"so_case": sc}}
        req = urllib.request.Request(
            f"https://{host}:{port}/{idx}/_update/{_id}", data=json.dumps(body).encode(),
            method="POST", headers={"Authorization": auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r2:
            out = json.loads(r2.read().decode())
        print(f"  {idx}: {_id} -> status=open (result={out.get('result')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
