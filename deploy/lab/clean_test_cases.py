#!/usr/bin/env python3
"""Clean up SO + spine state for TEST cases (meatsuit template tests).
Deletes SO docs for the given case ids and closes the spine cases.
Usage: python3 deploy/lab/clean_test_cases.py case-xxx [case-yyy ...]"""
import base64
import json
import ssl
import sys
import urllib.request
import yaml

sys.path.insert(0, ".")
from config import settings
from tools.case_tools import CaseStore


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def main() -> int:
    ids = sys.argv[1:]
    if not ids:
        print("usage: clean_test_cases.py case-xxx ...")
        return 1
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

    for cid in ids:
        # delete SO docs (so-case + so-casehistory)
        for idx in ("so-case", "so-casehistory"):
            q = {"query": {"term": {"so_related.case_id": cid}}}
            req = urllib.request.Request(
                f"https://{host}:{port}/{idx}/_delete_by_query",
                data=json.dumps(q).encode(), method="POST",
                headers={"Authorization": auth, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
                out = json.loads(r.read().decode())
            print(f"  {idx}: deleted {out.get('deleted', 0)}")
        # close spine case
        cs = CaseStore()
        c = cs.get_case(cid)
        if c:
            cs.close_case(cid, reason="test template cleanup")
            print(f"  spine: closed {cid}")
        else:
            print(f"  spine: {cid} not found (already gone)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
