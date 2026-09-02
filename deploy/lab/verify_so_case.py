#!/usr/bin/env python3
"""Force-refresh + count SO case docs for a case, and render the SO-side
report artifact (the SOC's human view). Usage: verify_so_case.py <case_id>"""
import json
import sys
import urllib.request
import base64
import ssl
import yaml

sys.path.insert(0, ".")
from config import settings


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _so_target():
    with open("transport.yaml") as f:
        cfg = yaml.safe_load(f)
    b = cfg["backends"]["securityonion"]
    import re
    m = re.match(r"https?://([^:]+)(?::(\d+))?", b["endpoint"])
    host = m.group(1) if m else "192.168.1.76"
    port = int(m.group(2) or 9200) if m else 9200
    user = b.get("user")
    pw = settings.so_indexer_password
    return host, port, user, pw


def _es(method, host, port, auth, path, body=None, ctx=None):
    ctx = ctx or _ctx()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"https://{host}:{port}/{path}", data=data, method=method,
        headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
        return json.loads(r.read().decode())


def main() -> int:
    case_id = sys.argv[1]
    host, port, user, pw = _so_target()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    # force refresh both indices, then count
    try:
        _es("POST", host, port, auth, "so-case/_refresh")
        _es("POST", host, port, auth, "so-casehistory/_refresh")
    except Exception as e:  # noqa: BLE001
        print("refresh:", e)

    q = {"query": {"term": {"so_related.case_id": case_id}}, "size": 100,
         "sort": [{"@timestamp": "asc"}]}
    res = _es("POST", host, port, auth, "so-case/_search", q)
    hits = res.get("hits", {}).get("hits", [])
    total = res.get("hits", {}).get("total", {}).get("value", len(hits))
    print(f"so-case docs for {case_id}: {total} (returned {len(hits)})")
    ops = [h["_source"] for h in hits]
    creates = [s for s in ops if s.get("so_operation") == "create"]
    comments = [s for s in ops if s.get("so_operation") == "comment"]
    print(f"  creates: {len(creates)} | comments: {len(comments)}")
    for s in creates[:2]:
        sc = s.get("so_case") or {}
        print(f"  CREATE title={sc.get('title')} status={sc.get('status')} category={sc.get('category')}")
    for s in comments[:3]:
        print(f"  comment: {(s.get('so_comment') or {}).get('message','')[:100]}")

    # render the SO-side report (the SOC human view of the case)
    try:
        from tools.report_gen import render_so_case_report
        md = render_so_case_report(case_id)
        print("\n=== SO-SIDE REPORT (SOC human view) ===")
        print(md[:2500])
    except Exception as e:  # noqa: BLE001
        print("so report render:", type(e).__name__, e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
