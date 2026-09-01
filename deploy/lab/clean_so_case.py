#!/usr/bin/env python3
"""Remove ALL so-case/so-casehistory docs for a spine case (lab cleanup),
then the fixed publisher is run once to write a single deterministic set.

Why: the old publisher had no deterministic _id, so re-publishing appended a
second create op — the SOC Cases page then showed 2 cases for one spine
case. Also removes the junk detection-envelope doc (@timestamp=0, no op)
that a probe left in so-case.
"""
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


def _so_target():
    with open("transport.yaml") as f:
        cfg = yaml.safe_load(f)
    b = cfg["backends"]["securityonion"]
    import re
    m = re.match(r"https?://([^:]+)(?::(\d+))?", b["endpoint"])
    host = m.group(1) if m else "192.168.1.76"
    port = int(m.group(2) or 9200) if m else 9200
    return host, port, b.get("user"), settings.so_indexer_password


def _es(method, host, port, auth, path, body=None, ctx=None):
    ctx = ctx or _ctx()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"https://{host}:{port}/{path}", data=data, method=method,
        headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read().decode())


def main() -> int:
    case_id = sys.argv[1] if len(sys.argv) > 1 else "case-26b166ce32"
    host, port, user, pw = _so_target()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    for idx in ("so-case", "so-casehistory"):
        # 1. delete docs keyed to this case
        q = {"query": {"term": {"so_related.case_id": case_id}}}
        d = _es("POST", host, port, auth, f"{idx}/_delete_by_query", q)
        n = d.get("deleted", 0)
        # 2. delete stray docs (no so_related at all — the junk envelope doc)
        q2 = {"query": {"bool": {"must_not": {"exists": {"field": "so_related"}}}}}
        d2 = _es("POST", host, port, auth, f"{idx}/_delete_by_query", q2)
        n2 = d2.get("deleted", 0)
        print(f"{idx}: deleted {n} case docs + {n2} stray docs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
