#!/usr/bin/env python3
"""Interim un-break: remove synthetic-user comment docs for a case (they
crash the SOC case view — unresolved author) and set the create doc's
so_case.userId to a REAL identity (admin) so author resolution succeeds
until per-role accounts exist. Usage: <case_id>"""
import base64
import json
import ssl
import sys
import urllib.request
import yaml

sys.path.insert(0, ".")
from config import settings

ADMIN_USER_ID = "96203a00-9881-4b54-9cf6-44104757c876"  # admin@ssop.com


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

    def _es(method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"https://{host}:{port}/{path}", data=data, method=method,
            headers={"Authorization": auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return json.loads(r.read().decode())

    # 0. resolve the create-doc _id (comments link via so_comment.caseId)
    q0 = {"query": {"term": {"so_audit_doc_id": case_id}}, "size": 5}
    res0 = _es("POST", "so-case/_search", q0)
    create_id = None
    for h in res0.get("hits", {}).get("hits", []):
        if (h["_source"].get("so_kind") or "") == "case":
            create_id = h["_id"]
            break
    if not create_id:
        print(f"no create doc for {case_id}; nothing to un-break")
        return 1

    # 1. delete ALL comment docs linked to this case (they carry the
    #    synthetic userId that crashes the SOC view).
    q = {"query": {"term": {"so_comment.caseId": create_id}}}
    out = _es("POST", "so-case/_delete_by_query", q)
    print(f"deleted comment docs (caseId={create_id}): {out.get('deleted', 0)}")

    # 2. point the create doc's userId at a real identity
    sc = res0["hits"]["hits"][0]["_source"].get("so_case") or {}
    sc["userId"] = ADMIN_USER_ID
    up = _es("POST", f"so-case/_update/{create_id}", {"doc": {"so_case": sc}})
    print(f"create {create_id} userId -> admin ({up.get('result')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
