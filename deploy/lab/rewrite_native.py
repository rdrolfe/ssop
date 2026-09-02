#!/usr/bin/env python3
"""Rewrite the create doc + comments for a case using the NATIVE schema,
directly, when re-publishing is needed after schema changes. Usage: <case_id>"""
import base64
import json
import sys
import urllib.request
import ssl
import yaml

sys.path.insert(0, ".")
from config import settings
from deploy.lab.publish_case_so import _so_operations, _op_ids, _so_target, _ctx, _es


def main() -> int:
    case_id = sys.argv[1]
    sys.path.insert(0, ".")
    from tools.case_tools import CaseStore
    case = CaseStore().get_case(case_id)
    if not case:
        print(f"case {case_id} not in spine")
        return 1
    host, port, user, pw = _so_target()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    ops, create_id = _so_operations(case)
    ids = _op_ids(case_id, len(ops))
    ids[0] = create_id
    bulk = []
    for op, oid in zip(ops, ids):
        bulk.append({"index": {"_index": "so-case", "_id": oid}})
        bulk.append(op)
    body = "".join(json.dumps(x) + "\n" for x in bulk)
    req = urllib.request.Request(
        f"https://{host}:{port}/_bulk", data=body.encode(), method="POST",
        headers={"Authorization": auth, "Content-Type": "application/x-ndjson"})
    with urllib.request.urlopen(req, timeout=30, context=_ctx()) as r:
        out = json.loads(r.read().decode())
    errs = sum(1 for item in out.get("items", []) if "error" in (item.get("index") or {}))
    print(f"native rewrite: {len(ops)} ops, {errs} errors, create_id={create_id}")
    return 0 if errs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
