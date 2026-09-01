#!/usr/bin/env python3
"""Capture both surfaces for the bake-off seed case.

Reads:
  - SO side: the native so-case store (activity log) for the seed case
  - Wazuh side: the console API /cases?case_id= (reads the spine) + the
    /report?case_id= deliverable (spine) and /report?case_id=&backend=so
    deliverable (SO-native) — axis-6 output for both backends
and writes /tmp/bakeoff_capture.json with both representations.

Usage: python3 capture_bakeoff.py [case_id]
"""
import base64
import json
import re
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
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        return json.loads(r.read().decode())


def _so_ops(case_id, host, port, auth):
    """SO native so-case docs for the case (fixed query: no .keyword subfield)."""
    q = {"query": {"bool": {"filter": [
        {"term": {"so_related.case_id": case_id}}]}},
         "size": 50, "sort": [{"@timestamp": "asc"}]}
    so = _es("POST", host, port, auth, "so-case/_search", q)
    ops = []
    for h in so.get("hits", {}).get("hits", []):
        s = h["_source"]
        ops.append({
            "operation": s.get("so_operation"),
            "ts": s.get("@timestamp"),
            "case_title": (s.get("so_case") or {}).get("title"),
            "category": (s.get("so_case") or {}).get("category"),
            "tags": (s.get("so_case") or {}).get("tags", []),
            "comment": (s.get("so_comment") or {}).get("message"),
            "related": (s.get("so_related") or {}),
        })
    return ops, so.get("hits", {}).get("total", {}).get("value")


def _console_case(case_id):
    """The Wazuh console /cases?case_id= view (reads the spine)."""
    try:
        req = urllib.request.Request(f"https://192.168.1.75:5602/cases?case_id={case_id}",
                                     headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20, context=_ctx()) as r:
            return json.loads(r.read().decode())
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def _report(case_id, backend):
    """The axis-6 report deliverable from one backend (markdown)."""
    try:
        req = urllib.request.Request(
            f"https://192.168.1.75:5602/report?case_id={case_id}&backend={backend}",
            headers={"Accept": "text/markdown"})
        with urllib.request.urlopen(req, timeout=20, context=_ctx()) as r:
            return r.read().decode()
    except Exception as e:  # noqa: BLE001
        return f"(error: {type(e).__name__}: {e})"


def main() -> int:
    case_id = sys.argv[1] if len(sys.argv) > 1 else "case-26b166ce32"
    host, port, user, pw = _so_target()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    so_ops, so_total = _so_ops(case_id, host, port, auth)
    console = _console_case(case_id)
    report_spine = _report(case_id, "spine")
    report_so = _report(case_id, "so")

    out = {
        "case_id": case_id,
        "captured_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "so_native_case_store": so_ops,
        "so_total_docs": so_total,
        "wazuh_console_api": console,
        "report_spine_markdown": report_spine,
        "report_so_markdown": report_so,
    }
    with open("/tmp/bakeoff_capture.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(json.dumps({
        "case_id": case_id,
        "so_docs": so_total,
        "so_ops_captured": len(so_ops),
        "console_ok": "case" in console or "cases" in console,
        "console_err": console.get("error"),
        "report_spine_len": len(report_spine),
        "report_so_len": len(report_so),
    }, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
