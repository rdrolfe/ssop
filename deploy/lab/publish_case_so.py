#!/usr/bin/env python3
"""Bake-off seed: publish one fully-decided spine case into SO's native
case store (so-case/so-casehistory) and capture both surfaces.

This is the "human experience parity" experiment: our spine is the source
of truth (one incident, fully decided), and we measure how each SIEM's
case surface communicates the ontology + the agent's compliance to it.

Seed case: case-26b166ce32 — DNS tunneling (NIMLOC) threat, escalate ->
investigate (2 sources, 2-chain) -> supervisor deny (false_positive).
A complete negative-outcome story, ideal for evaluating how each side
communicates WHY an alert was NOT acted on.

SO's native case model is an activity log: each doc in so-case carries
  so_case (the case object/fields), so_kind, so_operation, so_artifact,
  so_comment, so_related, so_audit_doc_id, @timestamp.
The SOC UI renders these. so-casehistory tracks the case history.

We map the spine timeline onto SO operations:
  case create   -> so_operation: create,   so_case: {...}
  timeline evt  -> so_operation: comment,  so_comment: {message, ...}  (+ so_related to link the event)
Then read back what SO stores (the SO-side human surface).

Also dumps the console API's representation (the Wazuh-side surface, which
reads the spine directly) so the two can be compared side by side.

Usage: python3 publish_case_so.py <case_id>
"""
import json
import sys
import urllib.request
import base64
import ssl
import yaml
from datetime import datetime, timezone

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
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        return json.loads(r.read().decode())


def _spine_case(case_id):
    from tools.case_tools import CaseStore
    cs = CaseStore()
    case = cs.get_case(case_id)
    if not case:
        return None
    return case


def _console_view(case_id):
    """The Wazuh-side human surface (console reads the spine). Returns raw JSON."""
    try:
        req = urllib.request.Request("https://192.168.1.75:5602/cases",
                                     headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15, context=_ctx()) as r:
            d = json.loads(r.read().decode())
        for c in d.get("cases", []):
            if c.get("case_id") == case_id:
                return c
        return {"case_id": case_id, "note": "not returned by console API"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def _so_operations(case):
    """Map the spine case onto SO case operations."""
    ts = case.get("ts") or datetime.now(timezone.utc).isoformat()
    ops = []
    # Category parity (bake-off axis 1): the spine's source.category is often
    # unset (router dispatch), but the analyst verdict in the timeline carries
    # the ontology category — the console reader derives it from there.
    # Backfill it so the SO create op carries the same category the console
    # shows, otherwise an SO-side operator sees verdict+decision without the
    # ontology tie-in.
    source_cat = (case.get("source") or {}).get("category", "")
    category = source_cat
    if not category:
        for ev in case.get("timeline", []):
            ev_cat = (ev.get("detail") or {}).get("category")
            if ev_cat:
                category = ev_cat
                break
    # 1. case create
    so_case = {
        "id": case["case_id"],
        "title": case.get("title", ""),
        "status": case.get("status", "new"),
        "description": case.get("title", ""),
        "category": category,
        "tags": [],
    }
    src = case.get("source") or {}
    if src.get("hunt_id"):
        so_case["tags"].append(f"hunt:{src['hunt_id']}")
    if src.get("rule_desc"):
        so_case["description"] = f"{case.get('title','')}\n\n{src['rule_desc']}"
    for obs in case.get("observables", []):
        so_case["tags"].append(f"{obs.get('type')}:{obs.get('value')}")
    ops.append({
        "@timestamp": ts,
        "so_case": so_case,
        "so_kind": "case",
        "so_operation": "create",
        "so_audit_doc_id": case["case_id"],
        "so_related": {"case_id": case["case_id"]},
    })
    # 2. timeline events -> comments (each role step is a comment on the case)
    for ev in case.get("timeline", []):
        d = ev.get("detail", {})
        msg = f"[{ev.get('role','?')}/{ev.get('type','?')}] "
        if ev.get("type") == "verdict":
            msg += f"decision={d.get('decision') or d.get('verdict')} verdict={d.get('verdict')} level={d.get('level')} cat={d.get('category')}"
        elif ev.get("type") == "investigation":
            msg += (f"{d.get('evidence_count')} evidence sources, "
                    f"severity={d.get('severity_label')} ({d.get('severity')}), "
                    f"chain={d.get('kill_chain')}")
        elif ev.get("type") == "finding":
            msg += f"finding={d.get('finding')} confidence={d.get('confidence')} summary={d.get('summary','')[:100]}"
        elif ev.get("type") in ("adjudication", "verdict"):
            msg += f"decision={d.get('decision')} rationale={d.get('rationale','')[:100]}"
        else:
            msg += json.dumps(d)[:150]
        ops.append({
            "@timestamp": ev.get("ts") or ts,
            "so_case": {"id": case["case_id"]},
            "so_kind": "timeline",
            "so_operation": "comment",
            "so_comment": {"message": msg},
            "so_related": {"case_id": case["case_id"], "role": ev.get("role"), "type": ev.get("type")},
        })
    return ops


def _op_ids(case_id: str, n: int) -> list[str]:
    """Deterministic _ids per operation index, so re-publishing UPSERTS
    instead of appending (which made the SOC show 2 cases for one spine
    case after a re-run)."""
    import hashlib
    return [
        "ssop-" + hashlib.sha1(f"{case_id}-{i}".encode()).hexdigest()[:20]
        for i in range(n)
    ]


def main() -> int:
    case_id = sys.argv[1] if len(sys.argv) > 1 else "case-26b166ce32"
    case = _spine_case(case_id)
    if not case:
        print(f"case {case_id} not in spine")
        return 1
    host, port, user, pw = _so_target()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    # Build + write the SO operations (bulk into so-case, then so-casehistory)
    ops = _so_operations(case)
    ids = _op_ids(case_id, len(ops))
    bulk = []
    for op, oid in zip(ops, ids):
        bulk.append({"index": {"_index": "so-case", "_id": oid}})
        bulk.append(op)
        hist = {**op, "so_kind": "casehistory"}
        bulk.append({"index": {"_index": "so-casehistory", "_id": oid}})
        bulk.append(hist)
    body = "".join(json.dumps(x) + "\n" for x in bulk)
    req = urllib.request.Request(
        f"https://{host}:{port}/_bulk", data=body.encode(), method="POST",
        headers={"Authorization": auth, "Content-Type": "application/x-ndjson"})
    with urllib.request.urlopen(req, timeout=30, context=_ctx()) as r:
        out = json.loads(r.read().decode())
    errs = sum(1 for item in out.get("items", []) if "error" in (item.get("index") or {}))
    print(f"wrote {len(ops)} SO operations x2 (case+history, deterministic ids), {errs} errors")

    # Capture SO-side: read back what SO stores for this case
    print("\n=== SO-SIDE (native so-case store) ===")
    q = {"query": {"term": {"so_related.case_id": case_id}}, "size": 20,
         "sort": [{"@timestamp": "asc"}]}
    res = _es("POST", host, port, auth, "so-case/_search", q)
    hits = res.get("hits", {}).get("hits", [])
    print(f"so-case docs for {case_id}: {len(hits)}")
    for h in hits:
        s = h["_source"]
        op = s.get("so_operation", "?")
        if op == "create":
            print("  CREATE:", s.get("so_case", {}).get("title", "")[:60])
        else:
            print("  ", op, "|", (s.get("so_comment") or {}).get("message", "")[:90])

    # Capture Wazuh-side (console API reads the spine)
    print("\n=== WAZUH-SIDE (console API) ===")
    cv = _console_view(case_id)
    if "error" in cv:
        print("  console API:", cv)
    else:
        print("  title:", cv.get("title", "?")[:70])
        print("  status:", cv.get("status"))
        print("  adjudication:", json.dumps(cv.get("adjudication"))[:200] if cv.get("adjudication") else None)
        print("  investigation:", json.dumps(cv.get("investigation"))[:200] if cv.get("investigation") else None)

    # Save both captures for the rubric
    out_doc = {"case_id": case_id, "so_side": hits, "wazuh_side": cv}
    with open("/tmp/bakeoff_capture.json", "w") as f:
        json.dump(out_doc, f, indent=2, default=str)
    print("\ncaptured -> /tmp/bakeoff_capture.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
