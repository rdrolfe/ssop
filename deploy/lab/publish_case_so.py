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
    # 1. case create — NATIVE schema (verified against the SOC's own docs
    #    + case-mappings.json): so_kind: "case", NO so_operation on the
    #    create, so_case carries the real fields (createTime/userId/priority/
    #    severity/status/tlp/pap/assigneeId...). The case identity is the
    #    CREATE DOC's _id — comments link via so_comment.caseId = create _id.
    now_iso = datetime.now(timezone.utc).isoformat()
    so_case = {
        "createTime": now_iso,
        "startTime": None,
        "completeTime": None,
        "title": case.get("title", ""),
        "description": case.get("title", ""),
        "priority": 0,
        "severity": "medium",
        "status": "new",
        "template": "",
        "tlp": "",
        "pap": "",
        "category": category,
        "assigneeId": "",
        "userId": settings.so_user_id_for_role(None),  # automation (create)
        "tags": [f"{obs.get('type')}:{obs.get('value')}" for obs in case.get("observables", [])],
    }
    src = case.get("source") or {}
    if src.get("hunt_id"):
        so_case["tags"] = (so_case["tags"] or []) + [f"hunt:{src['hunt_id']}"]
    if src.get("rule_desc"):
        so_case["description"] = f"{case.get('title','')}\n\n{src['rule_desc']}"
    ops.append({
        "@timestamp": now_iso,
        "so_case": so_case,
        "so_kind": "case",
        "so_audit_doc_id": case["case_id"],
    })
    create_id = _op_ids(case["case_id"], 1)[0]  # the create doc's deterministic _id

    # 2. timeline events -> NATIVE comment docs: so_kind "comment",
    #    so_comment {createTime, userId, caseId=create_id, description, hours},
    #    and so_related.caseId (camelCase) so the SOC links them to the case.
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
        ev_ts = (ev.get("ts") or now_iso).replace("+00:00", "Z").replace("Z", "+00:00")
        ops.append({
            "@timestamp": ev_ts,
            "so_kind": "comment",
            "so_comment": {
                "createTime": ev_ts,
                "userId": settings.so_user_id_for_role(ev.get("role")),
                "caseId": create_id,
                "description": msg,
                "hours": 0,
            },
            "so_related": {"caseId": create_id, "role": ev.get("role"), "type": ev.get("type")},
        })
    return ops, create_id


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
    ops, create_id = _so_operations(case)
    ids = _op_ids(case_id, len(ops))
    # the create doc's _id is the deterministic create id; comments already
    # link via so_comment.caseId=create_id, so any _id works for comments
    ids[0] = create_id
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

    # Capture SO-side: read back what SO stores for this case (refresh first —
    # NRT means a term query right after bulk can return 0 until the refresh
    # interval elapses, which made the read-back misleadingly report 0 docs).
    print("\n=== SO-SIDE (native so-case store) ===")
    _es("POST", host, port, auth, "so-case/_refresh")
    q = {"query": {"term": {"so_audit_doc_id": case_id}}, "size": 20,
         "sort": [{"@timestamp": "asc"}]}
    res = _es("POST", host, port, auth, "so-case/_search", q)
    hits = res.get("hits", {}).get("hits", [])
    print(f"so-case docs for {case_id}: {len(hits)}")
    for h in hits:
        s = h["_source"]
        kind = s.get("so_kind", "?")
        if kind == "case":
            print("  CREATE:", s.get("so_case", {}).get("title", "")[:60])
        else:
            print("  ", kind, "|", (s.get("so_comment") or {}).get("description", "")[:90])

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
