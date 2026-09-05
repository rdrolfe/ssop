#!/usr/bin/env python3
"""Operator reset: close EVERYTHING outstanding, then purge the stale case
store for a fresh slate.

User decision (2026-09-02): "auto close everything outstanding and purge
what would be wasteful afterward... Id rather create fresh data." The
1200+ replay/drill-era cases (open + closed) are not going to be reviewed;
they pollute recidivism scans and the console. Wipe them.

Keeps ONLY the two bake-off gate seeds (case-26b166ce32 deny/FP,
case-204a8dc4f9 positive/approve) — the matrix parity gate depends on
them; deleting them would turn the gate RED.

Steps:
  1. Close ALL open cases (dual-write: receipt + Qdrant) with a reset reason.
  2. Delete every case point from Qdrant EXCEPT the protected seeds.
  3. Close any open tickets (defensive — queue is normally 0).
  4. Delete published test cases from the SO store (so-case + so-casehistory)
     EXCEPT the protected seeds, so the SOC list is fresh too.

The append-only receipt spine (audit/cases.jsonl) is preserved — it is the
provenance trail and tiny; purging it would destroy the audit record.

Usage: python3 deploy/lab/reset_case_queue.py [--dry-run]
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")

DRY_RUN = "--dry-run" in sys.argv
PROTECTED = {"case-26b166ce32", "case-204a8dc4f9"}  # bake-off gate seeds


def main() -> int:
    from tools.case_tools import CASE_COLLECTION, CaseStore
    from tools.supervisory_tools import SupervisoryClient

    cs = CaseStore()
    mem = cs._get_memory()
    sc = SupervisoryClient()

    # 1. Load ALL case points from Qdrant.
    all_cases: list[dict] = []
    for r in mem.search_memory(CASE_COLLECTION, "case-", limit=2000,
                               scroll_limit=10000):
        p = cs._parse_content(r.get("content", ""))
        if p:
            all_cases.append(p)
    print(f"spine total: {len(all_cases)} | "
          f"open: {sum(1 for c in all_cases if c.get('status') == 'open')} | "
          f"protected: {sum(1 for c in all_cases if c.get('case_id') in PROTECTED)}")

    # 2. Close all open cases (keyed on machine state, not the stale status
    # field — legacy cases can read status=open while state=closed).
    from tools.case_tools import _normalize_state, CaseStateError
    open_cases = [c for c in all_cases
                  if _normalize_state(c.get("state", "new")) != "closed"]
    print(f"closing {len(open_cases)} open cases...")
    if not DRY_RUN:
        for c in open_cases:
            if c.get("case_id") in PROTECTED:
                continue  # seeds stay as-is (already decided)
            try:
                cs.close_case(c["case_id"], reason="operator reset: fresh slate "
                              "(2026-09-02, user: create fresh data)")
            except CaseStateError as e:
                print(f"  skip (already terminal): {e}")

    # 3. Delete all case points EXCEPT protected from Qdrant.
    to_delete = [c.get("case_id") for c in all_cases
                 if c.get("case_id") not in PROTECTED]
    print(f"purging {len(to_delete)} case points from Qdrant (keeping {len(PROTECTED)} seeds)...")
    if not DRY_RUN and to_delete:
        import uuid as _uuid
        ids = [str(_uuid.uuid5(_uuid.NAMESPACE_URL, cid)) for cid in to_delete]
        mem.client.delete(collection_name=CASE_COLLECTION,
                          points_selector=ids, wait=True)

    # 3b. Archive the receipt spine and rewrite it with ONLY the protected
    # seeds. WITHOUT this, the next reconcile(heal=True) — the analyst timer
    # and supervisory duty both call it — re-hydrates every purged case back
    # into Qdrant from the JSONL "receipt-only" diff, silently undoing the
    # purge (proven live 2026-09-04: reset -> 2 seeds, next supervisory run
    # -> 1213 points). The old spine is preserved as a timestamped archive
    # (provenance kept), the working spine becomes truly fresh.
    if not DRY_RUN:
        import json as _json
        from datetime import datetime as _dt
        spine = cs.cases_file
        if spine.exists() and spine.stat().st_size > 0:
            archive = spine.with_name(
                f"cases.jsonl.reset-{_dt.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.bak")
            with spine.open() as f, archive.open("w") as out:
                for line in f:
                    out.write(line)
                out.flush()
            # Rewrite spine with just the protected seeds' receipts.
            protected_recs: list[str] = []
            with spine.open() as f:
                for line in f:
                    try:
                        rec = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    if rec.get("case_id") in PROTECTED:
                        protected_recs.append(line)
            with spine.open("w") as f:
                f.writelines(protected_recs)
            print(f"receipt spine archived -> {archive.name} "
                  f"(kept {len(protected_recs)} seed receipts)")

    # 4. Close open tickets (defensive).
    open_ts = sc.list_tickets(status="open")
    print(f"open tickets: {len(open_ts)}")
    if not DRY_RUN:
        for t in open_ts:
            sc.mark_adjudicated(t, decision="deny",
                                rationale="operator reset: fresh slate")

    # 5. SO store cleanup: delete published docs for non-protected cases.
    if not DRY_RUN:
        import base64
        import json
        import ssl
        import urllib.request
        import yaml
        from config import settings

        with open("transport.yaml") as f:
            cfg = yaml.safe_load(f)
        b = cfg["backends"]["securityonion"]
        import re
        m = re.match(r"https?://([^:]+)(?::(\d+))?", b["endpoint"])
        host = m.group(1) if m else "192.168.1.76"
        port = int(m.group(2) or 9200) if m else 9200
        auth = "Basic " + base64.b64encode(
            f"{b['user']}:{settings.so_indexer_password}".encode()).decode()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        def es(method, path, body=None):
            req = urllib.request.Request(
                f"https://{host}:{port}/{path}",
                data=json.dumps(body).encode() if body else None,
                method=method, headers={"Authorization": auth,
                                        "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
                return json.loads(r.read().decode())

        # Which spine case ids have been published to SO? Pull distinct
        # so_audit_doc_id values, drop the protected ones, delete the rest.
        r = es("POST", "so-case/_search",
               {"query": {"exists": {"field": "so_audit_doc_id"}}, "size": 1000,
                "_source": ["so_audit_doc_id"]})
        published = {h["_source"].get("so_audit_doc_id") for h in
                     r.get("hits", {}).get("hits", []) if h.get("_source", {}).get("so_audit_doc_id")}
        doomed = published - PROTECTED
        print(f"SO published cases: {len(published)} | deleting {len(doomed)}...")
        for cid in sorted(doomed):
            for idx in ("so-case", "so-casehistory"):
                es("POST", f"{idx}/_delete_by_query",
                   {"query": {"term": {"so_audit_doc_id": cid}}})
            es("POST", "so-case/_refresh")
            print(f"  deleted SO docs for {cid}")

    # Post-state summary (re-scan Qdrant).
    remaining = []
    for r in mem.search_memory(CASE_COLLECTION, "case-", limit=2000,
                               scroll_limit=10000):
        p = cs._parse_content(r.get("content", ""))
        if p:
            remaining.append(p)
    print(f"\npost-reset: Qdrant cases = {len(remaining)} "
          f"({[c['case_id'] for c in remaining]}) | "
          f"open tickets = {len(sc.list_tickets(status='open'))}")
    print("DRY RUN — no writes" if DRY_RUN else "RESET COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
