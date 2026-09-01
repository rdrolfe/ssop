#!/usr/bin/env python3
"""Repair ssop-events ticket state: delete stale/duplicate ticket docs and
re-ship the authoritative local queue.

The phantom-open-tickets bug left the indexer with duplicate open docs (the
legacy auto-ID ships plus the new pinned-ID ships). This script:
  1. Deletes EVERY ssop.source=tickets doc whose _id does NOT start with
     'ticket-' (the legacy auto-ID docs that adjudication never updated).
  2. Then re-ships the authoritative local queue (3 open + all closed) with
     pinned _ids, so the indexer mirrors the local ticket dir exactly.

Usage: python3 deploy/lab/repair_ticket_index.py
"""
import base64
import json
import ssl
import sys
import urllib.request

sys.path.insert(0, ".")
from config import settings
from tools.ship_ticket import ship_ticket_doc
from tools.supervisory_tools import SupervisoryClient


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _indexer_url():
    url = settings.indexer_url or f"https://{settings.indexer_host}:{settings.indexer_port}"
    if settings.indexer_host and settings.indexer_host != "localhost":
        from urllib.parse import urlparse
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        url = f"{scheme}://{settings.indexer_host}:{parsed.port or settings.indexer_port}"
    return url.rstrip("/")


def main() -> int:
    url = _indexer_url()
    auth = "Basic " + base64.b64encode(
        f"{settings.indexer_user}:{settings.indexer_password}".encode()).decode()
    ctx = _ctx()

    # 1. Find ALL ticket docs, delete any with a legacy (non pinned) id.
    #    We must not delete the pinned-ID docs — those reflect adjudicated
    #    state and re-shipping them is what keeps the count honest.
    q = {"size": 1000, "query": {"term": {"ssop.source": "tickets"}},
         "_source": ["ticket_id", "status"]}
    req = urllib.request.Request(
        f"{url}/ssop-events/_search", data=json.dumps(q).encode(), method="POST",
        headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        res = json.loads(r.read().decode())
    hits = res.get("hits", {}).get("hits", [])
    legacy = [h["_id"] for h in hits if not h["_id"].startswith("ticket-")]
    print(f"ticket docs: {len(hits)} | legacy (to delete): {len(legacy)} | pinned: {len(hits) - len(legacy)}")

    if legacy:
        # bulk delete legacy docs by id
        body = "".join(
            json.dumps({"delete": {"_index": "ssop-events", "_id": i}}) + "\n"
            for i in legacy)
        req = urllib.request.Request(
            f"{url}/_bulk", data=body.encode(), method="POST",
            headers={"Authorization": auth, "Content-Type": "application/x-ndjson"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            out = json.loads(r.read().decode())
        errs = sum(1 for it in out.get("items", [])
                   if (it.get("delete") or {}).get("error"))
        print(f"deleted {len(legacy) - errs} legacy docs ({errs} errors)")

    # 2. Re-ship the authoritative local queue (open + closed) with pinned ids.
    sup = SupervisoryClient()
    tickets = sup.list_tickets()  # all statuses
    shipped = 0
    for t in tickets:
        if ship_ticket_doc(t):
            shipped += 1
    print(f"reshipped {shipped}/{len(tickets)} local tickets")

    # 3. Verify final open count in the indexer.
    q2 = {"size": 0, "query": {"bool": {"filter": [
        {"term": {"ssop.source": "tickets"}},
        {"term": {"status.keyword": "open"}}]}}}
    req = urllib.request.Request(
        f"{url}/ssop-events/_search", data=json.dumps(q2).encode(), method="POST",
        headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        res2 = json.loads(r.read().decode())
    open_docs = res2.get("hits", {}).get("total", {}).get("value", 0)
    local_open = len([t for t in tickets if t.get("status") == "open"])
    print(f"indexer open docs: {open_docs} | local open: {local_open}")
    return 0 if open_docs == local_open else 1


if __name__ == "__main__":
    sys.exit(main())
