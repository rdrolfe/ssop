#!/usr/bin/env python3
"""Repair the router cursor after the 19h wedge backlog.

The router was wedged (deadlock) and resumed from a stale cursor last_ts
(Aug 22), then chewed a ~56k-alert backlog 50 per run. The 5000-cap
seen_ids evicts old alert IDs as new ones are added, so the same old
alerts get re-dispatched (the apparmor ticket flood).

Fix: fast-forward the cursor past the backlog — set last_ts to "now",
clear seen_ids and bursts so only NEW alerts are processed going forward.
Does NOT touch tickets/cases (the operator decides what to do with the
flood). Idempotent.

Usage: python3 repair_router_cursor.py
"""
import json
import sys
from datetime import datetime, timezone

from tools.indexer_client import IndexerTransport

STATE = "router_state.json"


def main() -> int:
    t = IndexerTransport()
    # Resolve the newest alert timestamp in the index — that's where the
    # cursor should resume so the backlog is skipped, not re-dispatched.
    body = {"size": 1, "sort": [{"timestamp": "desc"}], "_source": ["timestamp"]}
    r = t.search(body)
    hits = r.get("hits", {}).get("hits", [])
    newest = hits[0]["_source"].get("timestamp") if hits else None
    if not newest:
        print("could not resolve newest alert timestamp")
        return 1

    cur = json.load(open(STATE))
    old_ts = cur.get("last_ts")
    cur["last_ts"] = newest
    cur["seen_ids"] = []
    cur["bursts"] = {}
    with open(STATE, "w") as f:
        json.dump(cur, f, indent=2)
    print(f"cursor advanced {old_ts} -> {newest}")
    print("seen_ids cleared, bursts cleared — only NEW alerts will dispatch")
    return 0


if __name__ == "__main__":
    sys.exit(main())
