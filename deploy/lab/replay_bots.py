#!/usr/bin/env python3
"""Replay the BOTSv1 Sysmon dataset through the REAL spine dispatch path
and count how many cases get created.

Option-1 semantics (raw volume): every event is lifted into the alert
shape the ontology expects (rule.id/level/groups/description, agent.name),
then dispatched through router.dispatch() exactly as the live router
would. Burst dedup is applied (same rule|agent within the burst window
counts as a repeat, not a new case). The spine is the source of truth —
cases land in Qdrant; nothing is published to SO here.

Run: python3 deploy/lab/replay_bots.py [--limit N] [--index IDX] [--sample]
"""
import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, ".")
import router
from config import settings
from tools.indexer_client import IndexerTransport

# BOTS Sysmon EventCode -> ontology-ish alert shape. Levels deliberately
# modest (raw Sysmon is telemetry, not tuned detections) so escalation is
# driven by the ontology's real rules, not a synthetic level inflation.
_EVENTCODE_RULE = {
    "1":  {"id": "bots-sysmon-1",  "level": 5, "groups": ["sysmon", "process_creation"], "desc": "Sysmon process created"},
    "2":  {"id": "bots-sysmon-2",  "level": 7, "groups": ["sysmon", "integrity"], "desc": "Sysmon file creation time changed"},
    "3":  {"id": "bots-sysmon-3",  "level": 6, "groups": ["sysmon", "network_connection"], "desc": "Sysmon network connection"},
    "5":  {"id": "bots-sysmon-5",  "level": 3, "groups": ["sysmon", "process_terminated"], "desc": "Sysmon process terminated"},
    "6":  {"id": "bots-sysmon-6",  "level": 6, "groups": ["sysmon", "driver_loaded"], "desc": "Sysmon driver loaded"},
    "7":  {"id": "bots-sysmon-7",  "level": 4, "groups": ["sysmon", "image_loaded"], "desc": "Sysmon image loaded"},
    "11": {"id": "bots-sysmon-11", "level": 5, "groups": ["sysmon", "file_create"], "desc": "Sysmon file created"},
    "13": {"id": "bots-sysmon-13", "level": 5, "groups": ["sysmon", "registry"], "desc": "Sysmon registry value set"},
    "22": {"id": "bots-sysmon-22", "level": 6, "groups": ["sysmon", "dns_query"], "desc": "Sysmon DNS query"},
}
_DEFAULT_RULE = {"id": "bots-sysmon-0", "level": 3, "groups": ["sysmon"], "desc": "Sysmon event"}


def to_alert(doc: dict) -> dict | None:
    """Lift a raw BOTS Sysmon doc into the alert shape the spine consumes."""
    code = str(doc.get("EventCode") or "").strip()
    r = _EVENTCODE_RULE.get(code, _DEFAULT_RULE)
    return {
        "id": "bots-" + str(doc.get("RecordID") or uuid.uuid4().hex[:10]),
        "timestamp": doc.get("@timestamp") or doc.get("timestamp") or "",
        "rule": {
            "id": r["id"],
            "level": r["level"],
            "groups": list(r["groups"]),
            "description": doc.get("EventDescription") or r["desc"],
        },
        "agent": {"name": doc.get("Computer") or doc.get("SourceHostname") or "bots-host"},
        "data": {
            "srcip": doc.get("SourceIp") or doc.get("SourceHostname"),
            "dstip": doc.get("DestinationIp"),
            "dstport": doc.get("DestinationPort"),
            "image": doc.get("Image"),
            "hostname": doc.get("Computer"),
            "eventcode": code,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="max events (0 = all)")
    ap.add_argument("--index", default="bots-sysmon-op-poc")
    ap.add_argument("--sample", type=int, default=0, help="sample N evenly across the index")
    args = ap.parse_args()

    t = IndexerTransport()
    counts = {
        "total": 0, "mapped": 0, "unmapped": 0,
        "cases_created": 0, "attached": 0, "burst_deduped": 0,
        "no_dispatch": 0, "notes": 0, "errors": 0,
    }
    case_ids: set[str] = set()
    by_category: dict[str, int] = {}
    by_eventcode: dict[str, int] = {}
    # burst tracking mirroring router.Cursor.burst_count (time-windowed:
    # same rule|agent within burst_window_min resets after the window).
    bursts: dict[str, dict] = {}
    burst_window = settings.burst_window_min
    t0 = time.time()

    def _burst(key: str, ts: str) -> int:
        """Return count including this occurrence (1 = dispatch)."""
        try:
            now = datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
        except Exception:  # noqa: BLE001
            now = datetime.now(timezone.utc)
        entry = bursts.get(key)
        if entry:
            last = datetime.fromisoformat(entry["last_ts"].replace("Z", "+00:00"))
            if (now - last) <= timedelta(minutes=burst_window):
                entry["count"] += 1
                entry["last_ts"] = ts
                return entry["count"]
        bursts[key] = {"count": 1, "last_ts": ts, "first_ts": ts}
        if len(bursts) > 2000:
            for k in list(bursts)[:500]:
                bursts.pop(k, None)
        return 1

    # scroll the index in batches
    after = None
    fetched = 0
    while True:
        body: dict = {"size": 500, "query": {"match_all": {}},
                      "sort": [{"@timestamp": "asc"}]}
        if args.limit and fetched + 500 > args.limit:
            body["size"] = max(1, args.limit - fetched)
        if after:
            body["search_after"] = after
        r = t.search(body, index=args.index)
        hits = r.get("hits", {}).get("hits", [])
        if not hits:
            break
        fetched += len(hits)
        last_sort = hits[-1].get("sort")
        if last_sort:
            after = last_sort

        for h in hits:
            counts["total"] += 1
            doc = h.get("_source", {})
            alert = to_alert(doc)
            if not alert:
                counts["unmapped"] += 1
                continue
            counts["mapped"] += 1
            code = str(doc.get("EventCode") or "?")
            by_eventcode[code] = by_eventcode.get(code, 0) + 1

            # burst dedup mirroring the router: same rule|agent within window
            bkey = f"{alert['rule']['id']}|{alert['agent']['name']}"
            burst = _burst(bkey, alert["timestamp"])
            if burst > 1:
                counts["burst_deduped"] += 1
                continue

            try:
                res = router.dispatch(alert, burst_count=burst)
            except Exception as e:  # noqa: BLE001
                counts["errors"] += 1
                continue
            disp = res.get("dispatch") or {}
            action = disp.get("action", "")
            cat = res.get("category", "?")
            by_category[cat] = by_category.get(cat, 0) + 1
            cid = res.get("case_id") or disp.get("case_id")
            if action.startswith("dispatched_to"):
                counts["cases_created"] += 1
                if cid:
                    case_ids.add(cid)
            elif action == "attached" or disp.get("attached") or res.get("attached"):
                counts["attached"] += 1
                if cid:
                    case_ids.add(cid)
            elif action in ("noted_no_escalate", "note"):
                counts["notes"] += 1
            else:
                counts["no_dispatch"] += 1

        if args.limit and fetched >= args.limit:
            break
        if args.sample and fetched >= args.sample:
            break

    dt = time.time() - t0
    counts["unique_cases"] = len(case_ids)
    print(json.dumps({
        "index": args.index,
        "elapsed_s": round(dt, 1),
        "events_per_s": round(fetched / dt, 1) if dt else None,
        **counts,
        "by_category": by_category,
        "by_eventcode": by_eventcode,
    }, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
