#!/usr/bin/env python3
"""IRIS -> spine state sync (Phase 0 of the IRIS front-end pivot).

Pulls HUMAN-authored IRIS activity (notes + non-SSOP timeline events) for
every IRIS case that maps to a spine case (case_soc_id), and appends
anything newer than the spine case's `last_iris_sync_ts` onto the spine
timeline as `iris_note` / `iris_event` entries attributed to the IRIS
author. This is the reverse direction of publish_case_iris.py (spine ->
IRIS): decisions and comments made BY HUMANS IN IRIS become part of the
spine's authoritative audit trail.

Mirror-loop guard: events tagged `ssop` and notes by service accounts
(IRIS user ids 2-6) are the publisher's own writes — skipped, so the spine
timeline never duplicates itself.

CRITICAL: resolves spine cases by EXACT payload.case_id match, never via
CaseStore.get_case() — get_case substring-matches content and returns the
first scroll hit, which can resolve to a SIBLING case whose rationale
embeds the target id (proven live 2026-09-05: sync wrote a note onto
case-07e9fe3ea7 when the target was case-93b2fe4368).

Idempotent: tracks last_iris_sync_ts per case; re-runs append nothing.

Usage (on infra-ops): python3 deploy/lab/sync_iris_to_spine.py [--dry-run]
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")
sys.path.insert(0, "deploy/lab")

from deploy.lab.iris_client import IrisClient  # noqa: E402
from tools.case_tools import CASE_COLLECTION, CaseStore  # noqa: E402

DRY = "--dry-run" in sys.argv


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _exact_cases(cs: CaseStore) -> dict[str, dict]:
    """id -> newest-case-dict, resolved by EXACT payload.case_id match."""
    m = cs._get_memory()
    all_points, offset = [], None
    while True:
        recs, nxt = m.client.scroll(
            collection_name=CASE_COLLECTION, limit=1000,
            with_payload=True, with_vectors=False, offset=offset)
        all_points.extend(recs)
        if not nxt:
            break
        offset = nxt
    by_id: dict[str, dict] = {}
    for p in all_points:
        cid = (p.payload or {}).get("case_id")
        if not cid:
            continue
        parsed = cs._parse_content((p.payload or {}).get("content", ""))
        if parsed and parsed.get("case_id") == cid:
            cur = by_id.get(cid)
            if cur is None or (p.payload.get("timestamp") or "") >= (cur.get("_ts") or ""):
                parsed["_ts"] = p.payload.get("timestamp") or ""
                by_id[cid] = parsed
    return by_id


def main() -> int:
    iris = IrisClient(role="supervisory")
    cs = CaseStore()

    iris_cases = {c.get("case_soc_id"): c for c in iris.list_cases()
                  if c.get("case_soc_id")}
    print(f"IRIS cases with spine mapping: {len(iris_cases)}")

    exact = _exact_cases(cs)
    print(f"spine cases resolved exactly: {len(exact)}")

    synced = 0
    for soc_id, icase in sorted(iris_cases.items()):
        case = exact.get(soc_id)
        if not case:
            continue
        last = case.get("last_iris_sync_ts") or ""
        activity = iris.get_human_activity(icase.get("case_id"))
        new_activity = [a for a in activity
                        if (a.get("ts") or "") > last] if last else activity
        if not new_activity:
            continue
        print(f"  {soc_id}: +{len(new_activity)} human items "
              f"({sum(1 for a in new_activity if a['kind']=='note')} notes)")
        if DRY:
            continue
        # Append directly to the exact-resolved case dict + dual-write
        # (mirrors append_event's write path without the fuzzy get_case).
        for a in new_activity:
            etype = "iris_note" if a["kind"] == "note" else "iris_event"
            detail = {
                "title": a.get("title"),
                "content": (a.get("content") or "")[:2000],
                "ts": a.get("ts"),
                "iris_case_id": icase.get("case_id"),
            }
            entry = {
                "ts": _ts(),
                "role": a.get("author") or "iris",
                "type": etype,
                "detail": detail,
            }
            case.setdefault("timeline", []).append(entry)
            case["updated_ts"] = entry["ts"]
            case["last_touched_ts"] = entry["ts"]
        case["last_iris_sync_ts"] = _ts()
        case.pop("_ts", None)
        cs._write_both(case, event="iris_sync", role="iris-sync")
        synced += 1

    print(f"synced {synced} cases" + (" (dry run)" if DRY else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
