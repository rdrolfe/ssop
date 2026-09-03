#!/usr/bin/env python3
"""Backlog purge: close provably-dead open cases.

The open-case audit (2026-09-02) showed 347 open; 175 are "other" cases
(no hunt_id / no rule_id / no verify_seed in source) — replay-era and
early-drill leftovers that were minted, escalated, and never closed or
adjudicated. 269 are 7-30d old; 51 have empty timelines; 116 never
reached supervisory.

Close rule (conservative — keeps anything a human touched or that's
fresh): an "other" case closes iff
    age > 7 days AND (empty timeline OR no supervisory event)

Hunt-attach chains (hunt_id), verify seeds, and rule-keyed cases are
untouched. Apparmor 147 are healthy recurring attaches — preserved.

Usage: python3 deploy/lab/purge_backlog.py [--dry-run]
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")

DRY_RUN = "--dry-run" in sys.argv
AGE_DAYS = 7


def _is_other(case: dict) -> bool:
    src = case.get("source") or {}
    return not (src.get("hunt_id") or src.get("verify_seed") or src.get("rule_id"))


def _age_days(case: dict) -> float | None:
    try:
        ts = case.get("ts") or case.get("updated_ts") or ""
        return (datetime.now(timezone.utc).timestamp()
                - datetime.fromisoformat(ts).timestamp()) / 86400
    except (ValueError, TypeError):
        return None


def _has_supervisory(case: dict) -> bool:
    return any(e.get("role") == "supervisory" for e in (case.get("timeline") or []))


def main() -> int:
    from tools.case_tools import CASE_COLLECTION, CaseStore

    cs = CaseStore()
    mem = cs._get_memory()
    open_cases = []
    for r in mem.search_memory(CASE_COLLECTION, "case-", limit=2000,
                               scroll_limit=10000):
        p = cs._parse_content(r.get("content", ""))
        if p and p.get("status") == "open":
            open_cases.append(p)

    closers: list[dict] = []
    kept: list[str] = []
    for c in open_cases:
        if not _is_other(c):
            kept.append("not-other")
            continue
        age = _age_days(c)
        if age is None or age <= AGE_DAYS:
            kept.append("fresh")
            continue
        if (c.get("timeline") or []) and _has_supervisory(c):
            kept.append("human-touched")
            continue
        closers.append(c)

    print(f"open={len(open_cases)} closers={len(closers)} kept={len(kept)}")
    from collections import Counter
    print("kept breakdown:", dict(Counter(kept).most_common()))
    if DRY_RUN:
        print("DRY RUN — no writes")
        return 0

    n = 0
    for c in closers:
        cs.close_case(c["case_id"], reason="backlog purge: stale unattended "
                      "open case (no hunt/rule source, >7d, no human decision)")
        n += 1
        print(f"  closed {c['case_id']} | {(c.get('title') or '')[:45]}")
    print(f"\nclosed={n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
