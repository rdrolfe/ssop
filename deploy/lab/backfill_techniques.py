#!/usr/bin/env python3
"""Backfill ATT&CK technique IDs onto OPEN cases minted before the
technique-mapping feature (investigator stage tags, c873be4).

Method (append-only, transparent):
- For each OPEN case without case["techniques"], extract the entity pair
  (srcip/dstip from source, or ip/domain observables), re-run the
  investigator, and take the tagged kill_chain (e.g. 'C2: DNS
  queries/tunneling [T1071.004, T1572]').
- Persist: case["techniques"] = extracted IDs + an appended timeline event
  (role=case-spine, type=technique_backfill) carrying the tagged chain, so
  the advisory renders real technique IDs and the change is auditable.
- Dual-write (Qdrant + receipt) like every other case mutation.

Cases with no IP/domain entity (host-only sysmon) are skipped honestly —
the investigator can't correlate an agent name, and inventing techniques
is not allowed.

Usage: python3 deploy/lab/backfill_techniques.py [--dry-run]
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")

DRY_RUN = "--dry-run" in sys.argv


def _extract_tids(stages: list[str]) -> list[str]:
    """Pull MITRE IDs out of tagged stage labels via the advisory parser."""
    from tools.advisory_gen import _stage_techniques
    out: list[str] = []
    seen: set[str] = set()
    for s in stages:
        for tid in _stage_techniques(str(s)):
            if tid not in seen:
                seen.add(tid)
                out.append(tid)
    return out


def _entity_args(case: dict) -> dict:
    """Map a case's source/observables to investigator kwargs."""
    src = case.get("source", {}) or {}
    args: dict = {}
    if src.get("srcip"):
        args["srcip"] = str(src["srcip"])
    if src.get("dstip"):
        args["dstip"] = str(src["dstip"])
    # Observables may carry ip/domain the source block lacks.
    for o in case.get("observables", []) or []:
        t, v = o.get("type"), str(o.get("value", ""))
        if t == "ip" and not args.get("srcip") and v:
            args["srcip"] = v
        elif t == "domain" and not args.get("domain") and v:
            args["domain"] = v
    return args


def main() -> int:
    from tools.case_tools import CASE_COLLECTION, CaseStore
    from tools.investigator import Investigator

    cs = CaseStore()
    mem = cs._get_memory()
    inv = Investigator()

    open_cases = []
    for r in mem.search_memory(CASE_COLLECTION, "case-", limit=2000,
                               scroll_limit=10000):
        p = cs._parse_content(r.get("content", ""))
        if not p or p.get("status") != "open":
            continue
        open_cases.append(p)

    skip_no_entity = skip_tagged = updated = 0
    for case in open_cases:
        if case.get("techniques"):
            skip_tagged += 1
            continue
        args = _entity_args(case)
        if not (args.get("srcip") or args.get("dstip") or args.get("domain")):
            skip_no_entity += 1
            continue
        res = inv.investigate(**args)
        stages = res.get("kill_chain", [])
        tids = _extract_tids(stages)
        if not tids:
            skip_no_entity += 1  # no correlated, tagged stages
            continue
        case["techniques"] = tids
        case.setdefault("timeline", []).append({
            "role": "case-spine", "type": "technique_backfill",
            "ts": datetime.now(timezone.utc).isoformat(),
            "detail": {"techniques": tids, "kill_chain": stages,
                       "reason": "backfill: technique mapping landed post-mint"},
        })
        case["updated_ts"] = case["timeline"][-1]["ts"]
        if not DRY_RUN:
            cs._write_both(case, event="technique_backfill", role="case-spine")
        updated += 1
        print(f"  {case['case_id']}: {', '.join(tids)}", flush=True)

    print(f"\nopen={len(open_cases)} updated={updated} "
          f"already_tagged={skip_tagged} no_entity/no_correlation={skip_no_entity}")
    print("DRY RUN — no writes" if DRY_RUN else "WROTE to Qdrant + receipt spine")
    return 0


if __name__ == "__main__":
    sys.exit(main())
