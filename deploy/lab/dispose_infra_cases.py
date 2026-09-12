#!/usr/bin/env python3
"""Terminal disposition for router-minted INFRA cases that nobody decided.

WHAT THIS IS NOW: the disposition RULE lives in `tools/infra_disposition.py`
and the router applies it at mint time (`dispatch_infra`), so this class should
no longer accumulate. This script is the BACKLOG SWEEP and the audit view for
cases minted before that landed — it delegates to the same derivation, so a dry
run here and a live dispatch can never disagree about what a case's disposition
should be.

THE ORIGINAL GAP (why the shared rule exists): `dispatch_infra` minted a case
per fleet-health event (assignee=responder) and recommended a playbook — then
nothing ever decided it. Those cases sat `state=new` forever: no decision on
the spine, so the advisory rendered "under review" for an event the platform
already handled, and the coverage number counted them as open work.

THE AUTHORITY (no new policy invented here): by operator policy 2026-09-09 the
ROUTER is the approving authority for INFRA cases at tier0/1 and is explicitly
barred from tier2 — encoded in the ontology (docs/ontology/ssop.ttl role
comment), in `case_decision`'s router branch, and in the advisory's decision
reader. See `tools/infra_disposition.py` for the rule.

Safety rails: dry-run is the DEFAULT; `--apply` writes; `--close` additionally
closes the decided cases (off by default — deciding and closing are separate
operator calls). Decisions go through the lifecycle machine via
`CaseStore.decide(..., role="router")`, never a hand-written state field.

Usage:
  python3 deploy/lab/dispose_infra_cases.py                 # report only
  python3 deploy/lab/dispose_infra_cases.py --apply         # record decisions
  python3 deploy/lab/dispose_infra_cases.py --apply --close # + close them
"""
from __future__ import annotations

import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, ".")

APPLY = "--apply" in sys.argv
CLOSE = "--close" in sys.argv
RECEIPT = Path.home() / ".ssop" / "state" / "infra-case-disposition.json"

#: reason-code prefix -> label in the report (the shared derivation's reasons)
_REASON_LABELS = {
    "unreachable": "unreachable",
    "category": "refused:category",
    "playbook_library_unavailable": "deferred:playbook_library_unavailable",
    "not_router_minted": "not_router_minted",
    "already_decided": "already_decided",
}


def _label(reason: str) -> str:
    head, _, tail = reason.partition("=")
    if ":" in head:
        head, _, state = head.partition(":")
        return f"{head}:{state}"
    if head in _REASON_LABELS:
        lbl = _REASON_LABELS[head]
        return f"{lbl}={tail}" if tail else lbl
    return reason


def main() -> int:
    from tools.case_tools import CASE_COLLECTION, CaseStore, case_decision
    from tools.infra_disposition import (
        REASON_ELIGIBLE, infra_disposition,
    )
    from tools.playbook_loader import load_playbooks

    cs = CaseStore()
    mem = cs._get_memory()
    try:
        playbooks = load_playbooks()
    except Exception:  # noqa: BLE001 — an unreadable library DEFERS, never decides
        print("playbook library unreadable — deferring every playbook-backed "
              "case (nothing will be written)")
        playbooks = None

    candidates: list[tuple[dict, str, str]] = []   # (case, decision, rationale)
    counts: Counter[str] = Counter()

    # ONE store scan (never a per-id get_case loop); the sweep reads the case
    # point, whose state fields carry everything the derivation needs.
    for r in mem.search_memory(CASE_COLLECTION, "case-", limit=2000,
                               scroll_limit=10000):
        case = CaseStore._parse_content(r.get("content", ""))
        if not case or not isinstance(case, dict):
            continue
        if case_decision(case)[0]:          # already decided — not our business
            continue
        if "[ROUTER]" not in str(case.get("title") or ""):
            continue                        # not router-minted — never ours
        disp = infra_disposition(case, playbooks)
        if not disp["eligible"]:
            counts[_label(disp["reason"])] += 1
            continue
        candidates.append((case, disp["decision"], disp["rationale"]))
        # Mode-neutral label: the header already says DRY RUN or APPLY, and a
        # receipt reading "would_decide" after an apply is a lying artifact.
        counts[f"decide:{disp['decision']}"] += 1

    print(f"router-minted undecided INFRA cases: {len(candidates)} "
          f"({'APPLY' if APPLY else 'DRY RUN'}{', +close' if CLOSE else ''})\n")
    for k, v in counts.most_common():
        print(f"  {v:5d}  {k}")
    print("\nsample (first 12):")
    for case, decision, rationale in candidates[:12]:
        print(f"  {case['case_id']}  {decision:11s} {rationale[:78]}")
        print(f"      title: {str(case.get('title'))[:80]}")

    written = 0
    if APPLY:
        for case, decision, rationale in candidates:
            cid = case["case_id"]
            try:
                res = cs.decide(cid, decision, rationale, role="router")
            except Exception as e:  # noqa: BLE001 — report honestly, keep going
                print(f"  WRITE FAILED {cid}: {type(e).__name__}: {e}")
                continue
            if res is None:
                print(f"  WRITE SKIPPED {cid}: not found / transition refused")
                continue
            written += 1
            if CLOSE:
                try:
                    cs.close_case(cid, reason=f"infra disposition: {decision} (router, "
                                             f"operator policy 2026-09-09)")
                except Exception as e:  # noqa: BLE001 — a failed close is reported, not hidden
                    print(f"  CLOSE FAILED {cid}: {type(e).__name__}: {e}")
        RECEIPT.parent.mkdir(parents=True, exist_ok=True)
        import json
        RECEIPT.write_text(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "applied": True, "closed": CLOSE, "written": written,
            "outcomes": dict(counts),
            "cases": [{"case_id": c["case_id"], "decision": d} for c, d, _ in candidates],
        }, indent=1))
        print(f"\nreceipt: {RECEIPT}")
        print(f"WROTE {written} router dispositions"
              f"{' and closed them' if CLOSE else ' (cases left open)'}")
    else:
        print("\nDRY RUN — no writes. Re-run with --apply to land them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
