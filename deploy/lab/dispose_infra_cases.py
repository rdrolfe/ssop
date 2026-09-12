#!/usr/bin/env python3
"""Terminal disposition for router-minted INFRA cases that nobody decided.

THE GAP THIS CLOSES: `dispatch_infra` mints a case per fleet-health event
(assignee=responder) and recommends a playbook — then nothing ever decides it.
Those cases sit `state=new` forever: no decision on the spine, so the advisory
renders "under review" for an event the platform already handled, and the
coverage number counts them as open work.

THE AUTHORITY IT USES (no new policy is invented here): by operator policy
2026-09-09 the ROUTER is the approving authority for INFRA cases at tier0/1
and is explicitly barred from tier2 — that rule is already encoded in the
ontology (docs/ontology/ssop.ttl role comment), in `case_decision`'s router
branch, and in the advisory's decision reader. This script applies exactly
that rule to the backlog:

  - case carries a tier0/tier1 recommended playbook -> decision `approve`
    (the playbook is verify/known-safe; the router may authorize it)
  - no playbook, or any tier2 playbook              -> decision `operational`
    (routine fleet-health event; no response required — never an approval,
    because a tier2 action is supervisory/human-only by construction)
  - ANY case whose category is not `infra`          -> refused, untouched
    (security cases are not this script's business at any tier)

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

# Categories this script is allowed to touch. Anything else is refused — a
# security/threat case is decided by the supervisory path, never here.
INFRA_CATEGORIES = {"infra"}


def _case_category(case: dict) -> str:
    """The case's category from source (mint) or the dispatch/verdict event."""
    src = case.get("source") or {}
    cat = str(src.get("category") or "").lower()
    if cat:
        return cat
    for ev in case.get("timeline", []) or []:
        if not isinstance(ev, dict):
            continue
        d = ev.get("detail") or {}
        if isinstance(d, dict) and d.get("category"):
            return str(d["category"]).lower()
    return ""


def _recommended_playbook(case: dict) -> str:
    """The playbook the router recommended at dispatch, if any."""
    src = case.get("source") or {}
    if src.get("recommended_playbook"):
        return str(src["recommended_playbook"])
    for ev in case.get("timeline", []) or []:
        if not isinstance(ev, dict):
            continue
        d = ev.get("detail") or {}
        if isinstance(d, dict) and d.get("recommended_playbook"):
            return str(d["recommended_playbook"])
    return ""


def main() -> int:
    from tools.case_tools import CASE_COLLECTION, CaseStore, case_decision, can_decide
    from tools.playbook_loader import load_playbooks

    cs = CaseStore()
    mem = cs._get_memory()
    try:
        playbooks = load_playbooks()
    except Exception:  # noqa: BLE001 — a library read failure must not decide cases
        playbooks = {}

    candidates: list[tuple[dict, str, str]] = []   # (case, decision, rationale)
    counts: Counter[str] = Counter()

    for r in mem.search_memory(CASE_COLLECTION, "case-", limit=2000, scroll_limit=10000):
        case = CaseStore._parse_content(r.get("content", ""))
        if not case or not isinstance(case, dict):
            continue
        if case_decision(case)[0]:          # already decided — not our business
            continue
        title = str(case.get("title") or "")
        if "[ROUTER]" not in title:
            continue
        cat = _case_category(case)
        if cat not in INFRA_CATEGORIES:
            counts[f"refused:category={cat or 'unknown'}"] += 1
            continue
        state = str(case.get("state") or "new")
        if not can_decide(state):
            counts[f"unreachable:{state}"] += 1
            continue
        pb_name = _recommended_playbook(case)
        pb = playbooks.get(pb_name) if pb_name else None
        tier = str(getattr(pb, "approval", "") or "")
        if pb is not None and tier in ("tier0", "tier1"):
            decision = "approve"
            rationale = (f"router adjudication (infra): tier{tier[-1]} playbook "
                         f"{pb_name} authorized under operator policy 2026-09-09 "
                         f"— router approves INFRA tier0/1 only")
        else:
            decision = "operational"
            why = f"playbook {pb_name} is tier{tier[-1]}" if tier == "tier2" else \
                  (f"playbook {pb_name} unknown/tier-less" if pb_name else "no playbook recommended")
            rationale = (f"router disposition (infra): routine fleet-health event, "
                         f"no response required ({why})")
        candidates.append((case, decision, rationale))
        # Mode-neutral label: the header already says DRY RUN or APPLY, and a
        # receipt reading "would_decide" after an apply is a lying artifact.
        counts[f"decide:{decision}"] += 1

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
