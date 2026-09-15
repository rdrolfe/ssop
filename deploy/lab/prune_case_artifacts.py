#!/usr/bin/env python3
"""Retire TEST-ARTIFACT cases from the working store (issue #28 spine hygiene).

What this is for: the spine accumulated test artifacts — dedupe seeds minted by
the verify matrix, synthetic drill leftovers, ad-hoc probe cases. They are not
incidents, and they dilute the metrics a human reads (the `unattested` count,
`/reports` denominators, the console). Storage is NOT the reason: the whole case
store is ~3 MB, and these artifacts are a few hundred KB of it.

What it deliberately does NOT touch: real THREAT/INTEL/INFRA cases, however old,
however undecided. An unadjudicated alert is WORK — deleting it destroys the
record that the alert happened. Decide it (the INFRA disposition tooling exists
for that class) and it can then be retired WITH its rationale on record.

How it retires: a signed `case_archived` tombstone (who/when/why) + the point is
deleted + the payload is dumped to `audit/cases_archive.jsonl`. NOT a receipt
rewrite — the spine is hash-chained, so removing records from the middle would
break chain verification, and `reconcile(heal=True)` re-hydrates anything whose
receipts still exist (a naive purge is silently undone within minutes).

DRY RUN BY DEFAULT, from the same function as the apply, so the prediction IS
the outcome (asserted below).

Usage (from the runtime root, e.g. ~/agent-runtime):
  deploy/lab/prune_case_artifacts.py             # dry run: what would go
  deploy/lab/prune_case_artifacts.py --apply     # retire them
  deploy/lab/prune_case_artifacts.py --case-id case-XXXXXXXX --apply
"""
import argparse
import logging
import sys

sys.path.insert(0, ".")
from tools.case_tools import CaseStore  # noqa: E402

logging.getLogger("httpx").setLevel(logging.WARNING)

ACTIONS = ("would_archive", "archived", "already", "completed",
           "delete_failed", "refused_decided", "missing")

REASON = "test artifact: not an incident record (verify/drill/probe case)"


def _show(label: str, r: dict) -> None:
    print(f"— {label}: candidates={r['candidates']}")
    for k in ACTIONS:
        n = len(r.get(k) or [])
        if n or k in ("would_archive", "archived"):
            print(f"    {k:16s} {n:5d}")
    for t in (r.get("titles") or [])[:12]:
        print(f"      {t}")
    if len(r.get("titles") or []) > 12:
        print(f"      … and {len(r['titles']) - 12} more")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="retire the artifacts (default is a dry run)")
    ap.add_argument("--case-id", action="append", default=None,
                    metavar="case-XXXXXXXX",
                    help="retire ONLY this case (repeatable)")
    a = ap.parse_args()

    cs = CaseStore()
    before = cs.reconcile(heal=False)

    dry = cs.archive_backlog(dry_run=True, reason=REASON, actor="operator",
                             case_ids=a.case_id)
    _show("DRY RUN", dry)

    if not dry["candidates"]:
        print("\nnothing to retire.")
        return 0
    if not a.apply:
        print(f"\nnothing written. {len(dry['would_archive'])} case(s) would be "
              f"retired; re-run with --apply.")
        return 0

    applied = cs.archive_backlog(dry_run=False, reason=REASON, actor="operator",
                                 case_ids=a.case_id)
    _show("APPLIED", applied)

    predicted, actual = sorted(dry["would_archive"]), sorted(applied["archived"])
    if predicted != actual:
        print(f"\nPREDICTION MISMATCH — dry run and apply disagree.\n"
              f"  predicted: {predicted}\n  actual:    {actual}")
        return 3
    print(f"\nprediction == application ({len(actual)} case(s)) ✔")
    if applied["delete_failed"]:
        print(f"WARNING: {len(applied['delete_failed'])} point delete(s) failed — "
              f"re-run to complete them (the tombstones are written).")

    # Idempotency: nothing left to retire means the first run was complete.
    again = cs.archive_backlog(dry_run=True, reason=REASON, actor="operator",
                               case_ids=a.case_id)
    print(f"re-run: would_archive={len(again['would_archive'])} "
          f"already={len(again['already'])}")
    if again["would_archive"]:
        print("NOT IDEMPOTENT — a re-run still finds candidates.")
        return 4

    after = cs.reconcile(heal=False)
    print("\nreconcile:")
    print(f"    before: qdrant={before['qdrant_count']} receipt={before['receipt_count']} "
          f"consistent={before['consistent']}")
    print(f"    after : qdrant={after['qdrant_count']} receipt={after['receipt_count']} "
          f"consistent={after['consistent']}")
    print(f"    archived={after['archived_count']} "
          f"lingering={len(after['archived_lingering'])} "
          f"tampered={after['tampered']} drifted={len(after['drifted'])}")
    print("\nboth counts DROP by the number retired: an archived case is excluded "
          "from the live set, while its signed record stays in the chain "
          "(so the spine still holds the record of the removal).")
    return 0


if __name__ == "__main__":
    sys.exit(main())