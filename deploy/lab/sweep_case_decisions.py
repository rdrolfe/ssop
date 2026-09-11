#!/usr/bin/env python3
"""Replay adjudicated TICKET decisions into the case spine (backlog repair).

THE GAP THIS REPAIRS: `adjudicate()` recorded the human verdict in the ticket
file + the tuning ledger but never on the CASE, so on the live spine 1,708 of
2,078 adjudicated tickets pointed at cases still sitting `state=new` — the
advisory/report rendered them "under review" and the queue's coverage number
lied. The code fix (supervisory_tools.sync_case_decision) closes the hole for
every FUTURE adjudication; this script replays the history through the SAME
path, so the repair and the going-forward behavior can never diverge.

What it does per ticket (status=adjudicated, carrying a decision + case_id):
  - case already carries a decision  -> skipped (idempotent, never re-decides)
  - case is closed/archived          -> reported unreachable, never forced
    (the lifecycle machine owns the transition; a closed case is terminal
    until explicitly reopened)
  - case missing / ticket has no case_id -> no-op, counted honestly
  - otherwise                        -> decision written to the spine
    (attach=False: the report/advisory SO attach is skipped so a thousand
    historical cases don't flood the SOC surface)

SAFETY: dry-run is the DEFAULT here (unlike the other backfill scripts in this
directory, which write by default) because the blast radius is ~1000 live case
mutations, not a handful. Pass --apply to write.

Usage:
  python3 deploy/lab/sweep_case_decisions.py            # report only
  python3 deploy/lab/sweep_case_decisions.py --apply    # write
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, ".")

APPLY = "--apply" in sys.argv
RECEIPT = Path.home() / ".ssop" / "state" / "case-decision-sweep.json"


def main() -> int:
    from tools.supervisory_tools import SupervisoryClient

    sup = SupervisoryClient()
    tickets = sup.list_tickets(status="adjudicated")
    print(f"adjudicated tickets: {len(tickets)} "
          f"({'APPLY' if APPLY else 'DRY RUN'})\n", flush=True)

    outcomes: Counter[str] = Counter()
    written: list[dict] = []
    samples: dict[str, list] = {}

    for t in tickets:
        cid = sup.ticket_case_id(t)
        if not cid or not t.get("decision"):
            outcomes["skipped:no_case_id_or_decision"] += 1
            continue
        res = sup.sync_case_decision(
            t, t.get("decision"), t.get("rationale", ""),
            dry_run=not APPLY, attach=False)
        outcome = str(res.get("outcome", "?"))
        outcomes[outcome] += 1
        if APPLY and outcome == "written":
            written.append({"case_id": cid, "ticket_id": t.get("ticket_id"),
                            "decision": res.get("decision")})
        if len(samples.setdefault(outcome, [])) < 3:
            samples[outcome].append(
                {"ticket": t.get("ticket_id"), "case": cid,
                 "ticket_decision": t.get("decision"),
                 "case_decision": res.get("decision")})

    print("outcomes:")
    for k, v in outcomes.most_common():
        print(f"  {v:5d}  {k}")
    print("\nsamples:")
    for k, rows in samples.items():
        for r in rows:
            print(f"  [{k}] ticket {r['ticket']} ({r['ticket_decision']}) "
                  f"-> case {r['case']} ({r.get('case_decision') or '-'})")

    if APPLY:
        RECEIPT.parent.mkdir(parents=True, exist_ok=True)
        RECEIPT.write_text(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "tickets_considered": len(tickets),
            "outcomes": dict(outcomes),
            "written": written,
        }, indent=1))
        print(f"\nreceipt: {RECEIPT}")
        print(f"WROTE {outcomes.get('written', 0)} case decisions to the spine")
    else:
        print("\nDRY RUN — no writes. Re-run with --apply to land them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
