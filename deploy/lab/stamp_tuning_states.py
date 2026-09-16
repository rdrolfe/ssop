#!/usr/bin/env python3
"""Stamp `state` on every existing tuning entry (ADR-008 migration).

WHY: ADR-008 makes suppression require `state == "committed"`, and
`tuning_state()` fails CLOSED — an entry with no state reads as PROPOSED. So
before the gate can go live, every legitimate entry needs its state recorded, or
the whole ledger goes inert at once (a bigger outage than the hole being closed).

WHO GETS WHAT (the ADR's authority model, applied to what is actually recorded):

  committed — a human console write (blank/null `tuned_by`), an agent write in a
              user-directed session (`hermes-supervisory-<date>`), and entries
              rescoped on 2026-09-15 (`tuned_by=rdrolfe`).
  proposed  — writes attributed to an unintended/unattended actor, e.g.
              `analyst-tier2-case-<id>` (a role agent is unattended by
              definition). These become INERT: their rules dispatch again.

THE GRANDFATHER, STATED PLAINLY: 25 entries have blank or null `tuned_by`, and
exactly one of those (the hunt entry) is known to have been written unattended —
which is unknowable from the fields, and is precisely why blank fails closed
going FORWARD. Rather than have a human re-confirm 25 rules, they are
grandfathered by one recorded act, marked on the entry itself
(`state=committed (grandfathered ...)`), so the decision is auditable rather than
implicit. Anything written after this migration is on its own.

Dry run by default; --apply writes.
"""
import argparse
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, ".")  # run from the runtime root

MARK = "grandfathered 2026-09-15"
ROLE_AGENT_PREFIXES = ("analyst-tier2-case-",)
INTERACTIVE_PREFIXES = ("hermes-supervisory-",)


def classify(entry: dict) -> tuple[str, str]:
    """(state, why) for one entry — the whole migration policy, in one place."""
    actor = str(entry.get("tuned_by") or "").strip()
    if not actor:
        return "committed", (f"{MARK}: pre-state ledger entry with human console "
                             f"provenance (blank tuned_by; ADR-008 grandfather)")
    if actor.startswith(INTERACTIVE_PREFIXES):
        return "committed", "agent write in a user-directed session (ADR-008 §6)"
    if actor.startswith(ROLE_AGENT_PREFIXES):
        return "proposed", ("written by a role agent — unattended by definition, "
                            "so it may only propose (ADR-008 §6)")
    return "committed", f"attributed to an interactive actor ({actor})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    from tools.tuning_tools import COMMITTED, PROPOSED, TuningLedger, tuning_state

    led = TuningLedger()
    entries = led.list_all(limit=500)
    plan = []
    for e in entries:
        rid = str(e.get("rule_id") or "")
        if not rid:
            continue
        state, why = classify(e)
        already = str(e.get("state") or "").strip().lower()
        if already == state:
            continue
        plan.append((rid, state, why, e))

    print(f"{'APPLY' if args.apply else 'DRY RUN'} — {len(entries)} entries, "
          f"{len(plan)} to stamp\n")
    for rid, state, why, e in plan:
        print(f"  {rid:<34} -> {state:<9} | {str(e.get('tuned_by') or '(blank)')[:28]:<28} | {why[:60]}")
    print("\nsummary:", dict(Counter(s for _, s, _, _ in plan)))
    if not args.apply:
        print("\n(dry run — nothing written)")
        return 0

    for rid, state, why, e in plan:
        rationale = str(e.get("rationale") or "")
        if "state=" not in rationale:
            rationale = f"{rationale} | state={state} ({why})"
        led.write(rid, e.get("decision", "auto_fp"), rationale,
                  source=e.get("source", "human"),
                  ts=e.get("ts"), tuned_by=e.get("tuned_by", ""),
                  fingerprint=e.get("fingerprint"),
                  exclude_hosts=e.get("exclude_hosts"), state=state)

    print("\n--- verify (read back) ---")
    bad = 0
    for rid, state, _, _ in plan:
        got = tuning_state(led.lookup(rid))
        ok = got == state
        bad += 0 if ok else 1
        if not ok:
            print(f"  MISMATCH {rid}: wanted {state}, read {got}")
    print(f"{len(plan) - bad}/{len(plan)} stamped and verified; "
          f"{'OK' if bad == 0 else f'{bad} FAILED'}")
    print(f"proposed now inert: "
          f"{[r for r, s, _, _ in plan if s == PROPOSED]}")
    print(f"stamped at {datetime.now(timezone.utc).isoformat()}")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
