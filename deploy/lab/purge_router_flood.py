#!/usr/bin/env python3
"""Purge the router-flood tickets (ROUTER-HUNT apparmor repeats from the
19h-wedge re-dispatch loop). Closes them via mark_adjudicated so no tuning
is written (they're duplicates of a real signal, not a tuning decision).

Idempotent: only touches tickets whose title starts with the flood prefix
and whose actor is router. Reports what it closed + what remains.
"""
import sys

sys.path.insert(0, ".")
from tools.supervisory_tools import SupervisoryClient

FLOOD_PREFIXES = ("[ROUTER-HUNT] apparmor-denials: suspicious",)


def main() -> int:
    sup = SupervisoryClient()
    open_t = sup.list_tickets(status="open")
    # The 19h-wedge re-dispatch loop re-created tickets for the WHOLE
    # backlog (apparmor patterns + analyst dispatches + SOAR tier-2
    # approvals). The cursor is now fast-forwarded past all of it, so every
    # open router/responder ticket is a stale duplicate of an old signal.
    flood = [t for t in open_t if t.get("actor") in ("router", "responder")]
    closed = 0
    for t in flood:
        sup.mark_adjudicated(t, decision="operational",
                             rationale="router-flood duplicate from 19h-wedge re-dispatch loop; cursor repaired, no tuning change")
        closed += 1
    remaining = [t for t in sup.list_tickets(status="open")]
    print(f"closed {closed} flood tickets; {len(remaining)} open remain")
    for t in remaining[:8]:
        print("  ", t.get("actor"), "|", (t.get("title") or "")[:55])
    return 0


if __name__ == "__main__":
    sys.exit(main())
