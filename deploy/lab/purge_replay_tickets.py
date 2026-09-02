#!/usr/bin/env python3
"""Purge open tickets minted by the BOTS anchor replay (they were closed on
the spine but their escalated tickets stayed open — queue contamination).
Matches by title prefix + the replay's rule set. Usage: python3 deploy/lab/purge_replay_tickets.py"""
import sys

sys.path.insert(0, ".")
from tools.supervisory_tools import SupervisoryClient

MATCH = (
    "[ROUTER-ANALYST] ET MALWARE Cerber ransomware proc",
    "[ROUTER-ANALYST] ET MALWARE webshell/backdoor uplo",
    "[ROUTER-ANALYST] ET MALWARE Possible DNS Tunneling",
)


def main() -> int:
    sup = SupervisoryClient()
    tickets = sup.list_tickets(status="open")
    purged = 0
    for t in tickets:
        title = t.get("title") or ""
        if any(title.startswith(m) for m in MATCH):
            sup.mark_adjudicated(t, "auto_fp", "BOTS replay contamination purge")
            purged += 1
    remaining = len(sup.list_tickets(status="open"))
    print(f"purged {purged}; remaining open: {remaining}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
