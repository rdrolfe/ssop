#!/usr/bin/env python3
"""Guard: no `.ssop` state path may be resolved from $HOME alone.

WHY THIS EXISTS (ADR-008 plane split). The unattended units run as `ssop-agent`,
whose passwd home IS the runtime tree, so a tilde-derived `.ssop` path silently
names TWO DIFFERENT DIRECTORIES depending on which plane is asking. Nothing
errors — both directories exist and both "work" — so the failure is invisible
until someone notices the data is stale:

  * `drill.py` wrote its receipt under one home and `daily_digest.py` read
    another: the digest's drill line went quietly stale.
  * `ssop-graceful-shutdown.service` (rdrolfe) wrote the marker to one place
    while `ssop-boot-evidence.service` (ssop-agent) looked in the other, which
    would have reported UNCLEAN on every boot forever — a control that inverts
    into a permanent false alarm, and a sensor that trains you to ignore it.

A runtime test cannot catch this class, because at runtime both paths are valid.
Only the SOURCE SHAPE can be asserted: every `.ssop` path must consult an
`SSOP_` override (SSOP_STATE_DIR for state/receipts, SSOP_CA_BUNDLE,
SSOP_AUDIT_KEY_DIR, ...), so both planes name the same place.

Rule: any occurrence must have an `SSOP_` override within a few lines — same
statement is typical, but the override may sit in a helper above the literal.

Non-vacuous by construction: it also asserts it FOUND the guarded occurrences,
so a refactor that deletes the state paths fails loudly here.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

#: a HOME-derived .ssop path — the shape that must not stand alone
BAD = re.compile(r'Path\.home\(\)\s*/\s*"\.ssop"|\$HOME/\.ssop/')
#: ...unless an SSOP_ override is consulted nearby (same statement, or a helper
#: a few lines above). Ten lines, because the override may sit at the top of the
#: function that the literal falls back inside.
GUARD = re.compile(r"SSOP_[A-Z_]+")
GUARD_WINDOW = 10

SKIP_DIRS = {"__pycache__", ".git", "agent-env", ".venv", "node_modules"}


def sources() -> list[Path]:
    out: list[Path] = []
    for base in ("deploy", "agents"):
        root = REPO / base
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if p.is_dir() or any(part in SKIP_DIRS for part in p.parts):
                continue
            if p.suffix in (".py", ".sh", ".service", ".yaml", ".yml"):
                out.append(p)
    return out


def main() -> int:
    fails = 0
    guarded = 0
    unguarded: list[str] = []

    for p in sources():
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if not BAD.search(line):
                continue
            window = lines[max(0, i - GUARD_WINDOW):i + 1]
            if any(GUARD.search(w) for w in window):
                guarded += 1
            else:
                unguarded.append(
                    f"{p.relative_to(REPO)}:{i + 1}: {line.strip()[:100]}")

    print(f"scanned {len(sources())} sources in deploy/ + agents/")
    print(f"[{'OK  ' if guarded >= 8 else 'FAIL'}] found {guarded} guarded "
          f".ssop path(s) with an SSOP_ override (>=8 expected)")
    if guarded < 8:
        fails += 1

    if unguarded:
        print(f"[FAIL] {len(unguarded)} state path(s) still resolved from $HOME:")
        for u in unguarded:
            print(f"       {u}")
        fails += 1
    else:
        print("[OK  ] no .ssop state path is derived from $HOME")

    print("\nSTATE PATHS HOME-INDEPENDENT" if fails == 0 else f"\n{fails} STATE-PATH FAILURES")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())