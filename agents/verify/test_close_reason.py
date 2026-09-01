#!/usr/bin/env python3
"""Non-vacuity test for the close_case reason requirement.

The writeup audit found 44/47 closed cases had an empty reason — a dead end
for post-incident review. close_case now raises ValueError on a blank
reason. The reason check runs FIRST (before any store access), so this test
is pure — no Qdrant/network needed:

  - blank reason ("" or whitespace)   -> ValueError, even for a nonexistent
    case id (proves the check precedes the store lookup)
  - a non-blank reason on a nonexistent case -> returns None (not-found path
    still works, proving the enforcement didn't break normal operation)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.case_tools import CaseStore  # noqa: E402


def main() -> int:
    cs = CaseStore()
    fails = 0

    # 1. Blank reason -> ValueError (proves the check runs before the store
    #    lookup, because even a nonexistent id raises).
    for blank in ("", "   ", "\t\n"):
        try:
            cs.close_case("case-nonexistent-000", reason=blank)
            print(f"blank reason {blank!r}: NO EXCEPTION (FAIL)")
            fails += 1
        except ValueError as e:
            print(f"blank reason {blank!r}: ValueError ok")
        except Exception as e:  # noqa: BLE001 — any other exception is wrong
            print(f"blank reason {blank!r}: wrong exception {type(e).__name__} (FAIL)")
            fails += 1

    # 2. Omitted reason entirely -> ValueError (default arg is "").
    try:
        cs.close_case("case-nonexistent-000")
        print("omitted reason: NO EXCEPTION (FAIL)")
        fails += 1
    except ValueError:
        print("omitted reason: ValueError ok")

    # 3. Non-blank reason on a nonexistent case -> None (not-found path
    #    preserved; enforcement didn't break normal operation).
    r = cs.close_case("case-nonexistent-000", reason="test reason")
    print(f"valid reason, missing case: returned {r} (expected None)")
    if r is not None:
        fails += 1

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
