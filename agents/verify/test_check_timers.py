#!/usr/bin/env python3
"""Unit tests for the timer-liveness check's pure logic (no systemd).

Covers the two pieces that decide a timer is stale:
  - _cadence_minutes: derives cadence from OnCalendar (minute + daily forms,
    comment lines, unknown forms)
  - _parse_ts: parses systemd's `Mon 2026-08-31 22:10:26 EDT` wall-clock
    timestamps into UTC

The systemd-facing side (check_timers on the runtime host) is proven
non-vacuous live: stopping ssop-router.timer makes the check FAIL, and
restoring it makes it pass. This test locks the parsing logic that feeds
that decision so a regression there is caught in-process.
"""
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verify.check_timers import _cadence_minutes, _parse_ts  # noqa: E402


def _write_unit(content: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".timer", delete=False) as f:
        f.write(content)
        return f.name


def main() -> int:
    fails = 0

    # 1. Minute cadence: *-*-* *:0/5:00 -> 5
    p = _write_unit("[Timer]\nOnCalendar=*-*-* *:0/5:00\n")
    if _cadence_minutes(p) != 5:
        print("FAIL: 5-min cadence"); fails += 1
    # 2. Minute cadence: *:0/15:00 -> 15 (hunt)
    p = _write_unit("[Timer]\nOnCalendar=*-*-* *:0/15:00\n")
    if _cadence_minutes(p) != 15:
        print("FAIL: 15-min cadence"); fails += 1
    # 3. Daily cadence: *-*-* 06:00:00 -> 1440
    p = _write_unit("[Timer]\nOnCalendar=*-*-* 06:00:00\n")
    if _cadence_minutes(p) != 1440:
        print(f"FAIL: daily cadence ({_cadence_minutes(p)})"); fails += 1
    # 4. Comment lines are ignored (hunt.timer has a comment above OnCalendar)
    p = _write_unit("# comment\n[Timer]\nOnCalendar=*-*-* *:0/15:00\n")
    if _cadence_minutes(p) != 15:
        print("FAIL: comment-ignored cadence"); fails += 1
    # 5. Unknown/absent form -> None (no false cadence)
    p = _write_unit("[Timer]\nOnCalendar=Mon *-*-* 03:00:00\n")
    if _cadence_minutes(p) is not None:
        print("FAIL: unknown cadence should be None"); fails += 1

    # 6. systemd timestamp parse: local EDT -> UTC
    # "Mon 2026-08-31 22:10:26 EDT" with host at UTC-4 = 2026-09-01 02:10:26Z
    ts = _parse_ts("Mon 2026-08-31 22:10:26 EDT")
    if ts is None:
        print("FAIL: ts parse None"); fails += 1
    else:
        # Compare against now-minus-offset logic by reconstructing:
        offset = datetime.now().astimezone().utcoffset() or timedelta(0)
        expect_utc = datetime(2026, 8, 31, 22, 10, 26, tzinfo=timezone.utc) - offset
        if abs((ts - expect_utc).total_seconds()) > 60:
            print(f"FAIL: ts mismatch {ts} vs {expect_utc}"); fails += 1
    # 7. "-" and empty -> None
    if _parse_ts("-") is not None or _parse_ts("") is not None:
        print("FAIL: dash/empty should be None"); fails += 1
    # 8. Malformed -> None
    if _parse_ts("garbage") is not None:
        print("FAIL: garbage should be None"); fails += 1

    print("timer parsing: OK" if fails == 0 else f"timer parsing: {fails} FAILURE(S)")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
