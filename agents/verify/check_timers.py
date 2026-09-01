"""Timer-liveness gate — no SSOP timer may silently fall on its face.

The reactive spine (router) wedged for 19h on Aug 30-31 while the matrix
stayed green (it tests decision logic, not process liveness). This check
closes that hole: every ssop-*.timer must have fired within its own
cadence × tolerance, or the matrix goes RED.

Cadence is DERIVED from each timer's own OnCalendar (the unit file is the
source of truth — no hardcoded schedule table to drift):
  *-*-* *:0/N:00   -> N minutes
  *-*-* HH:MM:00   -> daily (24h)
Anything else is treated as unknown-cadence: checked only that it fired
recently (default 1h), never false-fails.

A timer that is enabled+active but whose LAST fire is older than
cadence × tolerance is a FAIL. A timer that is not active/enabled is a
FAIL (a stopped router timer is a dead router). A timer that has NEVER
fired but has a NEXT in the future (e.g. a freshly-installed daily drill)
is OK — it's armed. A timer with no LAST and no NEXT is a FAIL.

Tolerance default 2.5 (missed ~1.5 full cycles = stale); override with
SSOP_TIMER_TOLERANCE. Output is exit-0/1 compatible.

Usage: python3 -m verify.check_timers
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

TIMER_GLOB = "ssop-*.timer"
SYSTEMD_DIR = "/etc/systemd/system"

# *-*-* *:0/15:00 -> 15 minutes
_MINUTE_RE = re.compile(r"\*:\d/(\d+):00")
# *-*-* 03:30:00 -> daily (24h)
_DAILY_RE = re.compile(r"^\*-\*-\* \d{2}:\d{2}:00$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cadence_minutes(unit_path: str) -> int | None:
    """Derive the nominal cadence (minutes) from a timer unit's OnCalendar."""
    try:
        text = open(unit_path, encoding="utf-8").read()
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("OnCalendar="):
            continue
        cal = line[len("OnCalendar="):].strip()
        m = _MINUTE_RE.search(cal)  # minute form appears after the *-*-* prefix
        if m:
            return int(m.group(1))
        if _DAILY_RE.match(cal):
            return 24 * 60
    return None


def _parse_ts(s: str) -> datetime | None:
    """Parse a systemd timestamp: `Mon 2026-08-31 22:10:26 EDT`.

    fromisoformat can't handle the weekday prefix + tz abbreviation. Strip
    the weekday, parse the date-time as LOCAL (systemd emits local wall
    clock), and attach the current local UTC offset (timers within our
    liveness window are all < 24h old, so DST drift is a non-issue).
    """
    s = s.strip()
    if not s or s == "-":
        return None
    m = re.match(r"^\S+\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\S+$", s)
    if not m:
        return None
    try:
        local = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    # Local wall clock -> UTC using the CURRENT local offset.
    offset = datetime.now().astimezone().utcoffset()
    if offset is None:
        offset = timedelta(0)
    return local.replace(tzinfo=timezone.utc) - offset


def _timer_last_next(name: str) -> tuple[datetime | None, datetime | None]:
    """Return (last_fire, next_fire) for one timer via systemctl show."""
    out = subprocess.run(
        ["systemctl", "show", name, "-p", "LastTriggerUSec", "-p", "NextElapseUSecRealtime",
         "-p", "ActiveState", "-p", "UnitFileState"],
        capture_output=True, text=True, timeout=15).stdout
    fields: dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip()
    last = _parse_ts(fields.get("LastTriggerUSec", ""))
    nxt = _parse_ts(fields.get("NextElapseUSecRealtime", ""))
    active = fields.get("ActiveState", "") == "active"
    enabled = fields.get("UnitFileState", "") == "enabled"
    return (last, nxt) if (active and enabled) else (None, None)


def check_timers() -> list[dict[str, Any]]:
    """Return FAIL items: {timer, cadence_min, last_age_min, detail}.

    Empty list = all timers healthy.
    """
    problems: list[dict[str, Any]] = []
    # --all is REQUIRED: systemd hides inactive timers by default, so a
    # stopped timer would vanish from the list and the check would go
    # vacuously green (the exact trap we've been fixing). With --all, a
    # stopped-but-enabled timer still appears and is flagged as inactive.
    out = subprocess.run(
        ["systemctl", "list-timers", TIMER_GLOB, "--all", "--no-pager", "--plain"],
        capture_output=True, text=True, timeout=15).stdout
    # Column layout (--plain): NEXT LEFT LAST PASSED UNIT ACTIVATES
    timers: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[-1].endswith(".service"):
            timers.add(parts[-2])
    for name in sorted(timers):
        last, nxt = _timer_last_next(name)
        unit_path = f"{SYSTEMD_DIR}/{name}"
        cad = _cadence_minutes(unit_path)
        if last is None:
            if nxt is not None:
                continue  # armed but never fired (fresh daily timer) — OK
            problems.append({"timer": name, "cadence_min": cad,
                             "detail": "timer not active/enabled or never fired with no NEXT"})
            continue
        assert last is not None  # Pyright narrowing (tuple unpack doesn't narrow)
        age_min = (_now() - last).total_seconds() / 60.0
        tol = float(os.getenv("SSOP_TIMER_TOLERANCE", "2.5"))
        limit = (cad * tol) if cad else 60.0
        if age_min > limit:
            problems.append({"timer": name, "cadence_min": cad,
                             "last_age_min": round(age_min, 1),
                             "detail": f"last fire {age_min:.0f}min ago > {limit:.0f}min "
                                       f"(cadence {cad or '?'}min x {tol})"})
    return problems


def main() -> int:
    probs = check_timers()
    if not probs:
        print("timer liveness: all timers healthy")
        return 0
    print(f"timer liveness: {len(probs)} problem(s)")
    for p in probs:
        print(f"  [stale] {p['timer']} (cadence {p.get('cadence_min') or '?'}min): {p['detail']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
