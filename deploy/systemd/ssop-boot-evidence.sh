#!/bin/bash
# ssop-boot-evidence.sh — record whether the previous shutdown was clean.
# Runs at boot. If the graceful-shutdown marker exists, the prior shutdown was
# clean (or first boot ever). If it's absent, the box stopped uncleanly (crash,
# OOM kill, power loss) — exactly the class of event we could not explain when
# infra-ops vanished mid-session. Every boot appends one line to the evidence
# log so the next unexplained stop has a trail.
set -u
# Resolve the shared state dir EXACTLY as config.STATE_DIR does: the pinned env
# var, then the tree's .env, then the tree default. The writer (this unit) and the
# reader (boot-evidence) MUST agree — a mismatch reports UNCLEAN on every boot
# forever, which is a control that trains you to ignore it. $HOME is NOT a valid
# answer here: this unit runs as rdrolfe while boot-evidence runs as ssop-agent,
# whose home IS this tree.
RUNTIME="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="${SSOP_STATE_DIR:-}"
if [ -z "$STATE_DIR" ] && [ -f "$RUNTIME/.env" ]; then
  STATE_DIR="$(sed -n 's/^SSOP_STATE_DIR=//p' "$RUNTIME/.env" | tail -1)"
fi
STATE_DIR="${STATE_DIR:-$RUNTIME/.ssop/state}"
LOG="$STATE_DIR/boot-evidence.log"
MARKER="$STATE_DIR/graceful-shutdown"

mkdir -p "$STATE_DIR"

BOOT_TS=$(date -Is 2>/dev/null || date -u +%FT%TZ)
UNAME=$(uname -r 2>/dev/null || echo "?")

if [ -f "$MARKER" ]; then
  CLEAN="CLEAN"
  REASON="graceful-shutdown marker present (previous shutdown was clean)"
  rm -f "$MARKER"   # consumed; next boot re-checks
else
  CLEAN="UNCLEAN"
  REASON="no graceful-shutdown marker — previous stop was NOT clean (crash/power-loss/OOM?)"
fi

echo "$BOOT_TS | $CLEAN | kernel=$UNAME | $REASON" >> "$LOG"

# Compact the log to the last 200 lines so it can't grow unbounded.
tail -200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"

echo "boot-evidence: $CLEAN ($BOOT_TS)"
