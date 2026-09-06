#!/bin/bash
# SSOP config-revert wrapper — restores a file from the protected backup store.
# The ONLY thing sudoers allows for config revert is this script. It enforces:
#   1. the source is a regular file directly in /opt/ssop-backups/ (no traversal)
#   2. each backup artifact maps to ONE canonical destination (fixed allowlist
#      below) — caller-selected destination paths are rejected
#   3. neither source nor destination may be a symlink
# Usage: ssop-revert.sh <backup-file> [caller-path]
#   caller-path (sent by agents/tools/responder_steps.py) is accepted for
#   compatibility but must equal the canonical destination for the artifact.
set -euo pipefail
BACKUP_DIR="/opt/ssop-backups"
SRC="${1:-}"
CALLER_TARGET="${2:-}"

# Canonical destination per backup artifact. One line per artifact — a
# destination outside this map is NOT revertible via this wrapper.
declare -A CANONICAL=(
  ["sshd_config"]="/etc/ssh/sshd_config"
  ["sshd_config.ssop-baseline"]="/etc/ssh/sshd_config"
  ["hosts"]="/etc/hosts"
  ["crontab"]="/etc/crontab"
  ["sysctl.conf"]="/etc/sysctl.conf"
  ["ssop-containment-network"]="/etc/sudoers.d/ssop-containment-network"
  ["ssop-containment-revert"]="/etc/sudoers.d/ssop-containment-revert"
)

# Safety: source must be a bare file directly in the backup store (no
# traversal, no subdirectories)
case "$SRC" in
  "$BACKUP_DIR"/*) ;;
  *) echo "refused: source must be in $BACKUP_DIR" >&2; exit 1 ;;
esac
ARTIFACT="${SRC#"$BACKUP_DIR"/}"
case "$ARTIFACT" in
  */*|*".."*) echo "refused: traversal or subdirectory in source" >&2; exit 1 ;;
esac
case "$CALLER_TARGET" in *".."*) echo "refused: traversal in target" >&2; exit 1;; esac

CANON_TARGET="${CANONICAL[$ARTIFACT]:-}"
if [ -z "$CANON_TARGET" ]; then
  echo "refused: no canonical destination for artifact '$ARTIFACT'" >&2
  exit 1
fi
# Reject caller-selected paths: only the canonical destination is allowed.
if [ -n "$CALLER_TARGET" ] && [ "$CALLER_TARGET" != "$CANON_TARGET" ]; then
  echo "refused: caller-selected destination '$CALLER_TARGET' != canonical '$CANON_TARGET'" >&2
  exit 1
fi
TARGET="$CANON_TARGET"

if [ ! -f "$SRC" ] || [ -L "$SRC" ]; then
  echo "refused: backup not found or symlink: $SRC" >&2
  exit 1
fi
if [ -L "$TARGET" ] || [ ! -f "$TARGET" ]; then
  echo "refused: destination missing or symlink: $TARGET" >&2
  exit 1
fi
cp "$SRC" "$TARGET"
echo "reverted $TARGET from $SRC"
