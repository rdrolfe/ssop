#!/bin/bash
# SSOP config-revert wrapper — restores a file from the protected backup store.
# The ONLY thing sudoers allows for config revert is this script; it enforces
# that the source lives in /opt/ssop-backups/ (no arbitrary cp).
# Usage: ssop-revert.sh <backup-file> <target-path>
set -euo pipefail
BACKUP_DIR="/opt/ssop-backups"
SRC="$1"
TARGET="$2"

# Safety: source must be inside the backup store (no path traversal)
case "$SRC" in
  "$BACKUP_DIR"/*) ;;
  *) echo "refused: source must be in $BACKUP_DIR" >&2; exit 1 ;;
esac
# Reject traversal in either arg
case "$SRC" in *".."*) echo "refused: traversal in source" >&2; exit 1;; esac
case "$TARGET" in *".."*) echo "refused: traversal in target" >&2; exit 1;; esac

if [ ! -f "$SRC" ]; then
  echo "refused: backup not found: $SRC" >&2
  exit 1
fi
cp "$SRC" "$TARGET"
echo "reverted $TARGET from $SRC"
