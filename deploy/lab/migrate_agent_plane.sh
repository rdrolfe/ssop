#!/usr/bin/env bash
# Migrate the unattended SSOP plane onto a dedicated user (ADR-008 stage 2, (i)).
#
# WHY: the commit boundary is only real if the unattended processes CANNOT read
# the private commit key. They currently run as rdrolfe, the same account that
# owns the key — so any key they were asked to respect, they could read.
#
# WHAT THIS DOES (idempotent; dry-run by default):
#   1. preflight: the dedicated user/group must exist (creating them needs
#      privilege this account does not have without a password — see the
#      PREREQUISITE block it prints).
#   2. back up every unit file it touches.
#   3. group-share the runtime tree with the automation group (the key directory
#      is NOT in that tree and stays 0700/0600 rdrolfe-only).
#   4. set User=/Group= on the unattended units, leaving the human console
#      (ssop-adjudicate-api) and the ssh tunnel on rdrolfe.
#   5. daemon-reload, restart the timers, verify each unit's effective user.
#
# Rollback: re-run with --rollback, or restore the backed-up unit files from the
# backup directory it printed and 'systemctl daemon-reload'.
set -uo pipefail

RUNTIME="/home/rdrolfe/agent-runtime"
AGENT_USER="ssop-agent"
AGENT_GROUP="ssop"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$RUNTIME/.deploy-bak/agent-plane-$STAMP"
APPLY=0
ROLLBACK=0

# Units that must move to the automation plane.
UNITS="ssop-supervisory ssop-router ssop-analyst ssop-hunt ssop-atomic ssop-intel ssop-drill ssop-selfheal ssop-boot-evidence"
# Deliberately NOT moved:
#   ssop-adjudicate-api  — the HUMAN console: a click must be able to commit, so
#                          it keeps the private key (and therefore stays rdrolfe).
#   ssop-qdrant-tunnel   — an ssh tunnel using rdrolfe's key material.

for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --rollback) ROLLBACK=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------- preflight
PREREQ="sudo groupadd -f $AGENT_GROUP
sudo useradd --system --gid $AGENT_GROUP --no-create-home --home-dir $RUNTIME --shell /usr/sbin/nologin $AGENT_USER
sudo usermod -aG $AGENT_GROUP rdrolfe"

if ! getent group "$AGENT_GROUP" >/dev/null; then
  say "PREREQUISITE: group '$AGENT_GROUP' does not exist."
  say "Run these three commands as a human on this box (one paste), then re-run:"
  say ""
  say "$PREREQ"
  say ""
  exit 3
fi
if ! getent passwd "$AGENT_USER" >/dev/null; then
  say "PREREQUISITE: user '$AGENT_USER' does not exist."
  say "Run these three commands as a human on this box (one paste), then re-run:"
  say ""
  say "$PREREQ"
  say ""
  exit 3
fi

say "preflight OK: $(getent passwd "$AGENT_USER")"
say "              $(getent group "$AGENT_GROUP")"
say ""

# ---------------------------------------------------------------- rollback
if [ "$ROLLBACK" = 1 ]; then
  latest="$(ls -1d "$RUNTIME"/.deploy-bak/agent-plane-* 2>/dev/null | tail -1)"
  [ -n "$latest" ] || { say "no backup directory found"; exit 1; }
  say "rolling back unit files from $latest and restoring rdrolfe ownership"
  for u in $UNITS; do
    [ -f "$latest/$u.service" ] && cp -p "$latest/$u.service" "$RUNTIME/$u.service" \
      && say "  restored $u.service"
  done
  chgrp -R rdrolfe "$RUNTIME" 2>/dev/null || say "  (chgrp back to rdrolfe failed — harmless)"
  sudo -n systemctl daemon-reload && say "  daemon-reload done"
  say "rollback complete (timers keep running as rdrolfe)"
  exit 0
fi

# ---------------------------------------------------------------- plan
say "PLAN"
say "  backup unit files            -> $BACKUP"
say "  chgrp -R $AGENT_GROUP          -> $RUNTIME (key dir excluded: it is 0700 rdrolfe)"
say "  chmod -R g+rwX               -> $RUNTIME"
say "  User=/Group=                 -> $AGENT_USER on: $UNITS"
say "  keep on rdrolfe              -> ssop-adjudicate-api (the human console), ssop-qdrant-tunnel"
say ""
[ "$APPLY" = 1 ] || { say "(dry run — nothing changed; re-run with --apply)"; exit 0; }

# ---------------------------------------------------------------- backup
mkdir -p "$BACKUP"
for u in $UNITS; do
  [ -f "$RUNTIME/$u.service" ] && cp -p "$RUNTIME/$u.service" "$BACKUP/$u.service"
done
say "backed up $(ls -1 "$BACKUP" | wc -l) unit file(s) to $BACKUP"

# ---------------------------------------------------------------- permissions
# chgrp/chmod need no privilege here: rdrolfe owns the tree and is a member of
# the automation group. The key directory lives OUTSIDE the tree on purpose.
chgrp -R "$AGENT_GROUP" "$RUNTIME" 2>/dev/null || say "WARN: chgrp failed"
chmod -R g+rwX "$RUNTIME" 2>/dev/null || say "WARN: chmod failed"
# Keep the private key unreadable by the automation group, explicitly.
chmod 700 /home/rdrolfe/.ssop-keys 2>/dev/null || true
chmod 600 /home/rdrolfe/.ssop-keys/tuning-commit.key 2>/dev/null || true
chmod 644 /home/rdrolfe/.ssop-keys/tuning-commit.key.pub 2>/dev/null || true
say "runtime tree group-shared; key dir left 0700 rdrolfe-only"

# ---------------------------------------------------------------- unit edits
/home/rdrolfe/agent-runtime/agent-env/bin/python3 - "$RUNTIME" "$AGENT_USER" "$AGENT_GROUP" $UNITS <<'PY'
import re
import sys
from pathlib import Path

runtime, user, group = sys.argv[1], sys.argv[2], sys.argv[3]
units = sys.argv[4:]
for name in units:
    p = Path(runtime) / f"{name}.service"
    if not p.is_file():
        print(f"  MISSING {p}")
        continue
    text = p.read_text()
    if re.search(r"^User=", text, re.M):
        text = re.sub(r"^User=.*$", f"User={user}", text, flags=re.M)
    else:
        text = re.sub(r"^\[Service\]$", f"[Service]\nUser={user}", text, flags=re.M)
    if re.search(r"^Group=", text, re.M):
        text = re.sub(r"^Group=.*$", f"Group={group}", text, flags=re.M)
    else:
        text = re.sub(rf"^User={user}$", f"User={user}\nGroup={group}", text, flags=re.M)
    p.write_text(text)
    print(f"  {name}: User={user} Group={group}")
PY

# ---------------------------------------------------------------- activate
sudo -n systemctl daemon-reload || say "WARN: daemon-reload failed"
say "daemon-reload done"

# ---------------------------------------------------------------- verify
say ""
say "VERIFY (effective user per unit, as systemd sees it)"
bad=0
for u in $UNITS; do
  eu="$(systemctl show "$u.service" -p User --value)"
  eg="$(systemctl show "$u.service" -p Group --value)"
  if [ "$eu" = "$AGENT_USER" ]; then
    say "  OK   $u -> $eu:$eg"
  else
    say "  FAIL $u -> $eu:$eg (wanted $AGENT_USER)"
    bad=$((bad+1))
  fi
done
for u in ssop-adjudicate-api ssop-qdrant-tunnel; do
  say "  human-plane (unchanged): $u -> $(systemctl show "$u.service" -p User --value)"
done

say ""
say "NEXT: restart the timers so they pick up the new user, then run the probe:"
say "  sudo -n systemctl restart ssop-supervisory.timer ssop-router.timer ssop-analyst.timer ssop-hunt.timer"
say "  sudo -n systemctl start ssop-supervisory.service"
exit "$bad"
