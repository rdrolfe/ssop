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
  # Undo the PERMISSION change too. The forward path chgrp'd the tree to the
  # automation group and relaxed modes; leaving that in place after a rollback
  # means the boundary is half-applied in the one state nobody is watching.
  chgrp -R rdrolfe "$RUNTIME" 2>/dev/null || say "  (chgrp back to rdrolfe failed — check the group exists)"
  chmod -R go-w "$RUNTIME" 2>/dev/null || say "  (go-w sweep failed)"
  chmod 700 "$RUNTIME/certs/ca" 2>/dev/null
  chmod 600 "$RUNTIME/certs/ca/ca.key" 2>/dev/null
  chmod 700 /home/rdrolfe/.ssop-keys 2>/dev/null
  say "  permissions reverted (group-write removed tree-wide, ca.key 600)"
  sudo -n systemctl daemon-reload && say "  daemon-reload done"
  say "rollback complete (timers keep running as rdrolfe)"
  exit 0
fi

# ---------------------------------------------------------------- plan
say "PLAN"
say "  backup unit files            -> $BACKUP"
say "  chgrp -R $AGENT_GROUP          -> $RUNTIME (key dir excluded: it is 0700 rdrolfe)"
say "  chmod -R g+rX                -> $RUNTIME   (READ only — NOT g+rwX)"
say "  chmod g+rwx                  -> $RUNTIME/{tickets,hunts,logs,playbooks,audit,.ssop}"
say "  g-w removed from             -> code, config, *.html, certs, keys, *.timer"
say "  600 rdrolfe-only             -> certs/ca/ca.key, ~/.ssop-keys/tuning-commit.key"
say "  User=/Group=                 -> $AGENT_USER on: $UNITS"
say "  keep on rdrolfe              -> ssop-adjudicate-api (the human console), ssop-qdrant-tunnel"
say ""
[ "$APPLY" = 1 ] || { say "(dry run — nothing changed; re-run with --apply)"; exit 0; }

# ---------------------------------------------------------------- backup
mkdir -p "$BACKUP"
nbak=0
for u in $UNITS; do
  if [ -f "$RUNTIME/$u.service" ]; then
    cp -p "$RUNTIME/$u.service" "$BACKUP/$u.service" && nbak=$((nbak+1)) \
      || say "  WARN: could not back up $u.service"
  else
    say "  (no $u.service in $RUNTIME — it may live only in /etc/systemd/system)"
  fi
done
say "backed up $nbak unit file(s) to $BACKUP"
# Rollback is the only undo. If nothing was captured, say so and refuse to
# mutate — a migration you cannot reverse should not run half-way.
if [ "$nbak" -eq 0 ] && [ "$APPLY" = 1 ]; then
  say "FATAL: no unit files backed up; refusing to apply. Fix the unit path first."
  exit 5
fi

# ---------------------------------------------------------------- permissions
# The commit boundary from ADR-008 is only real if the unattended plane cannot
# reach rdrolfe. Two mistakes defeat it, and this script made BOTH:
#
#   1. `chmod -R g+rwX` over the whole tree made every .py, .yaml, .html, .crt
#      and .key GROUP-WRITABLE by ssop-agent. The adjudicate API runs as
#      rdrolfe and imports that same code, so rewriting tools/case_tools.py
#      from the automation plane executes attacker code as rdrolfe on the next
#      console click — straight past the private key it cannot read.
#   2. The certs/ tree is inside $RUNTIME, so the same chmod handed ssop-agent
#      certs/ca/ca.key (the CA private key) and every service key. With the CA
#      key it can mint a certificate for anything and the whole plane trusts it.
#
# So: group gets READ everywhere, and WRITE only on the directories the
# services genuinely produce into. Trust material and code are read-only to the
# group; the CA private key is rdrolfe-only because nothing needs it at runtime.
chgrp -R "$AGENT_GROUP" "$RUNTIME" 2>/dev/null || say "WARN: chgrp failed"
# g+rX, NOT g+rwX. Files get group-read, directories get group-read+traverse.
chmod -R g+rX "$RUNTIME" 2>/dev/null || say "WARN: chmod failed"
# Then open up write ONLY on the data directories.
for d in tickets hunts logs playbooks audit .ssop; do
  [ -d "$RUNTIME/$d" ] && chmod g+rwx "$RUNTIME/$d" 2>/dev/null
done
# Group-write is still needed for the ticket/hunt producers, which create files.
chmod g+w "$RUNTIME"/*.json 2>/dev/null

# Trust material and code must NOT be group-writable, whatever the tree sweep
# did. Set these explicitly so the invariant does not depend on the -R above.
find "$RUNTIME" -path "$RUNTIME/agent-env" -prune -o -type f \
     \( -name '*.py' -o -name '*.sh' -o -name '*.service' -o -name '*.yaml' \
        -o -name '*.html' -o -name '*.timer' -o -name '*.crt' -o -name '*.pem' \
        -o -name '*.key*' \) -not -path '*/__pycache__/*' -exec chmod g-w {} + 2>/dev/null
chmod 640 "$RUNTIME/.env" 2>/dev/null
# The CA private key signs every service cert; nothing in the unattended plane
# needs it at runtime, so it stays rdrolfe-only.
chmod 700 "$RUNTIME/certs/ca" 2>/dev/null
chmod 600 "$RUNTIME/certs/ca/ca.key" 2>/dev/null

# The commit key is the whole point of this migration — verify, do not assume.
KEYDIR=/home/rdrolfe/.ssop-keys
if [ ! -d "$KEYDIR" ]; then
  say "FATAL: $KEYDIR missing — this migration exists to fence that key."
  exit 4
fi
chmod 700 "$KEYDIR" && chmod 600 "$KEYDIR/tuning-commit.key" \
  || say "FATAL: could not lock the commit key (check ownership)"
chmod 644 "$KEYDIR/tuning-commit.key.pub" 2>/dev/null
# Fail closed if the key is still group/other-readable — that is the boundary.
keymode="$(stat -c %a "$KEYDIR/tuning-commit.key")"
case "$keymode" in
  600|400) say "commit key locked: $keymode" ;;
  *) say "FATAL: commit key is $keymode, expected 600 — the boundary is NOT in place"
      exit 4 ;;
esac
say "runtime tree group-readable; key dir 0700 rdrolfe-only"

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
  frag="$(systemctl show "$u.service" -p FragmentPath --value)"
  # The script edits $RUNTIME/*.service, but systemd loads FragmentPath — which
  # on this box is /etc/systemd/system/. If those ever diverge, the edits below
  # are inert while `systemctl show` still reports the OLD (correct-looking)
  # value, so this check would pass having changed nothing. Assert the file we
  # edited is the file systemd actually loads.
  if [ -n "$frag" ] && [ "$frag" != "$RUNTIME/$u.service" ]; then
    say "  FAIL $u -> systemd loads $frag, not the $RUNTIME copy this script edits"
    bad=$((bad+1))
    continue
  fi
  if [ "$eu" = "$AGENT_USER" ]; then
    say "  OK   $u -> $eu:$eg"
  else
    say "  FAIL $u -> $eu:$eg (wanted $AGENT_USER)"
    bad=$((bad+1))
  fi
done

# Verify the boundary this migration exists to create, not just the user id.
# A group-writable module or a group-readable CA key means the plane can reach
# rdrolfe even though `User=` is correct.
say ""
say "BOUNDARY CHECK (the point of ADR-008)"
for probe in tools/case_tools.py agent.py .env transport.yaml certs/ca/ca-bundle.crt; do
  m="$(stat -c %a "$RUNTIME/$probe" 2>/dev/null || echo '?')"
  g="$(stat -c %G "$RUNTIME/$probe" 2>/dev/null || echo '?')"
  case "$m" in
    *[2367]) say "  FAIL $probe is $m $g — GROUP-WRITABLE by the automation plane"
             bad=$((bad+1)) ;;
    *)       say "  OK   $probe is $m $g" ;;
  esac
done
camo="$RUNTIME/certs/ca/ca.key"
if [ -r "$camo" ]; then
  g="$(stat -c %A "$camo")"
  case "$g" in
    -*------*) say "  OK   ca.key $m rdrolfe-only" ;;
    *) say "  FAIL ca.key is group/other-accessible — the whole trust anchor is exposed"
         bad=$((bad+1)) ;;
  esac
fi
for u in ssop-adjudicate-api ssop-qdrant-tunnel; do
  say "  human-plane (unchanged): $u -> $(systemctl show "$u.service" -p User --value)"
done

say ""
say "NEXT: restart the timers so they pick up the new user, then run the probe:"
say "  sudo -n systemctl restart ssop-supervisory.timer ssop-router.timer ssop-analyst.timer ssop-hunt.timer"
say "  sudo -n systemctl start ssop-supervisory.service"
exit "$bad"
