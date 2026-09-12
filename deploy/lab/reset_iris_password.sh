#!/usr/bin/env bash
# Reset an IRIS web-login password (run on the telemetry host, .75).
#
# WHY THIS SHAPE
#   This IRIS deployment has no self-service "forgot password" flow (no SMTP
#   configured — `login_routes.py` only handles lockout/MFA, not email reset),
#   and IRIS stores passwords as bcrypt hashes
#   (`bcrypt.generate_password_hash` in app/datamgmt/manage/manage_users_db.py).
#   A reset therefore means writing a fresh bcrypt hash into `user.password`.
#
# THE PASSWORD NEVER LEAVES THE TERMINAL
#   It is read interactively (no echo), never passed as an argument, never
#   written to a file, never exported, and the bcrypt hash is computed inside
#   the app CONTAINER so it matches exactly what IRIS itself would write.
#
# POLICY: IRIS enforces 12+ chars / 1 uppercase / 1 digit on created users. This
# script applies the same rule so a reset account stays consistent with the API.
#
# usage:  bash reset_iris_password.sh [login]        # default: rdrolfe
#         IRIS_RESET_PW=... bash reset_iris_password.sh probe   # automated test
set -euo pipefail

LOGIN="${1:-rdrolfe}"
DB="${IRIS_DB_CONTAINER:-iriswebapp_db}"
APP="${IRIS_APP_CONTAINER:-iriswebapp_app}"
API="${IRIS_URL:-https://127.0.0.1:8443}"

if [ -n "${IRIS_RESET_PW:-}" ]; then
  P1="$IRIS_RESET_PW"
else
  read -r -s -p "New password for '$LOGIN': " P1; echo
  read -r -s -p "Repeat: " P2; echo
  [ "$P1" = "$P2" ] || { echo "passwords differ — nothing changed"; exit 1; }
fi
[ -n "$P1" ] || { echo "empty password — nothing changed"; exit 1; }
[ "${#P1}" -ge 12 ] || { echo "policy: needs at least 12 characters"; exit 1; }
case "$P1" in *[A-Z]*) : ;; *) echo "policy: needs an uppercase letter"; exit 1 ;; esac
case "$P1" in *[0-9]*) : ;; *) echo "policy: needs a digit"; exit 1 ;; esac

UID_=$(docker exec "$DB" psql -U postgres -d iris_db -tAc \
        "SELECT id FROM \"user\" WHERE \"user\"='$LOGIN'")
[ -n "$UID_" ] || { echo "no such user: '$LOGIN'"; exit 1; }

# 1. bcrypt hash, computed with the app container's own bcrypt.
#
#    IRIS hashes via flask-bcrypt (`bc = Bcrypt(app)` in app/__init__.py), whose
#    generate_password_hash IS bcrypt.hashpw(pw, bcrypt.gensalt(12)) — the
#    `$2b$12$…` format. Importing IRIS's `app` object to call its wrapper would
#    re-run the application factory in a side process (post_init fires), so this
#    calls the library directly; the equivalent hash was verified to be accepted
#    by `app.bc.check_password_hash`, which is the same call the login route
#    makes (login_routes.py: `bc.check_password_hash(user.password, password)`).
HASH=$(printf '%s' "$P1" | docker exec -i "$APP" python3 -c \
  "import sys, bcrypt; print(bcrypt.hashpw(sys.stdin.read().encode('utf8'), bcrypt.gensalt(12)).decode('utf8'))" \
  | tr -d '\r\n')
case "$HASH" in
  \$2*) : ;;
  *) echo "hash generation produced an unexpected value — nothing written"; exit 1 ;;
esac

# 2. write it. The SQL is fed on STDIN — `psql -c` does not interpolate
#    `:variables`, and stdin keeps both the hash and the password out of argv.
printf 'UPDATE "user" SET password = '"'"'%s'"'"' WHERE id = %s;\n' "$HASH" "$UID_" \
  | docker exec -i "$DB" psql -U postgres -d iris_db -q -f - >/dev/null

# 3. verify the WRITE: the stored hash must be a valid bcrypt hash of the
#    password just typed (this is the check that matters — it proves the row
#    holds what the human intends, not merely that an UPDATE ran)
STORED=$(docker exec "$DB" psql -U postgres -d iris_db -tAc \
         "SELECT password FROM \"user\" WHERE id=$UID_")
MATCH=$(printf '%s\n%s' "$STORED" "$P1" | docker exec -i "$APP" python3 -c "
import sys, bcrypt
stored = sys.stdin.readline().strip().encode('utf8')
pw = sys.stdin.read().encode('utf8')
print('match' if bcrypt.checkpw(pw, stored) else 'MISMATCH')")
if [ "$MATCH" != "match" ]; then
  unset P1 P2 HASH STORED
  echo "verify FAILED: stored hash does not match the new password"
  exit 1
fi
echo "verify: stored bcrypt hash matches the new password"

# 4. verify the LOGIN path (integration). A single attempt; IRIS counts failed
#    attempts toward a lockout window, so a failure is reported, never retried.
RESP=$(printf 'username=%s&password=%s' "$LOGIN" "$P1" | curl -sk -o /dev/null \
       -w '%{http_code} %{redirect_url}' -X POST --data @- "$API/login")
unset P1 P2 HASH STORED MATCH
CODE="${RESP%% *}"; DEST="${RESP#* }"
if [ "$CODE" = "302" ] && ! printf '%s' "$DEST" | grep -qi "login"; then
  echo "verify: web login succeeded (HTTP 302 -> ${DEST:-/})"
elif [ "$CODE" = "200" ]; then
  echo "verify: login POST returned HTTP 200 (form redisplayed) — the password"
  echo "        write IS verified; if this account has MFA, the login stops at"
  echo "        the second factor. Check by hand before retrying anything."
else
  echo "verify: login POST returned HTTP $CODE — check by hand"
fi
echo "DONE: password updated for '$LOGIN' (id $UID_)"
