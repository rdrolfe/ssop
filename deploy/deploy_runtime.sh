#!/usr/bin/env bash
# Deploy the SSOP agent tree from the repo to the runtime host.
#
# WHY THIS EXISTS
# ---------------
# The runtime on 192.168.1.29 is a plain directory, NOT a git clone, so
# nothing auto-syncs it. Every change used to be copied by hand, which made
# "is the runtime running the current code?" a question you had to answer by
# remembering to check. That has already produced two real defects:
#
#   1. An `rsync --include='*/'` put investigator.py at the runtime ROOT
#      instead of tools/ -- silently, and only caught because md5 was
#      compared afterwards. The old copy kept running.
#   2. Repo and runtime code drifted apart until a change appeared to do
#      nothing on .29.
#
# So: one command, and it FAILS LOUDLY rather than assuming success.
#
# LAYOUT (the trap that caused defect 1)
# --------------------------------------
#   repo:    agents/tools/X.py   agents/config.py
#   runtime: tools/X.py          config.py          <- agents/ level is DROPPED
#
# EXCLUDED, deliberately
# ----------------------
#   transport.yaml  the repo copy is the clean-checkout default (backend:
#                   wazuh, empty endpoints). The runtime's holds the live
#                   SO endpoint + user. Copying it would revert the SO
#                   publish fix.
#   .env            holds SO_INDEXER_PASSWORD and the CA bundle path.
#   certs/          the CA bundle on the runtime has SO's CA appended (the
#                   trust anchor that made verified TLS work). The repo's
#                   does not, and regenerating it needs the CA key.
#
# USAGE
#   deploy/deploy_runtime.sh            # deploy and verify
#   deploy/deploy_runtime.sh --check    # verify only, copy nothing

set -euo pipefail

HOST="${SSOP_RT_HOST:-192.168.1.29}"
USER="${SSOP_RT_USER:-rdrolfe}"
KEY="${SSOP_RT_KEY:-$HOME/.ssh/hermes_ssop}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RT="$HOME/agent-runtime"
SSH=(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=10)

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

# Files that MUST agree between repo and runtime. Config and tools, because
# those are what an agent imports at runtime.
#
# drill.py is deliberately NOT here: it exists only on the runtime (it is
# not in agents/), so there is nothing to compare against. Noted rather than
# faked -- a tracked list that silently skips a file is worse than a short one.
TRACKED=(
  config.py
  router.py
  analyst.py
  agent.py
  hunt.py
  tools/attach_case_report.py
  tools/investigator.py
  tools/tuning_tools.py
  tools/ontology.py
  tools/tls.py
  tools/ingest_bots.py
)

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }

echo "== SSOP runtime deploy =="
echo "   repo    : $REPO"
echo "   runtime : $USER@$HOST:$RT"
echo

# --- reachable? ------------------------------------------------------------
if ! "${SSH[@]}" "$USER@$HOST" true 2>/dev/null; then
  red "SSH FAILED to $USER@$HOST -- aborting, nothing was copied."
  exit 1
fi

# --- copy ------------------------------------------------------------------
if [[ $CHECK_ONLY -eq 0 ]]; then
  echo "-- copying tracked files"
  for f in "${TRACKED[@]}"; do
    src="$REPO/agents/$f"
    [[ -f "$src" ]] || { red "MISSING IN REPO: agents/$f"; exit 1; }
    "${SSH[@]}" "$USER@$HOST" "mkdir -p '$RT/$(dirname "$f")'"
    scp -q -i "$KEY" -o BatchMode=yes "$src" "$USER@$HOST:$RT/$f"
    printf '   %s\n' "$f"
  done

  # Only the files we manage -- never a blanket rsync of the tree. A blanket
  # copy is how transport.yaml and .env get clobbered.
  echo "-- deployed $((${#TRACKED[@]})) files"
  echo
fi

# --- verify md5 (the gate; never assume the copy worked) -------------------
echo "-- verifying repo and runtime agree"
fails=0
for f in "${TRACKED[@]}"; do
  local_md5=$(md5sum "$REPO/agents/$f" 2>/dev/null | cut -d' ' -f1)
  rt_md5=$("${SSH[@]}" "$USER@$HOST" "md5sum '$RT/$f' 2>/dev/null | cut -d' ' -f1" || true)
  if [[ -z "$rt_md5" ]]; then
    red "   MISSING ON RUNTIME  $f"
    fails=$((fails + 1))
  elif [[ "$local_md5" != "$rt_md5" ]]; then
    red "   MISMATCH            $f"
    echo "      repo=$local_md5"
    echo "      rt  =$rt_md5"
    fails=$((fails + 1))
  else
    printf '   ok  %s\n' "$f"
  fi
done

# --- the files we must NOT touch, verified still distinct ------------------
# The repo legitimately has NO .env (only .env.template), so a md5 of the
# repo side is meaningless for it. Under `set -e` a bare md5sum on a
# missing file aborts the script with no message -- which is exactly the
# silent failure this script exists to prevent. So: for .env, assert only
# that the RUNTIME copy exists. For transport.yaml, compare both sides.
echo "-- confirming operator-local config was left alone"
for f in transport.yaml .env; do
  b=$("${SSH[@]}" "$USER@$HOST" "md5sum '$RT/$f' 2>/dev/null | cut -d' ' -f1" || true)
  if [[ -z "$b" ]]; then
    red "   MISSING ON RUNTIME  $f  (this is deploy's secret/config -- investigate)"
    fails=$((fails + 1))
    continue
  fi
  a=$(md5sum "$REPO/agents/$f" 2>/dev/null | cut -d' ' -f1 || true)
  if [[ -z "$a" ]]; then
    printf '   ok  %s (runtime-only secret, exists; repo has no copy by design)\n' "$f"
  elif [[ "$a" != "$b" ]]; then
    printf '   ok  %s (intentionally differs from repo)\n' "$f"
  else
    red "   WARNING $f now matches the repo -- operator values may be gone"
  fi
done

echo
if [[ $fails -gt 0 ]]; then
  red "DEPLOY FAILED -- $fails file(s) not in sync. Do not assume .29 is current."
  exit 1
fi
grn "DEPLOY OK -- $((${#TRACKED[@]})) files verified identical."
echo "   Next: restart the units that import the changed modules, e.g."
echo "     sudo systemctl restart ssop-analyst ssop-hunt"
