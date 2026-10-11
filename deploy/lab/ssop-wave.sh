#!/bin/bash
# SSOP wave — fire a seeded subset of REAL ATT&CK-mapped techniques at the lab
# victim (.78) and then ASSERT the platform held. Runs as the unattended plane
# (ssop-agent) on infra-ops (.29); journald captures the output.
#
# *** THIS IS NOT ATOMIC RED TEAM. *** Commands are hand-authored and
# ATT&CK-mapped; no `invoke-atomic` is run. It is also NOT the synthetic
# injector: every command here executes on a real host and every assertion is
# made against the live Wazuh indexer.
#
# WHY IT FAILS CLOSED
# The invariant gate asserts against the live indexer. With no credentials it
# would "pass" while measuring nothing -- a scheduled wave reporting coverage it
# does not have. So a missing credential is exit 78 (EX_CONFIG), not a pass, and
# a gate violation is exit 2. Either way the unit fails loudly in journald.
#
# The gate is what makes this scheduled job worth having: a daily wave is what
# would have caught the 2026-10-05 manager decode regression on its own, because
# the manager was silently discarding 1.6M events while every other check stayed
# green.
set -u

RT=/home/rdrolfe/agent-runtime
ENVF="$RT/.env"
RUNNER="$RT/deploy/lab/run_techniques.py"
LABKEY="${SSOP_LAB_SSH_KEY:-$RT/.ssh/agent-ssh}"

[ -r "$ENVF" ]   || { echo "CONFIG ERROR: cannot read $ENVF"; exit 78; }
[ -r "$RUNNER" ] || { echo "CONFIG ERROR: runner missing at $RUNNER"; exit 78; }
[ -r "$LABKEY" ] || { echo "CONFIG ERROR: lab ssh key not readable at $LABKEY"; exit 78; }

# Indexer credentials for the gate. Read the KEYS WE NEED rather than sourcing
# the whole file: that keeps the rest of the credential store out of this
# process's environment, and it does not depend on the .env being shell-safe.
# `tail -1` matches what the runtime's dotenv loader does -- .env defines
# SSH_KEY_PATH twice and the LAST assignment is the effective one.
envget() { sed -n "s|^$1=||p" "$ENVF" | tail -1; }

WAZUH_INDEXER_PASSWORD=$(envget WAZUH_INDEXER_PASSWORD)
WAZUH_INDEXER_USERNAME=$(envget WAZUH_INDEXER_USERNAME)
WAZUH_INDEXER_HOST=$(envget WAZUH_INDEXER_HOST)

if [ -z "${WAZUH_INDEXER_PASSWORD:-}" ]; then
  echo "CONFIG ERROR: WAZUH_INDEXER_PASSWORD is absent from $ENVF."
  echo "The invariant gate asserts against the live indexer; without credentials"
  echo "it would report a pass while measuring nothing. Refusing to run."
  exit 78
fi

export WAZUH_INDEXER_PASSWORD WAZUH_INDEXER_USERNAME WAZUH_INDEXER_HOST
export SSOP_LAB_SSH_KEY="$LABKEY"

echo "wave: $(date -u +%FT%TZ) host=$(hostname) user=$(id -un) key=$SSOP_LAB_SSH_KEY"

cd "$RT" || exit 1
# -u: unbuffered. Without it Python block-buffers stdout when it is not a tty,
# so journald stays EMPTY until the process exits -- an unattended run that hangs
# is then indistinguishable from one making progress, and a unit killed by
# TimeoutStartSec loses every line it produced.
exec "$RT/agent-env/bin/python3" -u "$RUNNER" --wave --assert-invariants