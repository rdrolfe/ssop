#!/bin/bash
# Run ART technique on ubuntu-target with input-arg override toward c2-sink.
set -e
TECH="$1"; ARG_KEY="$2"; ARG_VAL="$3"
echo "=== running $TECH (override $ARG_KEY=$ARG_VAL) ==="
cd ~/atomic-red-team
pwsh -NoProfile -Command "
  Import-Module Invoke-AtomicRedTeam -Force
  Invoke-AtomicTest '$TECH' -PathToAtomicsFolder ~/atomic-red-team/atomics -InputArgs @{ $ARG_KEY = '$ARG_VAL' } -TimeoutSeconds 120
" 2>&1 | tail -25
echo "=== done $TECH ==="
