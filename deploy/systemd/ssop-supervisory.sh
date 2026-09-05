#!/bin/bash
# SSOP supervisory duty — daily: adjudicate escalation queue + reconcile spine.
# Logs to journald; verdicts go to case spine; divergence flags to pane.
# Pre-run: IRIS -> spine sync (human notes/events made in IRIS become part of
# the spine audit trail BEFORE the duty decides).
cd /home/rdrolfe/agent-runtime || exit 1
mkdir -p /home/rdrolfe/agent-runtime/logs
/home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/deploy/lab/sync_iris_to_spine.py \
    >> /home/rdrolfe/agent-runtime/logs/iris-sync.log 2>&1 \
    || echo "iris->spine sync failed (non-fatal): $?" >> /home/rdrolfe/agent-runtime/logs/iris-sync.log
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/supervisory.py supervisory:adjudicate limit=100 auto_close=true
