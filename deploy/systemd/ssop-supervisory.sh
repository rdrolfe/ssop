#!/bin/bash
# SSOP supervisory duty — daily: adjudicate escalation queue + reconcile spine.
# Logs to journald; verdicts go to case spine; divergence flags to pane.
cd /home/rdrolfe/agent-runtime || exit 1
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/supervisory.py supervisory:adjudicate limit=100 auto_close=true
