#!/bin/bash
# SSOP analyst sweep — every 2 hours: ingest new alerts, classify, escalate.
# Logs to journald; outcomes flow to case spine + pane of glass automatically.
cd /home/rdrolfe/agent-runtime || exit 1
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/analyst.py analyst:recent limit=20 min_level=3
