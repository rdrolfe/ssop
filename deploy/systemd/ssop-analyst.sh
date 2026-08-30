#!/bin/bash
# SSOP analyst sweep — every 5 minutes: ingest new alerts, classify, escalate.
# Pure-rule classification (no LLM in the sweep itself); escalation only fires
# when a verdict escalates. limit=100 widens the per-run window so the faster
# cadence actually sees the backlog (was limit=20 — the blind spot).
# Logs to journald; outcomes flow to case spine + pane of glass automatically.
cd /home/rdrolfe/agent-runtime || exit 1
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/analyst.py analyst:recent limit=100 min_level=3
