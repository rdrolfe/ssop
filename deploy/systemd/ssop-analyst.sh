#!/bin/bash
# SSOP analyst sweep — every 5 minutes: ingest new alerts, classify, escalate.
# Pure-rule classification (no LLM in the sweep itself); escalation only fires
# when a verdict escalates.
#
# NOZZLE KNOBS (see docs/DEPLOYMENT.md Step 7):
#   - cadence:  OnCalendar in ssop-analyst.timer (this file's sibling)
#   - coverage: limit= below — raise it in step with any cadence increase.
#               At 2h/limit=20 the sweep only saw the 20 newest alerts (blind
#               spot); 100 + 5m fixes latency AND coverage for a homelab.
# Logs to journald; outcomes flow to case spine + pane of glass automatically.
cd /home/rdrolfe/agent-runtime || exit 1
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/analyst.py analyst:recent limit=100 min_level=3
