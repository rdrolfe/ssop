#!/bin/bash
# SSOP hunt sweep — run the live hunt library over a 1-day window.
# Coverage knob: days= below. 15m cadence → catch slow patterns without
# re-filing (sweep attaches to open hunt cases; clean = logged, not filed).
cd /home/rdrolfe/agent-runtime || exit 1
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/hunt.py hunt:sweep days=1
