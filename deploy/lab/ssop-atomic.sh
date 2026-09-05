#!/bin/bash
# SSOP atomic-indicator injector — fire MITRE-style indicators into the live
# index so the router sweep mints fresh cases. Part of the standing purple
# team cadence (see ssop-atomic.timer). The injector reads/writes nothing
# but the alert index; the router/analyst/supervisory timers do the rest.
cd /home/rdrolfe/agent-runtime || exit 1
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/deploy/lab/fire_atomic_indicators.py