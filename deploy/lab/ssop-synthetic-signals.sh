#!/bin/bash
# SSOP SYNTHETIC-SIGNAL injector — writes fabricated alert documents straight
# into the Wazuh index so the router sweep mints fresh cases. Part of the
# standing purple-team cadence (see ssop-synthetic-signals.timer).
#
# *** THIS EXECUTES NOTHING. It is NOT Atomic Red Team. ***
# It plants the *output* of an attack so the detection pipeline has something
# to discover; no adversary technique ever runs on any host. Real atomic
# execution is a separate, unbuilt workstream — see the wayfinder ticket
# `atomic-red-team-real-execution`.
#
# The injector reads/writes nothing but the alert index; the
# router/analyst/supervisory timers do the rest.
cd /home/rdrolfe/agent-runtime || exit 1
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/deploy/lab/fire_atomic_indicators.py
