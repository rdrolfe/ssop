#!/bin/bash
# SSOP alert router — every 3 min: fetch new alerts, dispatch to roles.
cd /home/rdrolfe/agent-runtime || exit 1
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/router.py
