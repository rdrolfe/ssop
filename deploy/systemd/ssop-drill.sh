#!/bin/bash
# SSOP purple-team drill — fire a technique, verify the chain, write receipt.
# Runs against the ACTIVE backend from transport.yaml (wazuh | securityonion).
cd /home/rdrolfe/agent-runtime || exit 1
exec /home/rdrolfe/agent-runtime/agent-env/bin/python3 /home/rdrolfe/agent-runtime/drill.py
