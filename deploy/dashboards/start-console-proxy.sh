#!/bin/bash
# Start the SSOP console proxy (durable, runs on the telemetry host .75).
# Refresh the certs from the dashboard container (they rotate with updates),
# then launch the proxy in the background. Idempotent — safe to run at
# @reboot AND manually.
set -e
cd "$HOME/ssop-console" || exit 1

# Refresh certs from the dashboard container into the durable path.
docker cp single-node-wazuh.dashboard-1:/usr/share/wazuh-dashboard/config/certs/dashboard.pem "$HOME/ssop-console/certs/cert.pem" >/dev/null 2>&1
docker cp single-node-wazuh.dashboard-1:/usr/share/wazuh-dashboard/config/certs/dashboard-key.pem "$HOME/ssop-console/certs/key.pem" >/dev/null 2>&1
chmod 600 "$HOME/ssop-console/certs/key.pem"

# Kill any existing instance, then start fresh.
pkill -f "console_proxy.py" 2>/dev/null || true
sleep 1
nohup python3 "$HOME/ssop-console/console_proxy.py" >> "$HOME/ssop-console/console_proxy.log" 2>&1 &
sleep 2
if pgrep -f "console_proxy.py" >/dev/null; then
  echo "console proxy started (pid $(pgrep -f 'console_proxy.py' | head -1))"
else
  echo "FAILED: proxy not running — log:"; tail -5 "$HOME/ssop-console/console_proxy.log"
  exit 1
fi
