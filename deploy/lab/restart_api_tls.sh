#!/bin/bash
# Restart adjudication API on .29 WITH TLS (matches console_proxy's https:// forward).
set -e
echo "=== get a cert to .29 (from .75 dashboard cert) ==="
scp -i ~/.ssh/agent-ssh -o StrictHostKeyChecking=accept-new rdrolfe@192.168.1.75:/tmp/telemetry_cert.pem /tmp/api_cert.pem 2>&1 | grep -iE "error|denied" || echo CERT-OK
scp -i ~/.ssh/agent-ssh -o StrictHostKeyChecking=accept-new rdrolfe@192.168.1.75:/tmp/telemetry_key.pem /tmp/api_key.pem 2>&1 | grep -iE "error|denied" || echo KEY-OK
chmod 600 /tmp/api_key.pem
echo "=== kill current API (plain HTTP) ==="
PID=$(ss -tlnp 2>/dev/null | grep 8787 | grep -oE "pid=[0-9]+" | head -1 | cut -d= -f2)
[ -n "$PID" ] && kill "$PID" && sleep 1
echo "=== start with --tls ==="
cd ~/agent-runtime && source agent-env/bin/activate 2>/dev/null
nohup python3 -m tools.adjudicate_api --host 0.0.0.0 --port 8787 --tls > /tmp/adjudicate_api.log 2>&1 &
sleep 3
echo "=== verify TLS responds ==="
curl -sk -w "\nHTTP %{http_code}\n" https://127.0.0.1:8787/health 2>&1 | tail -2
