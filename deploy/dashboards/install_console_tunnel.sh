#!/bin/bash
# Install + start the console tunnel on .75 (telemetry) and repoint the
# console proxy at the local tunnel endpoint.
# The systemd unit needs root to install — the script prints the sudo
# commands for the operator instead of assuming passwordless sudo.
set -euo pipefail
F=~/ssop-console/console_proxy.py

cp -p "$F" "$F.bak-tunnel-$(date +%m%d)"

python3 - "$F" << 'EOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
t = p.read_text()
if 'ADJUDICATE_API = "https://127.0.0.1:8787"' in t:
    print("already repointed"); sys.exit(0)
t = t.replace(
    'ADJUDICATE_API = "https://192.168.1.29:8787"',
    'ADJUDICATE_API = "https://127.0.0.1:8787"  # via ssop-console-tunnel.service (loopback-to-loopback SSH forward)')
p.write_text(t)
print("repointed OK")
EOF
python3 -m py_compile "$F" && echo COMPILE_OK

echo
echo "=== operator steps (need sudo) ==="
echo "sudo cp ~/ssop-console/ssop-console-tunnel.service /etc/systemd/system/"
echo "sudo systemctl daemon-reload"
echo "sudo systemctl enable --now ssop-console-tunnel"
echo "kill ${1:-<old-proxy-pid>}; cd ~/ssop-console && ADJUDICATE_API_TOKEN=<token> nohup python3 console_proxy.py > ~/ssop-console/proxy.log 2>&1 &"
