#!/bin/bash
# Console-proxy bearer-token injection — run ON .75 (telemetry host).
# The proxy is the trusted server-side component; it holds the token and
# attaches it to every upstream call. Browsers never see the token.
set -euo pipefail
F=~/ssop-console/console_proxy.py

cp -p "$F" "$F.bak-$(date +%m%d)"

python3 - "$F" << 'EOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
t = p.read_text()

if "ADJUDICATE_API_TOKEN" in t:
    print("already patched"); sys.exit(0)

# 1. Token constant next to the API address.
t = t.replace(
    'ADJUDICATE_API = "https://192.168.1.29:8787"',
    'ADJUDICATE_API = "https://192.168.1.29:8787"\n'
    '# Bearer token for the (now-authenticated) adjudication API. Read from\n'
    '# the environment; the proxy is the trusted server-side caller — browsers\n'
    '# never see it.\n'
    'ADJUDICATE_API_TOKEN = __import__("os").environ.get("ADJUDICATE_API_TOKEN", "")')

# 2. GET path: attach the Authorization header.
t = t.replace(
    'with urllib.request.urlopen(ADJUDICATE_API + path, timeout=15,\n'
    '                                        context=ssl._create_unverified_context()) as r:',
    '_get_req = urllib.request.Request(ADJUDICATE_API + path,\n'
    '                                     headers={"Authorization": "Bearer " + ADJUDICATE_API_TOKEN})\n'
    '            with urllib.request.urlopen(_get_req, timeout=15,\n'
    '                                        context=ssl._create_unverified_context()) as r:')

# 3. POST path: same.
t = t.replace(
    'headers={"Content-Type": "application/json"}, method="POST")',
    'headers={"Content-Type": "application/json",\n'
    '                         "Authorization": "Bearer " + ADJUDICATE_API_TOKEN}, method="POST")')

p.write_text(t)
print("patched OK")
EOF

python3 -m py_compile "$F" && echo "COMPILE_OK"
