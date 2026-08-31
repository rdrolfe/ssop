"""Ground-truth validation: do the published BOTSv1 answers exist in OUR data?

Probes the ingested BOTS indices (bots-*-poc) for the known-good answers from
the published BOTSv1 walkthroughs (samclass/Andickinson/Medium). If an agent
converges on these, it's correct. This is the data-presence half of the
ground-truth test — the full-loop half runs the spine against the same events.
"""
import os, sys, json, base64, ssl, urllib.request
from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, ".")
from config import settings

auth = "Basic " + base64.b64encode(f"{settings.indexer_user}:{settings.indexer_password}".encode()).decode()
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
HOST = settings.indexer_host if settings.indexer_host not in ("", "localhost") else "192.168.1.75"

def count(idx, query, host=None, auth_header=None):
    h = host or HOST
    a = auth_header or auth
    body = {"size": 0, "query": query}
    req = urllib.request.Request(
        f"https://{h}:9200/{idx}/_search", data=json.dumps(body).encode(),
        headers={"Authorization": a, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            d = json.loads(r.read().decode())
            return int(d.get("hits", {}).get("total", {}).get("value", 0))
    except Exception as e:
        return f"ERR: {e}"

# SO creds (the winsecurity index lives on SO, not Wazuh)
SO_HOST = "192.168.1.76"
SO_USER = "hermes@ssop.local"
SO_PASS = settings.so_indexer_password or settings.indexer_password
so_auth = "Basic " + base64.b64encode(f"{SO_USER}:{SO_PASS}".encode()).decode()

# Ground-truth anchors from the published BOTSv1 answers
# (fields match the data AS IT LIES: dest_ip for dest, _raw for form-data)
checks = [
    # (label, index, query)  — does the published answer exist in our data?
    ("scanner src 40.80.148.42 (Acunetix)", "bots-http-poc", {"term": {"c_ip": "40.80.148.42"}}),
    ("web server 192.168.250.70 (dest_ip)", "bots-http-poc", {"term": {"dest_ip": "192.168.250.70"}}),
    ("staging server 23.22.63.114", "bots-http-poc", {"term": {"c_ip": "23.22.63.114"}}),
    ("deface file poisonivy-coming-for-you", "bots-http-poc", {"match_phrase": {"_raw": "poisonivy-is-coming-for-you-batman.jpeg"}}),
    ("infected workstation 192.168.250.100", "bots-http-poc", {"term": {"c_ip": "192.168.250.100"}}),
    ("exe upload 3791.exe (_raw)", "bots-http-poc", {"match_phrase": {"_raw": "3791.exe"}}),
    ("ransomware FQDN cerber...xmfir0.win", "bots-dns-poc", {"wildcard": {"query": "*xmfir0*"}}),
    ("sysmon process 121214.tmp", "bots-sysmon-op-poc", {"match_phrase": {"_raw": "121214.tmp"}}),
    ("sysmon hash AAE3F5A29935E6ABCC2C2754D12A9AF0", "bots-sysmon-op-poc", {"match_phrase": {"_raw": "AAE3F5A29935E6ABCC2C2754D12A9AF0"}}),
    ("sysmon 3791.exe process create", "bots-sysmon-op-poc", {"match_phrase": {"_raw": "3791.exe"}}),
    ("windows process exec (joomla webshell, SO)", "bots-winsecurity", {"bool": {"must": [{"term": {"EventCode": 4688}}, {"match_phrase": {"_raw": "joomla"}}]}}),
    # sysmon slice is now duplicated to SO for two-backend ground-truth parity
    ("sysmon process 121214.tmp (SO)", "bots-sysmon-op-poc", {"match_phrase": {"_raw": "121214.tmp"}}, "so"),
    ("sysmon hash AAE3F5A29935E6ABCC2C2754D12A9AF0 (SO)", "bots-sysmon-op-poc", {"match_phrase": {"_raw": "AAE3F5A29935E6ABCC2C2754D12A9AF0"}}, "so"),
    ("sysmon 3791.exe process create (SO)", "bots-sysmon-op-poc", {"match_phrase": {"_raw": "3791.exe"}}, "so"),
]

print("=== BOTSv1 GROUND-TRUTH DATA PRESENCE ===")
print(f"host: {HOST} (+ SO {SO_HOST} for winsecurity + duplicated sysmon)\n")
ok = 0
for row in checks:
    label, idx, query = row[0], row[1], row[2]
    is_so = (len(row) > 3 and row[3] == "so") or idx == "bots-winsecurity"
    n = count(idx, query, host=(SO_HOST if is_so else None), auth_header=(so_auth if is_so else None))
    if isinstance(n, int) and n > 0:
        mark = "✅ PRESENT"
        ok += 1
    elif isinstance(n, int):
        mark = "❌ MISSING"
    else:
        mark = "⚠️ ERR"
    print(f"  [{mark}] {label}  -> {n}")
print(f"\n{ok}/{len(checks)} anchors present in ingested data")
