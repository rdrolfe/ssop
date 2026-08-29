import os, sys, json, base64, ssl, urllib.request
from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, ".")
from config import settings
from tools.bots_parser import normalize

auth = "Basic " + base64.b64encode(f"{settings.indexer_user}:{settings.indexer_password}".encode()).decode()
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
HOST = settings.indexer_host if settings.indexer_host not in ("", "localhost") else "192.168.1.75"

def search(idx, q, size=100, src=None):
    body = {"size": size, "query": q}
    if src: body["_source"] = src
    req = urllib.request.Request(f"https://{HOST}:9200/{idx}/_search",
        data=json.dumps(body).encode(),
        headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read().decode()).get("hits", {}).get("hits", [])

# FP sweep: pull process-create events (EC1) + a broad sample, count escalations,
# and inspect each escalation to confirm it's a genuine attack pattern.
print("=== Sysmon process-create FP sweep ===")
escalated = []
for q, label in [({"term": {"EventCode": 1}}, "EC1 process-create"),
                 ({"term": {"EventCode": 3}}, "EC3 network (control)")]:
    hits = search("bots-sysmon-op-poc", q, size=200, src=["_raw", "EventCode", "Image", "CommandLine"])
    esc = 0
    examples = []
    for h in hits:
        norm = normalize(h["_source"])
        if int(norm.get("rule", {}).get("level", 0)) >= 8:
            esc += 1
            if len(examples) < 6:
                examples.append(str(norm.get("rule", {}).get("description", ""))[:90])
    print(f"\n  [{label}] {esc}/{len(hits)} escalated")
    for ex in examples:
        print(f"    → {ex}")

print("\n=== dropped_tmp / webroot_exe FP check (all matching docs) ===")
# Every doc matching the two new patterns should be a genuine attack
for pat, field in [("appdata\\roaming\\", "Image"), ("wwwroot", "Image")]:
    hits = search("bots-sysmon-op-poc", {"wildcard": {field: f"*{pat}*"}}, size=100,
                  src=["_raw", "EventCode", "Image", "CommandLine"])
    tmp_dots = 0
    for h in hits:
        img = str(h["_source"].get("Image", "")).lower()
        if img.endswith(".tmp") or img.endswith(".exe"):
            tmp_dots += 1
    print(f"  Image contains '{pat}': {len(hits)} docs, {tmp_dots} are .tmp/.exe (suspicious)")
