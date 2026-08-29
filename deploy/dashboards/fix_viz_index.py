#!/usr/bin/env python3
"""Fix all SSOP visualizations + dashboard: embed index in searchSourceJSON.
The working pattern (ssop-actions-over-time) has {"index":"ssop-events",...}
inside searchSourceJSON — that's what OSD needs to resolve aggs.
"""
import json, base64, urllib.request, ssl, os

BASE = "https://localhost:5601"
USER = os.environ["DASHBOARD_USERNAME"]
PASS = os.environ["DASHBOARD_PASSWORD"]
PATTERN = "ssop-events"

VIZ_IDS = [
    "0d048260-9c1d-11f1-b914-e3158878e251",
    "0d3a3860-9c1d-11f1-b914-e3158878e251",
    "0dd2cee0-9c1d-11f1-b914-e3158878e251",
    "0e694280-9c1d-11f1-b914-e3158878e251",
    "0f02c360-9c1d-11f1-b914-e3158878e251",
    "0f9d55b0-9c1d-11f1-b914-e3158878e251",
]
DASH_ID = "1a79ca90-9c1d-11f1-b914-e3158878e251"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
auth = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
HDRS = {"Authorization": f"Basic {auth}", "osd-xsrf": "true", "Content-Type": "application/json"}

def fix_search_source(obj):
    """Embed index into searchSourceJSON, keep references."""
    attrs = obj.setdefault("attributes", {})
    meta = attrs.setdefault("kibanaSavedObjectMeta", {})
    try:
        ss = json.loads(meta.get("searchSourceJSON", "{}"))
    except Exception:
        ss = {}
    ss["index"] = PATTERN
    meta["searchSourceJSON"] = json.dumps(ss)
    obj["references"] = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                          "type": "index-pattern", "id": PATTERN}]
    return obj

def put(kind, oid, obj):
    req = urllib.request.Request(f"{BASE}/api/saved_objects/{kind}/{oid}",
                                 data=json.dumps(obj).encode(), headers=HDRS, method="PUT")
    with urllib.request.urlopen(req, context=ctx) as r:
        return json.loads(r.read().decode())

# Visualizations: rebuild payloads from the working structure (index embedded)
import glob
# The visStates were built earlier; reuse the /tmp payloads on the HOST,
# but we need them inside the container. Simpler: build full objects here
# by loading the built update files (they have attrs.visState already).
for vid in VIZ_IDS:
    path = f"/tmp/viz_updates/{vid}.json"
    if not os.path.exists(path):
        print(f"skip {vid}: no payload file")
        continue
    with open(path) as f:
        obj = json.load(f)
    obj = fix_search_source(obj)
    out = put("visualization", vid, obj)
    ok = "index" in json.loads(out["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
    print(f"{vid}: searchSource index embedded = {ok}")

# Dashboard: rebuild with index embedded in its searchSourceJSON
dash_path = "/tmp/dash_overview_ref.json"
if os.path.exists(dash_path):
    with open(dash_path) as f:
        dobj = json.load(f)
    dobj = fix_search_source(dobj)
    out = put("dashboard", DASH_ID, dobj)
    print(f"dashboard {DASH_ID}: searchSource index embedded")
