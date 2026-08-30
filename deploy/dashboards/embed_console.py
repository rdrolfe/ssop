#!/usr/bin/env python3
"""Embed the SSOP Human Console into dashboards via the OSD saved_objects API.

Runs INSIDE the dashboard container (localhost:5601 + DASHBOARD_USERNAME/
DASHBOARD_PASSWORD env are present there). Proven pattern from fix_viz_index.py.

1. Updates the existing adj-console-md markdown viz to point at the new
   tabbed console (label updated to SSOP Human Console).
2. Adds a panel referencing that viz to the SSOP Pane of Glass (ssop-pane)
   dashboard so the human console is one click from the primary pane.

NOTE: OSD's PUT rejects the GET roundtrip shape (namespaces/version/updated_at).
Build payloads with attributes + references ONLY, like fix_viz_index.py.
"""
import json, base64, urllib.request, urllib.error, ssl, os

BASE = "https://localhost:5601"
USER = os.environ.get("DASHBOARD_USERNAME", "admin")
PASS = os.environ.get("DASHBOARD_PASSWORD", "")
PATTERN = "ssop-events"
CONSOLE_URL = "https://192.168.1.75:5602/console"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
auth = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
HDRS = {"Authorization": f"Basic {auth}", "osd-xsrf": "true", "Content-Type": "application/json"}


def _call(req):
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:500]
        print(f"HTTP {e.code} on {req.full_url}: {body}", flush=True)
        raise


def get(kind, oid):
    req = urllib.request.Request(f"{BASE}/api/saved_objects/{kind}/{oid}", headers=HDRS)
    return _call(req)


def put(kind, oid, obj):
    req = urllib.request.Request(f"{BASE}/api/saved_objects/{kind}/{oid}",
                                 data=json.dumps(obj).encode(), headers=HDRS, method="PUT")
    return _call(req)


# --- 1. update adj-console-md viz (new console label + URL) ---
VIZ = "adj-console-md"
viz = get("visualization", VIZ)
attrs = viz["attributes"]
vs = json.loads(attrs["visState"])
vs["params"]["markdown"] = (
    f"[**OPEN SSOP HUMAN CONSOLE**]({CONSOLE_URL})\n\n"
    "Tickets / Closed Loop / Tuned Rules — what the agents decided and why."
)
vs["title"] = "SSOP Human Console"
attrs["visState"] = json.dumps(vs)
attrs["title"] = "SSOP Human Console (open)"
ss = json.loads(attrs.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON", "{}"))
ss["index"] = PATTERN
attrs.setdefault("kibanaSavedObjectMeta", {})["searchSourceJSON"] = json.dumps(ss)
out = put("visualization", VIZ, {"attributes": attrs, "references": [
    {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
     "type": "index-pattern", "id": PATTERN}]})
print(f"viz {VIZ} updated: {out.get('attributes', {}).get('title')}")

# --- 2. add console panel to ssop-pane dashboard ---
DASH = "ssop-pane"
dash = get("dashboard", DASH)
dattrs = dash["attributes"]
panels = json.loads(dattrs["panelsJSON"])
nums = [int(p["panelIndex"]) for p in panels if str(p["panelIndex"]).isdigit()]
nxt = (max(nums) + 1) if nums else 1
panels.append({
    "version": "8.0.0",
    "gridData": {"x": 0, "y": 30, "w": 24, "h": 6, "i": str(nxt)},
    "panelIndex": str(nxt),
    "type": "visualization",
    "id": VIZ,
    "title": "SSOP Human Console",
})
dattrs["panelsJSON"] = json.dumps(panels)
dss = json.loads(dattrs.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON", "{}"))
dss["index"] = PATTERN
dattrs.setdefault("kibanaSavedObjectMeta", {})["searchSourceJSON"] = json.dumps(dss)
refs = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
         "type": "index-pattern", "id": PATTERN}]
out = put("dashboard", DASH, {"attributes": dattrs, "references": refs})
npanels = len(json.loads(out["attributes"]["panelsJSON"]))
print(f"dashboard {DASH} updated: {npanels} panels (console panel index {nxt})")
