#!/usr/bin/env python3
"""Rebuild the SOC Workbench dashboard: ONE full-width iframe panel that
embeds the SSOP console (same host, same cert — the proven pattern), with
the panel version matching the running OSD (2.19.5, not the stale 8.0.0).

Runs INSIDE the dashboard container (env has DASHBOARD_USERNAME/PASSWORD).
"""
import json
import os
import urllib.request
import urllib.error
import ssl

BASE = "https://localhost:5601"
USER = os.environ["DASHBOARD_USERNAME"]
PASS = os.environ["DASHBOARD_PASSWORD"]
DASH_ID = "soc-workbench"
CONSOLE_URL = "https://192.168.1.75:5602/console"
OSD_VERSION = "2.19.5"  # api/status -> version.number (verified live)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def _req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{BASE}{path}", data=data, method=method,
        headers={"Content-Type": "application/json",
                 "osd-xsrf": "true",
                 "Authorization": "Basic " + __import__("base64").b64encode(
                     f"{USER}:{PASS}".encode()).decode()})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read().decode())


# 1. Read the current dashboard (attributes only — strip the GET round-trip
#    shape: namespaces/version/updated_at/id/type break the PUT).
cur = _req("GET", f"/api/saved_objects/dashboard/{DASH_ID}")
attrs = cur.get("attributes", {})
print("current:", attrs.get("title"), "| panels:", len(json.loads(attrs.get("panelsJSON") or "[]")))

# 2. New panelsJSON: one iframe panel, full width, tall enough for the
#    console (the decision surface). Version MUST match running OSD.
panel = {
    "version": OSD_VERSION,
    "gridData": {"x": 0, "y": 0, "w": 48, "h": 48, "i": "console"},
    "panelIndex": "console",
    "type": "iframe",
    "title": "SSOP SOC Workbench (ontology chain — cases, decisions, handoffs)",
    "embeddableConfig": {"url": CONSOLE_URL},
}
new_attrs = {
    "title": attrs.get("title", "SOC Workbench"),
    "description": ("Human-first SOC console embedded in Wazuh: case lifecycle, "
                    "on-case approve/deny/FP decisions, and role handoffs — the "
                    "full ontology chain in one pane."),
    "hits": 0,
    "panelsJSON": json.dumps([panel]),
    "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
    "timeRestore": False,
    "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
        {"query": {"query": "", "language": "kuery"}, "filter": []})},
}

# 3. PUT back (attributes + references only).
try:
    out = _req("PUT", f"/api/saved_objects/dashboard/{DASH_ID}",
               {"attributes": new_attrs, "references": []})
    print("PUT ok:", out.get("id"), "| type:", out.get("type"))
except urllib.error.HTTPError as e:
    print("PUT failed:", e.code, e.read().decode()[:500])
    raise
