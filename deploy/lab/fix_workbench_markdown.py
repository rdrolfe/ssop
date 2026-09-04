#!/usr/bin/env python3
"""Fix the SOC Workbench: replace the unsupported iframe panel (OSD 2.19.5
has NO iframe visualization type — 'OpenSearch Dashboards can't load
'iframe' visualizations') with a markdown panel carrying a direct link
into the SSOP console, plus the live case metrics via a table viz.

Runs INSIDE the dashboard container (env has DASHBOARD_USERNAME/PASSWORD).
"""
import base64
import json
import os
import ssl
import urllib.error
import urllib.request

BASE = "https://localhost:5601"
USER = os.environ["DASHBOARD_USERNAME"]
PASS = os.environ["DASHBOARD_PASSWORD"]
OSD_VERSION = "2.19.5"
CONSOLE_URL = "https://192.168.1.75:5602/console"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def _req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{BASE}{path}", data=data, method=method,
        headers={"Content-Type": "application/json", "osd-xsrf": "true",
                 "Authorization": "Basic " + base64.b64encode(
                     f"{USER}:{PASS}".encode()).decode()})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read().decode())


# 1. Create a markdown visualization: a big, obvious link into the console.
md_viz_id = "workbench-console-link"
md_markdown = (
    f"## SSOP SOC Workbench\n\n"
    f"The ontology chain lives in the console: case lifecycle, "
    f"approve / deny / false-positive decisions, role handoffs, and the "
    f"incident report + advisory.\n\n"
    f"> **[Open the SSOP Console →]({CONSOLE_URL})**\n\n"
    f"_(Same host, same cert — the console is served from this "
    f"dashboard's own hostname. Open the link in a new tab; bookmark it "
    f"for one-click access.)_"
)
md_attrs = {
    "title": "SSOP Workbench Console Link",
    "visState": json.dumps({
        "title": "SSOP Workbench Console Link",
        "type": "markdown",
        "params": {"markdown": md_markdown, "fontSize": 14},
        "aggs": [],
    }),
    "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
        {"query": {"query": "", "language": "kuery"}, "filter": []})},
    "description": "Link panel into the SSOP console",
    "version": 1,
}
try:
    _req("POST", f"/api/saved_objects/visualization/{md_viz_id}",
         {"attributes": md_attrs, "references": []})
    print("markdown viz created:", md_viz_id)
except urllib.error.HTTPError as e:
    print("markdown viz PUT failed:", e.code, e.read().decode()[:300])
    raise

# 2. Rebuild the dashboard: one markdown panel (full width, top) + a table
#    viz of the ssop-events index below it (case activity).
table_viz_id = "workbench-case-activity"
table_attrs = {
    "title": "Case Activity",
    "visState": json.dumps({
        "title": "Case Activity",
        "type": "table",
        "params": {"perPage": 20, "showPartialRows": False, "showMetricsAtAllLevels": False,
                   "sort": {"columnIndex": None, "direction": None},
                   "showTotal": False, "totalFunc": "sum"},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric",
             "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "bucket",
             "params": {"field": "@timestamp", "interval": "auto", "timeRange": None,
                        "drop_partials": False, "min_doc_count": 1,
                        "extended_bounds": {}}},
        ],
    }),
    "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
        {"index": "ssop-events", "query": {"query": "", "language": "kuery"},
         "filter": []})},
    "description": "SSOP case activity over time",
    "version": 1,
}
try:
    _req("POST", f"/api/saved_objects/visualization/{table_viz_id}",
         {"attributes": table_attrs, "references": [
             {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
              "type": "index-pattern", "id": "ssop-events"}]})
    print("table viz created:", table_viz_id)
except urllib.error.HTTPError as e:
    print("table viz PUT failed:", e.code, e.read().decode()[:300])
    raise

# 3. Dashboard: markdown link panel (full width) + table panel.
panels = [
    {"version": OSD_VERSION,
     "gridData": {"x": 0, "y": 0, "w": 48, "h": 10, "i": "console-link"},
     "panelIndex": "console-link", "type": "visualization",
     "id": md_viz_id, "title": "SSOP Workbench Console Link"},
    {"version": OSD_VERSION,
     "gridData": {"x": 0, "y": 10, "w": 48, "h": 20, "i": "activity"},
     "panelIndex": "activity", "type": "visualization",
     "id": table_viz_id, "title": "Case Activity"},
]
attrs = {
    "title": "SOC Workbench",
    "description": ("SSOP human console link + case activity. The console "
                    "(same-host HTTPS) holds the full ontology chain: cases, "
                    "decisions, handoffs."),
    "hits": 0,
    "panelsJSON": json.dumps(panels),
    "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
    "timeRestore": False,
    "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
        {"query": {"query": "", "language": "kuery"}, "filter": []})},
}
try:
    out = _req("PUT", f"/api/saved_objects/dashboard/soc-workbench",
               {"attributes": attrs, "references": []})
    print("dashboard rebuilt:", out.get("id"))
except urllib.error.HTTPError as e:
    print("dashboard PUT failed:", e.code, e.read().decode()[:300])
    raise
