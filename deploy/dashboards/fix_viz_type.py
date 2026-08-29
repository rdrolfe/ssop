#!/usr/bin/env python3
"""Fix visState.type from 'bar' to 'histogram' on the two bar visualizations."""
import json, base64, urllib.request, ssl, os

BASE = "https://localhost:5601"
IDX = "https://single-node-wazuh.indexer-1:9200"
USER = os.environ["DASHBOARD_USERNAME"]
PASS = os.environ["DASHBOARD_PASSWORD"]
IUSER = os.environ["INDEXER_USERNAME"]
IPASS = os.environ["INDEXER_PASSWORD"]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def auth(u, p):
    return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()

for vid in ["0dd2cee0-9c1d-11f1-b914-e3158878e251",
            "0e694280-9c1d-11f1-b914-e3158878e251"]:
    # GET current object from indexer
    req = urllib.request.Request(f"{IDX}/.kibana/_doc/visualization:{vid}")
    req.add_header("Authorization", auth(IUSER, IPASS))
    with urllib.request.urlopen(req, context=ctx) as r:
        d = json.loads(r.read().decode())
    v = d["_source"]["visualization"]
    vs = json.loads(v["visState"])
    vs["type"] = "histogram"  # the valid type for bar charts in this OSD
    v["visState"] = json.dumps(vs)
    obj = {
        "attributes": {
            "title": v["title"],
            "visState": v["visState"],
            "description": v.get("description", ""),
            "version": v.get("version", 1),
            "kibanaSavedObjectMeta": v.get("kibanaSavedObjectMeta", {}),
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": "ssop-events"}],
    }
    # PUT via saved-objects API
    req2 = urllib.request.Request(f"{BASE}/api/saved_objects/visualization/{vid}",
                                  data=json.dumps(obj).encode(), method="PUT")
    req2.add_header("Authorization", auth(USER, PASS))
    req2.add_header("osd-xsrf", "true")
    req2.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req2, context=ctx) as r:
        out = json.loads(r.read().decode())
    vs2 = json.loads(out["attributes"]["visState"])
    print(f"{vid}: type now = {vs2.get('type')}")
