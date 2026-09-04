#!/usr/bin/env python3
"""Repair ALL SSOP dashboards: bump every panel's version to the running
OSD version (2.19.5). The dashboards claim 8.0.0 / 2.14.0 — OSD 2.19.5
refuses to render panels whose version mismatches, which is why the
workbench + overview + pane look broken.

Preserves every other panel field (type/id/title/gridData/embeddableConfig).

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
OSD_VERSION = "2.19.5"  # verified live via /api/status

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


def main() -> int:
    # All SSOP dashboards (by id).
    dash_ids = [
        "soc-workbench",
        "ssop-pane",
        "1a79ca90-9c1d-11f1-b914-e3158878e251",  # SSOP Operations Overview
    ]
    fixed_total = 0
    for did in dash_ids:
        try:
            cur = _req("GET", f"/api/saved_objects/dashboard/{did}")
        except urllib.error.HTTPError as e:
            print(f"{did}: GET failed {e.code}")
            continue
        attrs = cur.get("attributes", {})
        pj = json.loads(attrs.get("panelsJSON") or "[]")
        changed = 0
        for p in pj:
            if p.get("version") != OSD_VERSION:
                p["version"] = OSD_VERSION
                changed += 1
        if not changed:
            print(f"{did}: already current ({len(pj)} panels)")
            continue
        attrs["panelsJSON"] = json.dumps(pj)
        try:
            _req("PUT", f"/api/saved_objects/dashboard/{did}",
                 {"attributes": attrs, "references": cur.get("references", [])})
            fixed_total += changed
            print(f"{did}: bumped {changed} panel(s) -> {OSD_VERSION}")
        except urllib.error.HTTPError as e:
            print(f"{did}: PUT failed {e.code} {e.read().decode()[:200]}")
    print(f"total panels bumped: {fixed_total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
