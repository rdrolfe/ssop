#!/usr/bin/env python3
"""Enable the licensed MISP feed set and pull it.

Run AFTER the MISP stack is healthy. Talks to the MISP REST API over VERIFIED
TLS (the SSOP CA bundle — no CERT_NONE, per issue #29).

What it does, and why exactly this:
  * Enables ONLY the feeds whose licences are on record in
    docs/feeds-and-licensing.md — CIRCL OSINT (TLP:CLEAR, redistributable) and
    botvrij.eu (use permitted, no resale).
  * Sets `delta_merge` on every feed before enabling it. The documented disk
    killer is the correlations table, driven by "new event each pull"
    ingestion; delta-merge is the mitigation, and it has to be set BEFORE the
    first pull or the first pull is the expensive one.
  * Does NOT enable the abuse.ch family: their ToS now requires an
    authenticated account (auth.abuse.ch) which does not exist yet, so enabling
    them would be an unlicensed access. Recorded as an operator dependency.
  * Does NOT enable any other MISP default feed: licence unestablished.

Usage:
    python3 configure_misp_feeds.py --url https://192.168.1.80 \
        --api-key <key> --ca ~/agent-runtime/certs/ca/ca-bundle.crt [--fetch]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request

ENABLE = {
    "CIRCL OSINT Feed": {"delta_merge": True},
    "The Botvrij.eu Data": {"delta_merge": True},
}
# Kept out for stated reasons, so the next reader does not "helpfully" enable them.
EXCLUDED = {
    "abuse.ch": "auth required (auth.abuse.ch), ToS 7.3 forbids derivative works — in-lab only",
    "AlienVault": "EULA forbids copying/duplicating the corpus — stays a live lookup",
}


def api(url: str, key: str, ca: str | None, path: str, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(f"{url.rstrip('/')}{path}", data=data,
                                 method="POST" if data else "GET")
    req.add_header("Authorization", key)
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    ctx = None
    if ca:
        import ssl
        ctx = ssl.create_default_context(cafile=ca)
    with urllib.request.urlopen(req, context=ctx, timeout=120) as r:
        body = r.read().decode()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--ca", default=None)
    ap.add_argument("--fetch", action="store_true", help="pull the feeds after enabling")
    args = ap.parse_args()

    feeds = api(args.url, args.api_key, args.ca, "/feeds/index")
    if isinstance(feeds, str):
        print("unexpected non-JSON from /feeds/index:", feeds[:200])
        return 1
    by_name = {f.get("Feed", {}).get("name", ""): f.get("Feed", {}) for f in feeds}
    print(f"feeds visible: {len(by_name)}")

    for name, opts in ENABLE.items():
        match = next((f for n, f in by_name.items() if n == name), None)
        if not match:
            print(f"  MISSING from this MISP's default feed list: {name!r}")
            continue
        fid = match["id"]
        already = bool(match.get("enabled"))
        api(args.url, args.api_key, args.ca, f"/feeds/edit/{fid}",
            {"delta_merge": opts["delta_merge"], "enabled": True})
        api(args.url, args.api_key, args.ca, f"/feeds/enable/{fid}", {})
        got = api(args.url, args.api_key, args.ca, f"/feeds/view/{fid}")
        row = got.get("Feed", {}) if isinstance(got, dict) else {}
        print(f"  {name}: id={fid} enabled={row.get('enabled')} "
              f"delta_merge={row.get('delta_merge')} (was enabled={already})")

    for pat, why in EXCLUDED.items():
        print(f"  NOT enabling {pat}: {why}")

    if args.fetch:
        for name in ENABLE:
            match = next((f for n, f in by_name.items() if n == name), None)
            if match:
                print(f"  pulling {name} (id={match['id']}) …")
                print("   ", api(args.url, args.api_key, args.ca,
                                 f"/feeds/fetchFromFeed/{match['id']}"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
