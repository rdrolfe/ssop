#!/usr/bin/env python3
"""Bulk intel (hunt -> MISP -> survivors) — the properties that must not break.

Guards the ADR-007 contract for `tools/bulk_intel.py` and the promotion rule
`agents/hunt.py` applies to a hunt finding:

  1. SURVIVORS ONLY. External per-indicator lookups are spent on the values
     the local corpus MATCHED and nothing else. A regression that "helpfully"
     enriches every candidate inverts the entire cost argument this feature
     exists to make — and it would look like it was working.
  2. NO LOCAL FILTER, NO SPEND. An unconfigured MISP means no external
     lookups at all: you do not get to fall back to per-indicator fan-out
     just because bulk matching is not deployed.
  3. DEGRADED is not CLEAN — and is not a reason to spend either. An
     unreachable corpus reports UNKNOWN, never an empty match set, and never
     triggers the provider path.
  4. PROMOTION IS EVIDENCE-SHAPED. A strong match (hash/domain/url) promotes a
     finding; a bare ip match only lifts clean->info. An unreachable corpus
     changes NOTHING — a hunt must not silently keep escalating on the last
     known-good intel.
  5. BULK, not per-indicator (inherited from the client, asserted here too so
     a future re-plumbing cannot quietly cost one request per value).
  6. NO writes, NO hand-rolled TLS/transport. The module talks only through
     `tools/misp_client.py` and `tools/enrichment.py`.

Hermetic: a fake MISP on 127.0.0.1 and a recording enrichment stub. No
network, no real MISP, no credentials, no provider calls.
"""
from __future__ import annotations

import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.bulk_intel import (STRONG_TYPES, BulkIntel, probe_corpus,  # noqa: E402
                              promote_finding)
from tools.misp_client import MispClient  # noqa: E402

FAILS = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


# --- a fake MISP ------------------------------------------------------------

# value -> MISP attribute type. Deliberately mixes a STRONG type (sha1) with a
# weak one (ip-dst) so the promotion rule is exercised on real shapes.
KNOWN: dict[str, str] = {
    "198.51.100.7": "ip-dst",
    "evil.example.com": "domain",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "sha1",
}
REQUESTS: list[dict] = []
MODE = {"fail": False}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - signature matches http.server
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        REQUESTS.append({"path": self.path, "body": body})
        if MODE["fail"]:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"boom")
            return
        if self.path != "/attributes/restSearch":
            self.send_response(404)
            self.end_headers()
            return
        values = body.get("value") or []
        if isinstance(values, str):
            values = [values]
        attrs = [{"type": KNOWN[v], "category": "Network activity", "value": v,
                  "to_ids": True, "event_id": "42", "timestamp": "1789000000"}
                 for v in values if v in KNOWN]
        payload = json.dumps({"response": {"Attribute": attrs}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


srv = HTTPServer(("127.0.0.1", 0), _Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{srv.server_port}"


class RecEnrichment:
    """Records exactly what the external provider path was asked to look up."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    def enrich_many(self, observables):
        for o in observables:
            self.seen.append((o.get("type"), o.get("value")))
        return [{"observable": o, "provider": "stub", "status": "malicious"} for o in observables]


def client(**kw) -> MispClient:
    return MispClient(url=URL, api_key="fake-key", **kw)


# --- 1. survivors only -------------------------------------------------------
cand = [
    {"type": "ip", "value": "198.51.100.7"},                  # known (weak)
    {"type": "ip", "value": "10.0.0.9"},                        # unknown
    {"type": "domain", "value": "evil.example.com"},            # known (strong)
    {"type": "domain", "value": "clean.example.org"},           # unknown
    {"type": "hash", "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},  # known (strong)
    {"type": "hash", "value": "0" * 40},                        # unknown
]
rec = RecEnrichment()
intel = BulkIntel(misp=client(), enrichment=rec).match(cand, external=True)

check("1. every candidate was searched, only matches reported",
      intel["candidates"] == 6 and intel["matched"] == 3 and intel["degraded"] is False,
      f"candidates={intel['candidates']} matched={intel['matched']} degraded={intel['degraded']}")
check("1b. external lookups were spent on the 3 SURVIVORS and nothing else",
      sorted(v for _, v in rec.seen) == sorted(KNOWN),
      f"enriched={sorted(v for _, v in rec.seen)}")
check("1c. survivors carry the caller's TYPES, not the corpus attribute types",
      {v: t for t, v in rec.seen}.get("evil.example.com") == "domain"
      and {v: t for t, v in rec.seen}.get(
          "da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash",
      f"seen={rec.seen}")
check("1d. the batch was ONE request (bulk, not per-indicator)",
      len(REQUESTS) == 1, f"requests={len(REQUESTS)}")
check("1e. strong vs weak matches are counted apart",
      intel["strong_matches"] == 2 and intel["types"].get("ip") == 1
      and intel["types"].get("hash") == 1 and intel["types"].get("domain") == 1,
      f"strong={intel['strong_matches']} types={intel['types']}")

# --- 2. external is OPT-IN ---------------------------------------------------
REQUESTS.clear()
rec2 = RecEnrichment()
introspect = BulkIntel(misp=client(), enrichment=rec2).match(cand, external=False)
check("2. external=False spends nothing on providers",
      rec2.seen == [] and introspect["external_looked_up"] == 0,
      f"seen={rec2.seen}")
check("2b. ...but the local match still happened",
      introspect["matched"] == 3, f"matched={introspect['matched']}")

# --- 3. no local filter -> no spend -----------------------------------------
rec3 = RecEnrichment()
off = BulkIntel(misp=MispClient(url="", api_key=""), enrichment=rec3).match(cand, external=True)
check("3. an unconfigured corpus spends NOTHING (no per-indicator fallback)",
      rec3.seen == [] and off["external_looked_up"] == 0)
check("3b. ...and still reports the candidate count, not a silent zero",
      off["candidates"] == 6 and off["enabled"] is False and "not configured" in off["summary"],
      f"candidates={off['candidates']} summary={off['summary']!r}")
check("3c. an unconfigured corpus is NOT degraded — it was never checked",
      off["degraded"] is False)

# --- 4. DEGRADED is not CLEAN, and is not a reason to spend -----------------
MODE["fail"] = True
rec4 = RecEnrichment()
try:
    bad = BulkIntel(misp=client(), enrichment=rec4).match(cand, external=True)
finally:
    MODE["fail"] = False
check("4. an erroring corpus reports degraded=True with an error",
      bad["degraded"] is True and bool(bad.get("error")), f"error={bad.get('error')!r}")
check("4b. a degraded result has NO matches (never a phantom empty-clean)",
      bad["matches"] == {} and bad["matched"] == 0)
check("4c. a degraded corpus does NOT trigger external spend",
      rec4.seen == [] and bad["external_looked_up"] == 0, f"seen={rec4.seen}")
check("4d. the summary says UNKNOWN rather than reporting a clean fleet",
      "UNKNOWN" in bad["summary"], f"summary={bad['summary']!r}")

# --- 5. the promotion rule ---------------------------------------------------
strong = {"degraded": False, "matched": 3, "strong_matches": 2}
weak = {"degraded": False, "matched": 1, "strong_matches": 0}
none = {"degraded": False, "matched": 0, "strong_matches": 0}
unknown = {"degraded": True, "matched": 0, "strong_matches": 0}

check("5. a strong match promotes a clean hunt to suspicious",
      promote_finding("clean", strong)[0] == "suspicious")
check("5b. a strong match promotes an info hunt to suspicious",
      promote_finding("info", strong)[0] == "suspicious")
check("5c. a weak (ip-only) match lifts clean to info, never to suspicious",
      promote_finding("clean", weak)[0] == "info")
check("5d. a weak match leaves an existing suspicious finding alone",
      promote_finding("suspicious", weak)[0] == "suspicious")
check("5e. no match changes nothing",
      promote_finding("clean", none)[0] == "clean"
      and promote_finding("info", none)[0] == "info")
check("5f. an UNKNOWN corpus changes NOTHING (no escalation on stale intel)",
      promote_finding("clean", unknown)[0] == "clean"
      and promote_finding("suspicious", unknown)[0] == "suspicious"
      and promote_finding("clean", unknown)[1] == "intel-unknown")
check("5g. the reason string names the promotion, for the case record",
      promote_finding("clean", strong)[1] == "strong-intel-match"
      and promote_finding("clean", weak)[1] == "weak-intel-match")
check("5h. STRONG_TYPES is hash/domain/url only — a bare ip is deliberately weak",
      STRONG_TYPES == frozenset({"hash", "domain", "url"}), f"{sorted(STRONG_TYPES)}")

# --- 6. static invariants on the module source ------------------------------
src = (Path(__file__).resolve().parent.parent / "tools" / "bulk_intel.py").read_text()
write_hits = re.findall(r"[\"'](/(?:attributes|events|shadow_attributes|sightings)"
                        r"/(?:add|edit|delete|publish|push)[^\"']*)[\"']", src)
check("6. no write endpoint in the module (the no-submit invariant)",
      not write_hits, f"found {write_hits}")
check("6b. no hand-rolled transport — it goes through the MISP client",
      "urllib" not in src and "import ssl" not in src and "http.client" not in src)
check("6c. no CERT_NONE / verification opt-out",
      "CERT_NONE" not in src and "check_hostname" not in src)
check("6d. external lookups are DELEGATED to the shared enrichment client",
      "from tools.enrichment import EnrichmentClient" in src
      and "from tools.misp_client import MispClient" in src)

# --- 7. empty input is a no-op ----------------------------------------------
REQUESTS.clear()
rec7 = RecEnrichment()
empty = BulkIntel(misp=client(), enrichment=rec7).match([], external=True)
check("7. no candidates makes no request and spends nothing",
      len(REQUESTS) == 0 and rec7.seen == [] and empty["candidates"] == 0)
check("7b. ...and is reported honestly, not as a clean result",
      empty["degraded"] is False and empty["summary"] == "no candidate observables",
      f"summary={empty['summary']!r}")

# --- 8. duplicate values collapse -------------------------------------------
REQUESTS.clear()
dupes = [{"type": "ip", "value": "198.51.100.7"},
         {"type": "ip", "value": "198.51.100.7"},
         {"type": "domain", "value": "evil.example.com"}]
d = BulkIntel(misp=client(), enrichment=RecEnrichment()).match(dupes)
check("8. duplicate candidates collapse to unique values",
      d["candidates"] == 2 and len(REQUESTS[0]["body"]["value"]) == 2,
      f"candidates={d['candidates']} sent={REQUESTS[0]['body']['value']}")

# --- 9. the corpus probe (the matrix gate's non-vacuity) --------------------
# The per-fixture hunt_intel invariant SKIPS whenever a live hunt returns no
# extractable observables — which is most runs — so the matrix needs a direct
# probe or "hunt matches the feed corpus" is claimable from a run that never
# consulted the corpus. These checks pin the probe's answers.
MODE["fail"] = False
pr = probe_corpus(MispClient(url=URL, api_key="fake-key"))
check("9. a reachable corpus reports reachable, not degraded",
      pr["enabled"] is True and pr["reachable"] is True and pr["degraded"] is False,
      f"{pr}")
check("9b. the negative control matches NOTHING (0 expected)",
      "0 match(es)" in pr["summary"], f"summary={pr['summary']!r}")

off_pr = probe_corpus(MispClient(url="", api_key=""))
check("9c. an unconfigured corpus is NOT reported reachable",
      off_pr["enabled"] is False and off_pr["reachable"] is False)
check("9d. ...and says so in plain words rather than reporting a clean corpus",
      "not configured" in off_pr["summary"], f"summary={off_pr['summary']!r}")

MODE["fail"] = True
try:
    bad_pr = probe_corpus(MispClient(url=URL, api_key="fake-key"))
finally:
    MODE["fail"] = False
check("9e. an unreachable corpus is NOT reported reachable",
      bad_pr["reachable"] is False and bad_pr["degraded"] is True)
check("9f. the probe never raises — it reports",
      isinstance(bad_pr["error"], str) and bool(bad_pr["summary"]))

srv.shutdown()
print()
if FAILS:
    print(f"FAILURES: {FAILS}")
    sys.exit(1)
print("ALL CHECKS PASSED")
