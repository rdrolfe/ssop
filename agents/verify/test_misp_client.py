#!/usr/bin/env python3
"""MISP bulk-match client — the properties that must not silently break.

Guards the ADR-007 contract for `tools/misp_client.py`:

  1. BULK, not per-indicator. N values must cost O(N/batch_size) requests, not
     O(N). A regression to a per-value loop would still "work" — it would just
     put an HTTP round trip on every indicator of every sweep, which is the
     exact cost this feature exists to remove.
  2. DEGRADED is not CLEAN. An unreachable/erroring MISP must report
     `degraded=True`, never an empty match set that a caller reads as "nothing
     malicious in the fleet".
  3. NO WRITE PATH exists in the module — no /attributes/add, no /events/add,
     no publish, no sharing edits. Enforced statically so a future edit cannot
     quietly add a disclosure path (sovereignty: submit is OFF by default).
  4. VERIFIED TLS only: the module must not build its own context or disable
     verification; it goes through tools.tls (issue #29).
  5. Loopback fixtures may use plain HTTP; a non-loopback MISP must be HTTPS —
     so the test profile can't become a production downgrade.

Hermetic: a fake MISP on 127.0.0.1. No network, no real MISP, no credentials.
"""
from __future__ import annotations

import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.misp_client import MispClient  # noqa: E402

FAILS = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


# --- a fake MISP ------------------------------------------------------------

KNOWN = {"45.155.205.233", "evil.example.com", "d41d8cd98f00b204e9800998ecf8427e"}
REQUESTS: list[dict] = []
MODE = {"fail": False}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - signature matches http.server
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        REQUESTS.append({"path": self.path, "body": body,
                         "auth": self.headers.get("Authorization")})
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
        attrs = [{"type": "ip-dst", "category": "Network activity", "value": v,
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

# --- 1. bulk, not per-indicator --------------------------------------------
REQUESTS.clear()
c = MispClient(url=URL, api_key="fake-key")
values = [f"10.0.0.{i}" for i in range(1, 251)]          # 250 unknowns
res = c.match_many(values)
check("1. 250 values cost 2 requests with batch_size=200 (not 250)",
      len(REQUESTS) == 2, f"requests={len(REQUESTS)}")
check("1b. the batch carried 200 values, not 1",
      len(REQUESTS[0]["body"]["value"]) == 200, f"n={len(REQUESTS[0]['body']['value'])}")
check("1c. the API key rides the request as a header",
      REQUESTS[0]["auth"] == "fake-key")

# --- 2. matches are returned per value, with provenance kept ----------------
REQUESTS.clear()
mix = ["45.155.205.233", "clean.example.org", "evil.example.com"]
res = c.match_many(mix)
check("2. known values match, clean values do not",
      set(res["matches"]) == {"45.155.205.233", "evil.example.com"},
      f"matches={sorted(res['matches'])}")
check("2b. matched count is reported", res["matched"] == 2, f"matched={res['matched']}")
check("2c. provenance survives (type/category/event_id)",
      res["matches"]["45.155.205.233"][0].get("event_id") == "42"
      and res["matches"]["45.155.205.233"][0].get("type") == "ip-dst")
obs_pair = [{"type": "ip", "value": "45.155.205.233"},
            {"type": "domain", "value": "clean.example.org"}]
ann_pair = c.annotate_observables(obs_pair)
check("2d. a match is marked known=True, a clean value known=False",
      obs_pair[0]["known"] is True and obs_pair[1]["known"] is False
      and ann_pair["known_values"] == ["45.155.205.233"],
      f"known={{obs_pair[0]['known']}}, {{obs_pair[1]['known']}}")

# --- 3. DEGRADED is not CLEAN ----------------------------------------------
MODE["fail"] = True
try:
    bad = c.match_many(["45.155.205.233"])
    check("3. an erroring MISP reports degraded=True", bad.get("degraded") is True)
    check("3b. a degraded result carries an error and no phantom matches",
          bool(bad.get("error")) and bad.get("matches") == {})
    # the annotate call must run WHILE the failure is still in effect, or the
    # check passes for the wrong reason (it did once — caught by re-reading it)
    obs = [{"type": "ip", "value": "45.155.205.233"}]
    ann = c.annotate_observables(obs)
finally:
    MODE["fail"] = False
check("3c. a degraded batch never marks observables known",
      ann["degraded"] is True and obs[0]["known"] is False)

# --- 4. unconfigured is 'not checked', not 'clean' --------------------------
c_off = MispClient(url="", api_key="")
check("4. unconfigured client reports available()=False", c_off.available() is False)
off = c_off.match_many(["45.155.205.233"])
check("4b. unconfigured client degrades rather than returning empty-clean",
      off["degraded"] is True and off["searched"] == 0 and bool(off.get("error")))

# --- 5. static invariants on the module source ------------------------------
src = (Path(__file__).resolve().parent.parent / "tools" / "misp_client.py").read_text()
write_hits = re.findall(r"[\"'](/(?:attributes|events|shadow_attributes|sightings)"
                        r"/(?:add|edit|delete|publish|push)[^\"']*)[\"']", src)
check("5. no write endpoint anywhere in the module (the no-submit invariant)",
      not write_hits, f"found {write_hits}")
check("5b. no CERT_NONE / hand-rolled unverified context in CODE",
      "ssl.CERT_NONE" not in src and "check_hostname = False" not in src
      and "verify_mode = ssl.CERT" not in src,
      "the docstring may mention CERT_NONE as prose; the check targets code")
check("5c. TLS comes from the shared factory (issue #29)",
      "verified_ssl_context" in src)
check("5d. an insecure config raises instead of degrading to 'no matches'",
      "MispConfigError" in src and "except MispConfigError" in src)
check("5e. the module never POSTs to a non-restSearch path",
      all(r["path"] == "/attributes/restSearch" for r in REQUESTS),
      f"paths={[r['path'] for r in REQUESTS]}")

# --- 6. a non-loopback MISP must be HTTPS ----------------------------------
refused = False
try:
    MispClient(url="http://misp.internal.example", api_key="k").match_many(["x"])
except Exception:  # noqa: BLE001
    refused = True
check("6. plain-HTTP non-loopback MISP is refused (test profile can't leak out)",
      refused)
check("6b. loopback fixtures are still allowed over HTTP (that is how this test ran)",
      bool(REQUESTS) and REQUESTS[0]["path"] == "/attributes/restSearch")

# --- 7. empty input is a no-op, not a request ------------------------------
REQUESTS.clear()
empty = c.match_many([])
check("7. empty input makes no request and is not degraded",
      len(REQUESTS) == 0 and empty["degraded"] is False and empty["searched"] == 0)

srv.shutdown()
print()
if FAILS:
    print(f"FAILURES: {FAILS}")
    sys.exit(1)
print("ALL CHECKS PASSED")
