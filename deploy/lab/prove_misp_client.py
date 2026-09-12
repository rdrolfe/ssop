#!/usr/bin/env python3
"""Proof: the MISP bulk-match client works against the LIVE in-lab instance.

Run from the runtime root on infra-ops with the runtime venv:
    cd ~/agent-runtime && ./agent-env/bin/python deploy/lab/prove_misp_client.py

Why this exists: a hermetic fixture proves the client's LOGIC, not that the real
instance answers it. This drives the real thing end-to-end — real TLS (SSOP CA,
no opt-out), real API key, real corpus — and includes a NEGATIVE CONTROL so a
pass cannot be vacuous:

  1. sample real indicator values OUT of the live corpus via the API;
  2. ask the CLIENT to bulk-match exactly those values;
  3. require every sampled value to come back (a filtering bug fails here);
  4. require a nonsense value to come back empty (a "match everything" bug
     fails here);
  5. require the whole thing in a bounded number of requests (the bulk property).
"""
from __future__ import annotations

import sys
from pathlib import Path

# tools/ lives at <runtime root>/tools (deployed) or <repo>/agents/tools (local
# checkout). Prefer whichever ACTUALLY HAS tools/ — and note the order matters:
# inserting both with insert(0, …) puts the LAST one first, so the runtime's
# stale `agents/` copy shadowed the real `tools/` and the import failed with
# ModuleNotFoundError even though the file was present and md5-correct.
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parents[2]
_PKG_ROOT = _ROOT if (_ROOT / "tools").is_dir() else _ROOT / "agents"
sys.path.insert(0, str(_PKG_ROOT))

from tools.misp_client import MispClient  # noqa: E402

FAILS = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


c = MispClient()
check("client is configured (MISP_URL + MISP_API_KEY present)", c.available())
if not c.available():
    print("\nCannot continue without configuration.")
    sys.exit(1)
print(f"  endpoint: {c.url} | batch_size={c.batch_size} | timeout={c.timeout}s")

# 1. sample real values straight from the corpus (through the client's own transport)
sample = (c._post("/attributes/restSearch", {"limit": 6, "returnFormat": "json"})
          .get("response") or {}).get("Attribute") or []
values = [a["value"] for a in sample if a.get("value")]
check("sampled real indicators from the live corpus", len(values) >= 3,
      f"got {len(values)}")
if len(values) < 3:
    print("\nCorpus too small to sample — is the feed pull finished?")
    sys.exit(1)
print(f"  sampled: {[v[:28] for v in values[:3]]} …")

# 2/3. the client's bulk match must return every one of them
res = c.match_many(values)
check("bulk match is not degraded (instance reachable over verified TLS)",
      res["degraded"] is False, str(res.get("error")))
check("every sampled indicator matched", set(values) <= set(res["matches"]),
      f"missing {sorted(set(values) - set(res['matches']))[:3]}")
check("single request for the batch (bulk, not per-indicator)",
      res["batches"] == 1, f"batches={res['batches']}")
print(f"  searched={res['searched']} matched={res['matched']} batches={res['batches']}")

# 4. negative control
ctl = c.match_many(["definitely-not-an-indicator.invalid", "0.0.0.0.invalid"])
check("negative control returns no matches", ctl["matched"] == 0 and not ctl["degraded"],
      f"matched={ctl['matched']}")

# 5. annotate path (what hunt will actually call)
obs = [{"type": "ip", "value": values[0]}, {"type": "ip", "value": "198.51.100.7"}]
ann = c.annotate_observables(obs)
check("annotate marks the known observable and not the clean one",
      obs[0]["known"] is True and obs[1]["known"] is False, str([o.get("known") for o in obs]))
check("annotate returns the survivors for later enrichment",
      obs[0]["value"] in ann["known_values"])

print()
if FAILS:
    print(f"FAILURES: {FAILS}")
    sys.exit(1)
print("LIVE MISP CLIENT PROOF: PASSED")
