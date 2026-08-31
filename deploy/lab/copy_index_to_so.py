#!/usr/bin/env python3
"""Scroll-copy a BOTS slice index from the Wazuh indexer to SO ES.

The BOTSv1 ground-truth sysmon slice (bots-sysmon-op-poc, 830K docs) lives
on the Wazuh host (.75) but not on SO (.76). This copies the index as-is
(scroll on source, bulk into target) so the ground-truth ransomware drill
can run against BOTH backends — the point of the two-backend parity goal.

Source/target endpoints + creds are resolved explicitly from transport.yaml
backends + .env (same convention as ingest_bots._target) — never the active
backend, and never committed secrets.

Usage: python3 copy_index_to_so.py <source_index> [target_index]
"""
import base64
import json
import ssl
import sys
import urllib.request
import urllib.error

from dotenv import load_dotenv

load_dotenv()
import yaml as _yaml
from config import settings


def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _backend(backend: str):
    """Resolve (host, port, user, password) for a transport.yaml backend."""
    with open("transport.yaml") as f:
        cfg = _yaml.safe_load(f)
    b = (cfg.get("backends") or {}).get(backend) or {}
    ep = b.get("endpoint") or ""
    import re as _re
    m = _re.match(r"https?://([^:]+)(?::(\d+))?", ep)
    host = m.group(1) if m else "192.168.1.75"
    port = int(m.group(2) or 9200) if m else 9200
    user = b.get("user") or settings.indexer_user
    if backend == "securityonion":
        pw = b.get("password") or settings.so_indexer_password
    else:
        pw = settings.indexer_password
    return host, port, user, pw


def _scroll_docs(host, port, user, pw, index, batch=5000):
    """Yield _source docs from index via the scroll API (read-only)."""
    ctx = _ctx()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    base = f"https://{host}:{port}"
    init = {
        "size": batch,
        "query": {"match_all": {}},
        "sort": ["_doc"],
    }
    req = urllib.request.Request(
        f"{base}/{index}/_search?scroll=2m", data=json.dumps(init).encode(),
        headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        resp = json.loads(r.read().decode())
    scroll_id = resp.get("_scroll_id")
    hits = resp.get("hits", {}).get("hits", [])
    while hits:
        yield [h.get("_source", {}) for h in hits]
        if not scroll_id:
            break
        req = urllib.request.Request(
            f"{base}/_search/scroll",
            data=json.dumps({"scroll": "2m", "scroll_id": scroll_id}).encode(),
            headers={"Authorization": auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            resp = json.loads(r.read().decode())
        scroll_id = resp.get("_scroll_id")
        hits = resp.get("hits", {}).get("hits", [])


def _bulk(host, port, user, pw, index, docs):
    ctx = _ctx()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    url = f"https://{host}:{port}/_bulk"
    batch = []
    for d in docs:
        batch.append({"index": {"_index": index}})
        batch.append(d)
    body = "".join(json.dumps(x) + "\n" for x in batch)
    req = urllib.request.Request(url, data=body.encode(),
                                 headers={"Authorization": auth,
                                          "Content-Type": "application/x-ndjson"})
    with urllib.request.urlopen(req, timeout=120, context=ctx) as r:
        out = json.loads(r.read().decode())
    errs = sum(1 for item in out.get("items", [])
               if "error" in (item.get("index") or {}))
    return errs


def main():
    src_idx = sys.argv[1] if len(sys.argv) > 1 else "bots-sysmon-op-poc"
    dst_idx = sys.argv[2] if len(sys.argv) > 2 else src_idx

    src = _backend("wazuh")
    dst = _backend("securityonion")
    print(f"source: {src[0]}:{src[1]}/{src_idx} (user {src[2]})")
    print(f"target: {dst[0]}:{dst[1]}/{dst_idx} (user {dst[2]})")
    print("NOTE: passwords come from .env / transport.yaml backends; "
          "never printed.")

    # Pre-create the target index (ignore 400 already-exists)
    ctx = _ctx()
    auth = "Basic " + base64.b64encode(f"{dst[2]}:{dst[3]}".encode()).decode()
    req = urllib.request.Request(
        f"https://{dst[0]}:{dst[1]}/{dst_idx}", data=b"{}", method="PUT",
        headers={"Authorization": auth, "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=20, context=ctx)
    except urllib.error.HTTPError as e:
        if e.code != 400:
            print(f"index create: HTTP {e.code}")

    total = 0
    for docs in _scroll_docs(*src, src_idx):
        errs = _bulk(*dst, dst_idx, docs)
        total += len(docs)
        print(f"  copied {len(docs)} (total {total}, {errs} errors)")
    print(f"DONE: {total} docs into {dst_idx} on SO")


if __name__ == "__main__":
    main()
